//! Canonical OCI layer serialization, independent of the container runner.
//!
//! Implements the draft at <https://github.com/composefs/composefs-rs/pull/356>.
//! Only metadata and padding enter the splitstream; file objects are referenced
//! directly and read once to compute the digest of the logical tar stream.

use std::{collections::HashMap, fs::File, io, os::unix::ffi::OsStrExt, path::PathBuf};

use anyhow::{Context, Result, bail, ensure};
use composefs::{
    digest::{Digest, Sha256},
    fsverity::FsVerityHashValue,
    generic_tree::LeafId,
    repository::Repository,
    splitstream::SplitStreamWriter,
    tree::{Directory, FileSystem, Inode, LeafContent, RegularFile, Stat},
    util::DigestWrite,
};
use composefs_oci::{
    OciDigest,
    tar::{TarEntry, TarItem},
};
use tar_core::{
    EntryType, Header,
    builder::{HeaderBuilder, PaxBuilder},
};

const BLOCK: usize = 512;
const NAME_MAX: usize = 100;
const ID_MAX: u64 = 0o7777777;
const SIZE_MAX: u64 = 0o77777777777;
// Currently private in composefs-oci::skopeo; this is its splitstream wire tag.
pub(crate) const TAR_LAYER_CONTENT_TYPE: u64 = u64::from_le_bytes(*b"ocilayer");

/// Walk a layer tree in canonical order, retaining hardlink identity.
pub(crate) fn entries<H: FsVerityHashValue>(fs: &FileSystem<H>) -> Vec<TarEntry<H>> {
    fn walk<H: FsVerityHashValue>(
        fs: &FileSystem<H>,
        dir: &Directory<H>,
        path: PathBuf,
        seen: &mut HashMap<LeafId, PathBuf>,
        result: &mut Vec<TarEntry<H>>,
    ) {
        result.push(TarEntry {
            path: path.clone(),
            stat: dir.stat.clone(),
            item: TarItem::Directory,
        });
        for (name, inode) in dir.entries() {
            let path = path.join(name);
            match inode {
                Inode::Directory(dir) => walk(fs, dir, path, seen, result),
                Inode::Leaf(id, _) => {
                    let leaf = fs.leaf(*id);
                    let item = if let Some(target) = seen.get(id) {
                        TarItem::Hardlink(target.clone().into_os_string())
                    } else {
                        seen.insert(*id, path.clone());
                        TarItem::Leaf(leaf.content.clone())
                    };
                    result.push(TarEntry {
                        path,
                        stat: leaf.stat.clone(),
                        item,
                    });
                }
            }
        }
    }
    let mut result = Vec::new();
    walk(
        fs,
        &fs.root,
        PathBuf::from("/"),
        &mut HashMap::new(),
        &mut result,
    );
    result
}

/// A tar sink which hashes logical bytes while writing splitstream instructions.
struct LayerWriter<H: FsVerityHashValue> {
    stream: SplitStreamWriter<H>,
    hash: DigestWrite<Sha256>,
    size: u64,
}

impl<H: FsVerityHashValue> LayerWriter<H> {
    fn inline(&mut self, bytes: &[u8]) {
        self.hash.0.update(bytes);
        self.size += bytes.len() as u64;
        self.stream.write_inline(bytes);
    }

    fn padding(&mut self, size: u64) {
        self.inline(&[0; BLOCK][..((BLOCK as u64 - size % BLOCK as u64) % BLOCK as u64) as usize]);
    }

    fn header(&mut self, mut header: Header) {
        // tar-core uses seven octal digits + NUL. The draft specifies the
        // traditional six digits + NUL + space checksum encoding.
        let checksum = format!("{:06o}\0 ", header.compute_checksum());
        header
            .as_ustar_mut()
            .cksum
            .copy_from_slice(checksum.as_bytes());
        self.inline(header.as_bytes());
    }

    fn pax(&mut self, name: &[u8], kind: EntryType, data: &[u8]) -> Result<()> {
        let mut header = base_header(name, 0, 0, 0, data.len() as u64, 0)?;
        header.entry_type(kind);
        self.header(header.finish());
        self.inline(data);
        self.padding(data.len() as u64);
        Ok(())
    }

    fn entry(&mut self, entry: TarEntry<H>) -> Result<()> {
        let mut path = b".".to_vec();
        path.extend_from_slice(entry.path.as_os_str().as_bytes());
        if matches!(entry.item, TarItem::Directory) && !path.ends_with(b"/") {
            path.push(b'/');
        }
        let (kind, size, link, device) = match &entry.item {
            TarItem::Directory => (EntryType::Directory, 0, &b""[..], 0),
            TarItem::Hardlink(target) => {
                let target = [b".", target.as_bytes()].concat();
                return self.link_entry(&path, &entry.stat, EntryType::Link, &target);
            }
            TarItem::Leaf(LeafContent::Symlink(target)) => {
                (EntryType::Symlink, 0, target.as_bytes(), 0)
            }
            TarItem::Leaf(LeafContent::Regular(file)) => {
                (EntryType::Regular, file.file_size(), &b""[..], 0)
            }
            TarItem::Leaf(LeafContent::BlockDevice(dev)) => (EntryType::Block, 0, &b""[..], *dev),
            TarItem::Leaf(LeafContent::CharacterDevice(dev)) => {
                (EntryType::Char, 0, &b""[..], *dev)
            }
            TarItem::Leaf(LeafContent::Fifo) => (EntryType::Fifo, 0, &b""[..], 0),
            TarItem::Leaf(LeafContent::Socket) => {
                bail!("OCI layers cannot represent socket {:?}", entry.path)
            }
        };
        self.entry_header(&path, &entry.stat, kind, size, link, device)?;
        if let TarItem::Leaf(LeafContent::Regular(file)) = entry.item {
            match file {
                RegularFile::Inline(data) => self.inline(&data),
                RegularFile::External(id, size) | RegularFile::ExternalNoVerity(id, size) => {
                    let mut file = File::from(self.stream.repo().open_object(&id)?);
                    let copied = io::copy(&mut file, &mut self.hash)?;
                    ensure!(
                        copied == size,
                        "Object size mismatch: expected {size}, read {copied}"
                    );
                    self.stream.write_reference(id)?;
                    self.stream.add_external_size(size);
                    self.size += size;
                }
                RegularFile::Sparse(_) => bail!("Layer file has no content: {:?}", entry.path),
            }
            self.padding(size);
        }
        Ok(())
    }

    fn link_entry(&mut self, path: &[u8], stat: &Stat, kind: EntryType, link: &[u8]) -> Result<()> {
        self.entry_header(path, stat, kind, 0, link, 0)
    }

    fn entry_header(
        &mut self,
        path: &[u8],
        stat: &Stat,
        kind: EntryType,
        size: u64,
        link: &[u8],
        dev: u64,
    ) -> Result<()> {
        ensure!(
            stat.st_mtim_sec >= 0,
            "Canonical tar requires a nonnegative mtime"
        );
        ensure!(
            stat.st_mtim_nsec < 1_000_000_000,
            "Invalid mtime nanoseconds"
        );
        let mtime = stat.st_mtim_sec as u64;
        let mut pax = PaxBuilder::new();
        if path.len() > NAME_MAX {
            pax.path(path);
        }
        if link.len() > NAME_MAX {
            pax.linkpath(link);
        }
        if size > SIZE_MAX {
            pax.size(size);
        }
        if u64::from(stat.st_uid) > ID_MAX {
            pax.uid(stat.st_uid.into());
        }
        if u64::from(stat.st_gid) > ID_MAX {
            pax.gid(stat.st_gid.into());
        }
        if stat.st_mtim_nsec != 0 {
            let time = format!("{mtime}.{:09}", stat.st_mtim_nsec);
            pax.add("mtime", time.trim_end_matches('0').as_bytes());
        } else if mtime > SIZE_MAX {
            pax.mtime(mtime);
        }
        for (key, value) in &stat.xattrs {
            let key = key.to_str().context("Non-UTF-8 xattr name")?;
            pax.add(&format!("SCHILY.xattr.{key}"), value);
        }
        if !pax.as_bytes().is_empty() {
            let basename = path
                .strip_suffix(b"/")
                .unwrap_or(path)
                .rsplit(|b| *b == b'/')
                .next()
                .unwrap_or(b"");
            let mut name = b"PaxHeaders.0/".to_vec();
            name.extend_from_slice(basename);
            name.truncate(NAME_MAX);
            self.pax(&name, EntryType::XHeader, pax.as_bytes())?;
        }
        let mut header = base_header(
            &path[..path.len().min(NAME_MAX)],
            stat.st_mode & 0o7777,
            if u64::from(stat.st_uid) > ID_MAX {
                0
            } else {
                stat.st_uid.into()
            },
            if u64::from(stat.st_gid) > ID_MAX {
                0
            } else {
                stat.st_gid.into()
            },
            if size > SIZE_MAX { 0 } else { size },
            if mtime > SIZE_MAX { 0 } else { mtime },
        )?;
        header
            .entry_type(kind)
            .link_name(&link[..link.len().min(NAME_MAX)])?;
        header.device(rustix::fs::major(dev), rustix::fs::minor(dev))?;
        self.header(header.finish());
        Ok(())
    }
}

fn base_header(
    path: &[u8],
    mode: u32,
    uid: u64,
    gid: u64,
    size: u64,
    mtime: u64,
) -> Result<HeaderBuilder> {
    let mut header = HeaderBuilder::new_ustar();
    header
        .path(path)?
        .mode(mode)?
        .uid(uid)?
        .gid(gid)?
        .size(size)?
        .mtime(mtime)?
        .device(0, 0)?;
    Ok(header)
}

/// Store a layer without materializing a tar archive; return diff ID, verity and size.
///
/// Currently rejects sockets, negative modification times, and non-UTF-8 xattr
/// names.
pub fn write_layer<H: FsVerityHashValue>(
    repo: &std::sync::Arc<Repository<H>>,
    fs: &FileSystem<H>,
) -> Result<(OciDigest, H, u64)> {
    let mut writer = LayerWriter {
        stream: repo.create_stream(TAR_LAYER_CONTENT_TYPE)?,
        hash: DigestWrite(Sha256::new()),
        size: 0,
    };
    let mut global = PaxBuilder::new();
    global.add("canonical-tar", b"1");
    // The draft leaves the global header's name unspecified; keep it fixed.
    writer.pax(b"GlobalHead.0", EntryType::XGlobalHeader, global.as_bytes())?;
    for entry in entries(fs) {
        writer.entry(entry)?;
    }
    writer.inline(&[0; BLOCK * 2]);
    let digest: OciDigest = format!(
        "sha256:{}",
        writer
            .hash
            .0
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
    .parse()?;
    let verity = repo.write_stream(
        writer.stream,
        &composefs_oci::layer_content_id(&digest),
        None,
    )?;
    Ok((digest, verity, writer.size))
}
