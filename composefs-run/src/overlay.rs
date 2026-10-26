//! Normalize an overlay upper tree into an OCI changeset without mounting it.
//!
//! Parent paths resolve against the immutable parent filesystem. Metacopy files
//! reuse its content references; directory redirects materialize inherited
//! entries in the changeset. Neither operation reads a merged overlay mount.

use std::{
    collections::HashMap,
    ffi::{OsStr, OsString},
    os::unix::ffi::OsStrExt,
    path::{Component, Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, ensure};
use composefs::{
    fs::{ObjectStore, ReadFilesystemOpts},
    fsverity::FsVerityHashValue,
    generic_tree::LeafId,
    repository::Repository,
    tree::{Directory, FileSystem, Inode, Leaf, LeafContent, RegularFile, Stat},
};
use rustix::{
    fd::OwnedFd,
    fs::{Mode, OFlags},
};

/// Overlay metadata namespace selected when mounting the filesystem.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XattrNamespace {
    /// `trusted.overlay.*`, used without the `userxattr` mount option.
    Trusted,
    /// `user.overlay.*`, used with the `userxattr` mount option.
    User,
}

#[derive(Clone, Copy)]
pub(crate) enum Xattr {
    Metacopy,
    Redirect,
    Opaque,
    Whiteout,
}

const XATTR_ESCAPE_PREFIX: &[u8] = b"overlay.";

impl XattrNamespace {
    fn prefix(self) -> &'static str {
        match self {
            Self::Trusted => "trusted.overlay.",
            Self::User => "user.overlay.",
        }
    }

    pub(crate) fn name(self, attr: Xattr) -> &'static str {
        match (self, attr) {
            (Self::Trusted, Xattr::Metacopy) => "trusted.overlay.metacopy",
            (Self::Trusted, Xattr::Redirect) => "trusted.overlay.redirect",
            (Self::Trusted, Xattr::Opaque) => "trusted.overlay.opaque",
            (Self::Trusted, Xattr::Whiteout) => "trusted.overlay.whiteout",
            (Self::User, Xattr::Metacopy) => "user.overlay.metacopy",
            (Self::User, Xattr::Redirect) => "user.overlay.redirect",
            (Self::User, Xattr::Opaque) => "user.overlay.opaque",
            (Self::User, Xattr::Whiteout) => "user.overlay.whiteout",
        }
    }

    fn attr(self, stat: &Stat, key: Xattr) -> Option<&[u8]> {
        stat.xattrs
            .get(OsStr::new(self.name(key)))
            .map(AsRef::as_ref)
    }

    fn normalize_stat(self, stat: &mut Stat) {
        let prefix = self.prefix().as_bytes();
        stat.xattrs = std::mem::take(&mut stat.xattrs)
            .into_iter()
            .filter_map(|(key, value)| {
                if let Some(suffix) = key.as_bytes().strip_prefix(prefix) {
                    // Private overlay metadata is hidden, but escaped image
                    // xattrs are exposed after removing one escape level.
                    let suffix = suffix.strip_prefix(XATTR_ESCAPE_PREFIX)?;
                    let name = [prefix, suffix].concat();
                    Some((OsStr::from_bytes(&name).into(), value))
                } else {
                    Some((key, value))
                }
            })
            .collect();
    }
}

fn is_whiteout<H: FsVerityHashValue>(leaf: &Leaf<H>, namespace: XattrNamespace) -> Result<bool> {
    let xwhiteout = namespace.attr(&leaf.stat, Xattr::Whiteout).is_some();
    ensure!(
        !xwhiteout || matches!(&leaf.content, LeafContent::Regular(file) if file.file_size() == 0),
        "Invalid overlay xattr whiteout"
    );
    Ok(matches!(leaf.content, LeafContent::CharacterDevice(0)) || xwhiteout)
}

fn redirect_path(parent: &Path, value: &[u8]) -> Result<PathBuf> {
    ensure!(
        !value.is_empty() && !value.contains(&0),
        "Invalid empty or NUL-containing overlay redirect"
    );
    ensure!(
        !value
            .split(|b| *b == b'/')
            .any(|part| part == b"." || part == b".."),
        "Overlay redirect contains . or .."
    );
    let path = Path::new(OsStr::from_bytes(value));
    ensure!(
        path.components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_))),
        "Invalid overlay redirect"
    );
    Ok(if path.is_absolute() {
        path.to_owned()
    } else {
        parent.join(path)
    })
}

pub(crate) fn parent_directory<'a, H: FsVerityHashValue>(
    parent: &'a FileSystem<H>,
    path: &Path,
) -> Option<&'a Directory<H>> {
    let mut dir = &parent.root;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => match dir.lookup(name)? {
                Inode::Directory(child) => dir = child,
                _ => return None,
            },
            _ => return None,
        }
    }
    Some(dir)
}

fn parent_file<'a, H: FsVerityHashValue>(
    parent: &'a FileSystem<H>,
    path: &Path,
) -> Option<&'a RegularFile<H>> {
    let dir = parent_directory(parent, path.parent()?)?;
    match dir.lookup(path.file_name()?)? {
        Inode::Leaf(id, _) => match &parent.leaf(*id).content {
            LeafContent::Regular(content) => Some(content),
            _ => None,
        },
        _ => None,
    }
}

/// Convert a raw upper tree to OCI entries, preserving upper hardlinks and
/// parent hardlinks among materialized entries. The parent is never modified.
///
/// The parent must already contain resolved content references, as returned by
/// `OciImage::read_filesystem`. Its internal data-only redirects must be decoded
/// directly to repository objects, without searching the logical parent tree.
/// Reused parent nodes are copied without interpreting their xattrs.
///
/// Literal upper filenames beginning with `.wh.` are rejected because OCI
/// reserves that prefix for whiteouts. Redirects resolve against the parent
/// first, then composefs data-only redirects of the form `/XX/OBJECT` fall back
/// to repository objects.
/// Only metadata in `namespace` is interpreted and removed. Escaped image
/// xattrs are unescaped once; other xattrs are preserved.
pub fn normalize<H: FsVerityHashValue>(
    repo: &Repository<H>,
    parent: &FileSystem<H>,
    upper: FileSystem<H>,
    namespace: XattrNamespace,
) -> Result<FileSystem<H>> {
    let upper_leaf_count = upper.leaves.len();
    let mut normalizer = Normalizer {
        parent,
        namespace,
        leaves: upper.leaves,
        inherited: HashMap::new(),
        metacopies: HashMap::new(),
    };
    let root = normalizer.directory(upper.root, Path::new("/"), false, true)?;
    // A hardlinked metacopy may first appear at a newly created name. Gather
    // all source candidates before resolving each upper inode exactly once.
    for (id, paths) in &normalizer.metacopies {
        let leaf = &normalizer.leaves[id.0];
        ensure!(
            matches!(leaf.content, LeafContent::Regular(_)),
            "Metacopy inode is not a regular file"
        );
        // Regular lower layers are searched before data-only layers, even
        // when the redirect looks like a repository object pathname.
        let mut content = paths
            .iter()
            .find_map(|path| parent_file(parent, path))
            .cloned();
        if let Some(path) = namespace
            .attr(&leaf.stat, Xattr::Redirect)
            .and_then(|redirect| redirect.strip_prefix(b"/"))
            .filter(|_| content.is_none())
            && path.len() == 2 * size_of::<H>() + 1
            && let Ok(object) = H::from_object_pathname(path)
        {
            match repo.open_object(&object) {
                Ok(fd) => {
                    let size = rustix::fs::fstat(&fd)?.st_size as u64;
                    content = Some(if size <= composefs::INLINE_CONTENT_MAX_V0 as u64 {
                        RegularFile::Inline(repo.read_object(&object)?.into_boxed_slice())
                    } else {
                        RegularFile::External(object, size)
                    });
                }
                Err(error)
                    if error.downcast_ref::<rustix::io::Errno>()
                        == Some(&rustix::io::Errno::NOENT) => {}
                Err(error) => {
                    return Err(error).context("Resolving metacopy object redirect");
                }
            }
        }
        normalizer.leaves[id.0].content =
            LeafContent::Regular(content.with_context(|| {
                format!("Cannot resolve metacopy inode from parent at {paths:?}")
            })?);
    }
    // Inherited nodes are already decoded. Only upper xattrs are metadata
    // for this overlay; parent xattrs are ordinary image metadata.
    for leaf in &mut normalizer.leaves[..upper_leaf_count] {
        namespace.normalize_stat(&mut leaf.stat);
    }
    let mut result = FileSystem {
        root,
        leaves: normalizer.leaves,
    };
    result.compact();
    result.fsck()?;
    Ok(result)
}

struct Normalizer<'a, H: FsVerityHashValue> {
    parent: &'a FileSystem<H>,
    namespace: XattrNamespace,
    leaves: Vec<Leaf<H>>,
    inherited: HashMap<LeafId, LeafId>,
    metacopies: HashMap<LeafId, Vec<PathBuf>>,
}

impl<H: FsVerityHashValue> Normalizer<'_, H> {
    fn whiteout(&mut self) -> Inode<H> {
        let id = LeafId(self.leaves.len());
        self.leaves.push(Leaf {
            stat: Stat {
                st_mode: 0o644,
                st_uid: 0,
                st_gid: 0,
                st_mtim_sec: 0,
                st_mtim_nsec: 0,
                xattrs: Default::default(),
            },
            content: LeafContent::Regular(RegularFile::Inline(Box::default())),
        });
        Inode::leaf(id)
    }

    fn inherited_inode(&mut self, inode: &Inode<H>) -> Result<Inode<H>> {
        Ok(match inode {
            Inode::Directory(dir) => {
                let mut result = Directory::new(dir.stat.clone());
                for (name, inode) in dir.entries() {
                    ensure!(
                        !name.as_bytes().starts_with(b".wh."),
                        "OCI reserves filename {name:?}"
                    );
                    result.insert(name, self.inherited_inode(inode)?);
                }
                Inode::Directory(Box::new(result))
            }
            Inode::Leaf(id, _) => {
                let mapped = *self.inherited.entry(*id).or_insert_with(|| {
                    let mapped = LeafId(self.leaves.len());
                    self.leaves.push(self.parent.leaf(*id).clone());
                    mapped
                });
                Inode::leaf(mapped)
            }
        })
    }

    fn directory(
        &mut self,
        mut dir: Directory<H>,
        source: &Path,
        materialize: bool,
        visible: bool,
    ) -> Result<Directory<H>> {
        let redirected = self
            .namespace
            .attr(&dir.stat, Xattr::Redirect)
            .map(|value| redirect_path(source.parent().unwrap_or(Path::new("/")), value))
            .transpose()?;
        let opaque = self.namespace.attr(&dir.stat, Xattr::Opaque);
        ensure!(
            opaque.is_none_or(|v| v == b"y" || v == b"x"),
            "Unsupported overlay opaque value"
        );
        let opaque = opaque == Some(b"y");
        let source = redirected.as_deref().unwrap_or(source);
        let lower = if (visible || redirected.is_some()) && !opaque {
            parent_directory(self.parent, source)
        } else {
            None
        };
        ensure!(
            redirected.is_none() || opaque || lower.is_some(),
            "Missing redirected parent directory {source:?}"
        );
        let materialize = materialize || redirected.is_some();
        let mut result = Directory::new(dir.stat.clone());
        self.namespace.normalize_stat(&mut result.stat);
        let names: Vec<OsString> = dir.entries().map(|(name, _)| name.to_owned()).collect();
        for name in names {
            ensure!(
                !name.as_bytes().starts_with(b".wh."),
                "OCI reserves filename {name:?}"
            );
            let inode = dir.pop(&name).expect("entry exists");
            let lower_inode = lower.and_then(|dir| dir.lookup(&name));
            let inode = match inode {
                Inode::Directory(child) => Inode::Directory(Box::new(self.directory(
                    *child,
                    &source.join(&name),
                    materialize,
                    matches!(lower_inode, Some(Inode::Directory(_))),
                )?)),
                Inode::Leaf(id, _) => {
                    let leaf = &self.leaves[id.0];
                    if is_whiteout(leaf, self.namespace)? {
                        let whiteout_name = [b".wh.".as_slice(), name.as_bytes()].concat();
                        result.insert(OsStr::from_bytes(&whiteout_name), self.whiteout());
                        continue;
                    }
                    if self.namespace.attr(&leaf.stat, Xattr::Metacopy).is_some() {
                        let path = if let Some(redirect) =
                            self.namespace.attr(&leaf.stat, Xattr::Redirect)
                        {
                            Some(redirect_path(source, redirect)?)
                        } else if lower_inode.is_some() {
                            Some(source.join(&name))
                        } else {
                            None
                        };
                        let paths = self.metacopies.entry(id).or_default();
                        if let Some(path) = path {
                            paths.push(path);
                        }
                    }
                    Inode::leaf(id)
                }
            };
            result.insert(&name, inode);
        }
        if materialize && let Some(lower) = lower {
            for (name, inode) in lower.entries() {
                // A source whiteout in the upper hides this inherited name.
                if result.lookup(name).is_some()
                    || result
                        .lookup(OsStr::from_bytes(
                            &[b".wh.".as_slice(), name.as_bytes()].concat(),
                        ))
                        .is_some()
                {
                    continue;
                }
                ensure!(
                    !name.as_bytes().starts_with(b".wh."),
                    "OCI reserves filename {name:?}"
                );
                result.insert(name, self.inherited_inode(inode)?);
            }
        }
        if opaque || redirected.is_some() {
            result.insert(OsStr::new(".wh..wh..opq"), self.whiteout());
        }
        Ok(result)
    }
}

/// Store adapter for the standard scanner. Metacopy payloads are sparse
/// placeholders, potentially very large, and must never be imported as data.
struct UpperStore<H: FsVerityHashValue> {
    repo: Arc<Repository<H>>,
    namespace: XattrNamespace,
}

impl<H: FsVerityHashValue> ObjectStore<H> for UpperStore<H> {
    fn ensure_object_from_fd(&self, fd: OwnedFd, size: u64) -> Result<H> {
        let key = self.namespace.name(Xattr::Metacopy);
        match rustix::fs::fgetxattr(&fd, key, &mut [0u8; 0]) {
            Ok(_) | Err(rustix::io::Errno::RANGE) => return Ok(H::EMPTY),
            Err(rustix::io::Errno::NODATA) => {}
            Err(error) => return Err(error).context("Checking upper file metacopy marker"),
        }
        ObjectStore::ensure_object_from_fd(self.repo.as_ref(), fd, size)
    }

    fn write_semaphore(&self) -> Arc<tokio::sync::Semaphore> {
        self.repo.write_semaphore()
    }
}

/// Read the raw upper tree using composefs's scanner. A subsequent call to
/// `normalize` must resolve its metacopy placeholders against the parent,
/// using the same `namespace` selected for this read and the original mount.
pub async fn read_upper<H: FsVerityHashValue>(
    repo: &Arc<Repository<H>>,
    upper: &Path,
    namespace: XattrNamespace,
) -> Result<FileSystem<H>> {
    let fd = rustix::fs::open(
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let mut fs = composefs::fs::read_filesystem_with_opts(
        fd,
        upper.to_owned(),
        ReadFilesystemOpts {
            store: Some(Arc::new(UpperStore {
                repo: repo.clone(),
                namespace,
            })),
            ..Default::default()
        },
    )
    .await
    .context("Reading overlay upper directory")?;
    // Runtime SELinux labels describe this run's host isolation, not the image.
    fs.filter_xattrs(|key| key != OsStr::new("security.selinux"));
    Ok(fs)
}
