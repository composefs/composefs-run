//! Layer serialization, overlay translation and OCI image construction tests.

use crate::overlay::{Xattr, XattrNamespace};
use anyhow::Result;
use composefs::{
    erofs::{
        reader::erofs_to_filesystem,
        writer::{ValidatedFileSystem, mkfs_erofs},
    },
    fsverity::{FsVerityHashValue, Sha256HashValue, Sha512HashValue},
    repository::{Repository, RepositoryConfig},
    tree::{Directory, FileSystem, Inode, LeafContent, RegularFile, Stat},
};
use composefs_oci::{
    OciImage,
    tar::{TarEntry, TarItem},
};
use oci_spec::image::{HistoryBuilder, ImageConfiguration, ImageManifest};
use rustix::fs::CWD;
use std::{
    collections::HashMap, ffi::OsStr, io::Read, os::unix::ffi::OsStrExt, path::Path, sync::Arc,
};

fn stat() -> Stat {
    Stat {
        st_mode: 0o755,
        st_uid: 0,
        st_gid: 0,
        st_mtim_sec: 0,
        st_mtim_nsec: 0,
        xattrs: Default::default(),
    }
}

fn add<H: FsVerityHashValue>(fs: &mut FileSystem<H>, path: &str, content: LeafContent<H>) {
    let id = fs.push_leaf(stat(), content);
    let (dir, name) = fs.root.split_mut(OsStr::new(path)).unwrap();
    dir.insert(name, Inode::leaf(id));
}

fn file<H: FsVerityHashValue>(fs: &mut FileSystem<H>, path: &str, data: &[u8]) {
    add(
        fs,
        path,
        LeafContent::Regular(RegularFile::Inline(data.into())),
    );
}

fn directory<H: FsVerityHashValue>(fs: &mut FileSystem<H>, name: &str) {
    let (parent, name) = fs.root.split_mut(OsStr::new(name)).unwrap();
    parent.insert(name, Inode::Directory(Box::new(Directory::new(stat()))));
}

fn read_layer<H: FsVerityHashValue>(repo: &Repository<H>, id: &H) -> Result<Vec<TarEntry<H>>> {
    let mut stream = repo.open_stream(
        "",
        Some(id),
        Some(crate::canonical_tar::TAR_LAYER_CONTENT_TYPE),
    )?;
    let mut entries = Vec::new();
    while let Some(entry) = composefs_oci::tar::get_entry(&mut stream)? {
        entries.push(entry);
    }
    Ok(entries)
}

fn bytes<H: FsVerityHashValue>(
    fs: &FileSystem<H>,
    path: &str,
    repo: &Repository<H>,
) -> Result<Vec<u8>> {
    let (dir, name) = fs.root.split(OsStr::new(path))?;
    let leaf = fs.leaf(dir.leaf_id(name)?);
    match &leaf.content {
        LeafContent::Regular(RegularFile::Inline(data)) => Ok(data.to_vec()),
        LeafContent::Regular(RegularFile::External(id, _)) => repo.read_object(id),
        content => anyhow::bail!("Unexpected content {content:?}"),
    }
}

#[test]
fn canonical_layer_roundtrip() -> Result<()> {
    fn run<H: FsVerityHashValue>() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let (repo, _) = Repository::<H>::init_path(
            CWD,
            temp.path().join("repo"),
            RepositoryConfig::new(H::ALGORITHM).set_insecure(),
        )?;
        let repo = Arc::new(repo);
        let mut fs = FileSystem::new(stat());
        directory(&mut fs, "a");
        file(&mut fs, "/a/inline", b"hello");
        let data = vec![b'x'; 8193];
        let object = repo.ensure_object(&data)?;
        add(
            &mut fs,
            "/a/external",
            LeafContent::Regular(RegularFile::External(object.clone(), data.len() as u64)),
        );
        let id = fs
            .root
            .get_directory(OsStr::new("a"))?
            .leaf_id(OsStr::new("external"))?;
        fs.root.insert(OsStr::new("hardlink"), Inode::leaf(id));
        let long_name = "z".repeat(130);
        file(&mut fs, &format!("/{long_name}"), b"long");
        add(
            &mut fs,
            "/symlink",
            LeafContent::Symlink(OsStr::new(&"s".repeat(120)).into()),
        );
        add(&mut fs, "/fifo", LeafContent::Fifo);
        add(
            &mut fs,
            "/device",
            LeafContent::CharacterDevice(rustix::fs::makedev(1, 3)),
        );
        fs.root.stat.st_uid = u32::MAX;
        fs.root.stat.st_gid = u32::MAX;
        fs.root.stat.st_mtim_sec = 8_589_934_592;
        fs.root.stat.st_mtim_nsec = 123_400_000;
        fs.root.stat.xattrs.insert(
            OsStr::new("user.binary").into(),
            Box::from(b"\0\xff\n=value".as_slice()),
        );
        let (digest, verity, size) = crate::canonical_tar::write_layer(&repo, &fs)?;
        let mut raw = Vec::new();
        let mut stream = repo.open_stream("", Some(&verity), None)?;
        stream.cat(&repo, &mut raw)?;
        assert_eq!(raw.len() as u64, size);
        assert_eq!(digest, composefs_oci::sha256_content_digest(&raw));
        assert_eq!(raw[156], b'g');
        assert_eq!(&raw[512..531], b"19 canonical-tar=1\n");
        assert!(raw[raw.len() - 1024..].iter().all(|b| *b == 0));
        assert_eq!(&raw[148..156][6..], b"\0 ");
        assert_eq!(&raw[257..265], b"ustar\000");
        assert_eq!(&raw[345..500], &[0; 155]);
        let mut objects = Vec::new();
        stream = repo.open_stream("", Some(&verity), None)?;
        stream.get_object_refs(|id| objects.push(id.clone()))?;
        assert_eq!(objects, [object]);
        let entries = read_layer(&repo, &verity)?;
        let paths: Vec<_> = entries
            .iter()
            .map(|e| {
                e.path
                    .components()
                    .collect::<std::path::PathBuf>()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert_eq!(
            paths,
            [
                "/",
                "/a",
                "/a/external",
                "/a/inline",
                "/device",
                "/fifo",
                "/hardlink",
                "/symlink",
                &format!("/{long_name}")
            ]
        );
        assert_eq!(entries[0].stat.st_uid, u32::MAX);
        assert_eq!(entries[0].stat.st_mtim_nsec, 123_400_000);
        assert_eq!(entries[0].stat.xattrs, fs.root.stat.xattrs);
        assert!(
            matches!(&entries[6].item, TarItem::Hardlink(target) if Path::new(target) == Path::new("/a/external"))
        );
        let mut archive = tar::Archive::new(raw.as_slice());
        let mut saw_content = false;
        for entry in archive.entries()? {
            let mut entry = entry?;
            if entry.path()?.as_ref() == Path::new("./a/external") {
                let mut content = Vec::new();
                entry.read_to_end(&mut content)?;
                assert_eq!(content, data);
                saw_content = true;
            }
        }
        assert!(saw_content);
        let again = crate::canonical_tar::write_layer(&repo, &fs)?;
        assert_eq!((digest, verity, size), again);
        Ok(())
    }
    run::<Sha256HashValue>()?;
    run::<Sha512HashValue>()
}

#[test]
fn overlay_whiteouts() -> Result<()> {
    for (namespace, prefix) in [
        (XattrNamespace::Trusted, "trusted.overlay."),
        (XattrNamespace::User, "user.overlay."),
    ] {
        let mut fs = FileSystem::<Sha256HashValue>::new(stat());
        directory(&mut fs, "opaque");
        fs.root
            .get_directory_mut(OsStr::new("opaque"))?
            .stat
            .xattrs
            .insert(
                OsStr::new(&format!("{prefix}opaque")).into(),
                Box::from(b"y".as_slice()),
            );
        file(&mut fs, "/opaque/!keep", b"present");
        add(&mut fs, "/deleted", LeafContent::CharacterDevice(0));
        file(&mut fs, "/xdeleted", b"");
        let id = fs.root.leaf_id(OsStr::new("xdeleted"))?;
        fs.leaf_mut(id).stat.xattrs.insert(
            OsStr::new(&format!("{prefix}whiteout")).into(),
            Box::default(),
        );
        fs.root.insert(OsStr::new("xdeleted2"), Inode::leaf(id));
        fs.root.stat.xattrs.insert(
            OsStr::new(&format!("{prefix}origin")).into(),
            Box::from(b"internal".as_slice()),
        );
        let temp = tempfile::tempdir()?;
        let (repo, _) = Repository::<Sha256HashValue>::init_path(
            CWD,
            temp.path().join("repo"),
            RepositoryConfig::default().set_insecure(),
        )?;
        let fs = crate::overlay::normalize(&repo, &FileSystem::new(stat()), fs, namespace)?;
        let entries = crate::canonical_tar::entries(&fs);
        assert_eq!(
            entries
                .iter()
                .map(|e| e.path.to_str().unwrap())
                .collect::<Vec<_>>(),
            [
                "/",
                "/.wh.deleted",
                "/.wh.xdeleted",
                "/.wh.xdeleted2",
                "/opaque",
                "/opaque/!keep",
                "/opaque/.wh..wh..opq"
            ]
        );
        for entry in entries.iter().filter(|e| {
            e.path
                .file_name()
                .is_some_and(|n| n.as_bytes().starts_with(b".wh."))
        }) {
            assert_eq!(entry.stat.st_mode, 0o644);
            assert_eq!(entry.stat.st_mtim_sec, 0);
            assert!(
                matches!(&entry.item, TarItem::Leaf(LeafContent::Regular(RegularFile::Inline(data))) if data.is_empty())
            );
        }
        fs.for_each_stat(|s| assert!(s.xattrs.is_empty()));
    }
    Ok(())
}

#[test]
fn child_image_preserves_parent_and_applies_layer() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let (repo, _) = Repository::<Sha256HashValue>::init_path(
        CWD,
        temp.path().join("repo"),
        RepositoryConfig::default().set_insecure(),
    )?;
    let repo = Arc::new(repo);
    let mut base = FileSystem::new(stat());
    directory(&mut base, "usr");
    directory(&mut base, "opaque");
    file(&mut base, "/kept", b"unchanged");
    file(&mut base, "/deleted", b"delete me");
    file(&mut base, "/changed", b"before");
    file(&mut base, "/opaque/old", b"hidden");
    let (diff, layer_id, size) = crate::canonical_tar::write_layer(&repo, &base)?;
    let images = base.commit_images(&repo, None)?;
    let config: ImageConfiguration = serde_json::from_value(
        serde_json::json!({"architecture":"amd64", "os":"linux", "config":{"Env":["BASE=preserved"], "Cmd":["/bin/sh"]}, "rootfs":{"type":"layers", "diff_ids":[diff]}}),
    )?;
    let refs = HashMap::from([(diff.to_string().into_boxed_str(), layer_id)]);
    for history in [
        None,
        Some(vec![]),
        Some(vec![
            HistoryBuilder::default()
                .created("2025-05-13T07:48:55.650698239Z")
                .created_by("parent")
                .build()?,
        ]),
    ] {
        let mut config = config.clone();
        config.set_history(history.clone());
        let (config_digest, config_id) = composefs_oci::write_config(
            &repo,
            &config,
            refs.clone(),
            images.get(&composefs::erofs::format::FormatVersion::V2),
            images.get(&composefs::erofs::format::FormatVersion::V1),
            &HashMap::new(),
        )?;
        let manifest: ImageManifest = serde_json::from_value(
            serde_json::json!({"schemaVersion":2, "mediaType":"application/vnd.oci.image.manifest.v1+json", "config":{"mediaType":"application/vnd.oci.image.config.v1+json", "digest":config_digest, "size":config.to_string()?.len()}, "layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar", "digest":diff, "size":size}]}),
        )?;
        let digest = composefs_oci::sha256_content_digest(manifest.to_string()?.as_bytes());
        composefs_oci::oci_image::write_manifest(
            &repo,
            &manifest,
            &digest,
            &config_id,
            &refs.clone().into_iter().collect::<Vec<_>>(),
            Some("base"),
        )?;
        let parent = OciImage::open_ref(&repo, "base")?;
        let mut upper = FileSystem::new(stat());
        directory(&mut upper, "opaque");
        upper
            .root
            .get_directory_mut(OsStr::new("opaque"))?
            .stat
            .xattrs
            .insert(
                OsStr::new(XattrNamespace::User.name(Xattr::Opaque)).into(),
                Box::from(b"y".as_slice()),
            );
        file(&mut upper, "/opaque/!keep", b"new");
        directory(&mut upper, "/opaque/sub");
        upper
            .root
            .get_directory_mut(OsStr::new("/opaque/sub"))?
            .stat
            .xattrs
            .insert(
                OsStr::new(XattrNamespace::User.name(Xattr::Opaque)).into(),
                Box::from(b"y".as_slice()),
            );
        directory(&mut upper, "/opaque/sub/empty");
        file(&mut upper, "/opaque/sub/file", b"nested");
        file(&mut upper, "/changed", b"after");
        add(&mut upper, "/deleted", LeafContent::CharacterDevice(0));
        let upper = crate::overlay::normalize(&repo, &base, upper, XattrNamespace::User)?;
        let created_by = "sh -c 'printf after > /changed'";
        let before = std::time::SystemTime::now();
        let committed = crate::commit::create_image(&repo, &parent, &upper, "child", created_by)?;
        let after = std::time::SystemTime::now();
        let child = OciImage::open_ref(&repo, "child")?;
        assert_eq!(child.manifest_digest(), &committed);
        assert_eq!(
            &child.manifest().layers()[0],
            &parent.manifest().layers()[0]
        );
        assert_eq!(child.manifest().layers().len(), 2);
        let child_config = child.config().unwrap();
        assert_eq!(child_config.config(), config.config());
        assert_eq!(child_config.rootfs().diff_ids().len(), 2);
        match history {
            None => assert!(child_config.history().is_none()),
            Some(history) if history.is_empty() => {
                assert_eq!(child_config.history().as_ref().unwrap().len(), 0)
            }
            Some(history) => {
                let child_history = child_config.history().as_ref().unwrap();
                assert_eq!(&child_history[..history.len()], history);
                assert_eq!(child_history.len(), history.len() + 1);
                assert_eq!(
                    child_history.last().unwrap().created_by().as_deref(),
                    Some(created_by)
                );
                let created = child_history.last().unwrap().created().as_deref().unwrap();
                let timestamp = chrono::DateTime::parse_from_rfc3339(created)?;
                assert!(created.ends_with('Z'));
                let timestamp: std::time::SystemTime = timestamp.into();
                assert!((before..=after).contains(&timestamp));
            }
        }
        let merged = child.read_filesystem(&repo, false)?;
        assert_eq!(bytes(&merged, "/kept", &repo)?, b"unchanged");
        assert_eq!(bytes(&merged, "/changed", &repo)?, b"after");
        assert_eq!(bytes(&merged, "/opaque/!keep", &repo)?, b"new");
        assert_eq!(bytes(&merged, "/opaque/sub/file", &repo)?, b"nested");
        assert!(
            merged
                .root
                .get_directory(OsStr::new("/opaque/sub/empty"))
                .is_ok()
        );
        assert!(merged.root.lookup(OsStr::new("deleted")).is_none());
        assert!(
            merged
                .root
                .get_directory(OsStr::new("opaque"))?
                .lookup(OsStr::new("old"))
                .is_none()
        );
        assert_eq!(
            bytes(&parent.read_filesystem(&repo, false)?, "/changed", &repo)?,
            b"before"
        );
        let mut unsupported = FileSystem::new(stat());
        add(&mut unsupported, "/socket", LeafContent::Socket);
        assert!(
            crate::commit::create_image(&repo, &parent, &unsupported, "child", created_by).is_err()
        );
        assert_eq!(
            OciImage::open_ref(&repo, "child")?.manifest_digest(),
            &committed
        );
        // Reusing an existing ref and committing from a previously committed image.
        crate::commit::create_image(&repo, &child, &FileSystem::new(stat()), "base", "true")?;
        assert_eq!(
            OciImage::open_ref(&repo, "base")?.manifest().layers().len(),
            3
        );
        for reference in ["../escape", "", "/absolute", "a//b", "@digest", "bad\0ref"] {
            assert!(
                crate::commit::create_image(&repo, &parent, &upper, reference, created_by).is_err()
            );
        }
    }
    Ok(())
}

fn xattr<H: FsVerityHashValue>(fs: &mut FileSystem<H>, path: &str, key: &str, value: &[u8]) {
    let (dir, name) = fs.root.split(OsStr::new(path)).unwrap();
    let id = dir.leaf_id(name).unwrap();
    fs.leaf_mut(id)
        .stat
        .xattrs
        .insert(OsStr::new(key).into(), value.into());
}

fn redirect<H: FsVerityHashValue>(fs: &mut FileSystem<H>, path: &str, prefix: &str, target: &[u8]) {
    fs.root
        .get_directory_mut(OsStr::new(path))
        .unwrap()
        .stat
        .xattrs
        .insert(
            OsStr::new(&format!("{prefix}redirect")).into(),
            target.into(),
        );
}

#[test]
fn normalize_without_mounts() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let (repo, _) = Repository::<Sha256HashValue>::init_path(
        CWD,
        temp.path().join("repo"),
        RepositoryConfig::default().set_insecure(),
    )?;
    let data = vec![b'm'; 8193];
    let content_id = repo.ensure_object(&data)?;
    let mut parent = FileSystem::new(stat());
    directory(&mut parent, "/old");
    directory(&mut parent, "/old/nested");
    directory(&mut parent, "/elsewhere");
    directory(&mut parent, "/destination");
    file(&mut parent, "/destination/unrelated", b"must be hidden");
    file(&mut parent, "/old/keep", b"inherited");
    file(&mut parent, "/old/deleted", b"deleted");
    file(&mut parent, "/old/nested/lower", b"nested data");
    file(&mut parent, "/elsewhere/other", b"absolute redirect");
    add(
        &mut parent,
        "/metadata",
        LeafContent::Regular(RegularFile::External(content_id.clone(), data.len() as u64)),
    );
    let parent_id = parent.root.leaf_id(OsStr::new("metadata"))?;
    parent
        .root
        .get_directory_mut(OsStr::new("old"))?
        .insert(OsStr::new("linked"), Inode::leaf(parent_id));
    parent
        .root
        .get_directory_mut(OsStr::new("elsewhere"))?
        .insert(OsStr::new("linked"), Inode::leaf(parent_id));
    for (namespace, prefix) in [
        (XattrNamespace::Trusted, "trusted.overlay."),
        (XattrNamespace::User, "user.overlay."),
    ] {
        let mut upper = FileSystem::new(stat());
        directory(&mut upper, "/destination");
        redirect(&mut upper, "/destination", prefix, b"old");
        directory(&mut upper, "/destination/relative");
        redirect(&mut upper, "/destination/relative", prefix, b"nested");
        directory(&mut upper, "/destination/absolute");
        redirect(&mut upper, "/destination/absolute", prefix, b"/elsewhere");
        file(&mut upper, "/destination/added", b"upper");
        add(
            &mut upper,
            "/destination/deleted",
            LeafContent::CharacterDevice(0),
        );
        add(&mut upper, "/old", LeafContent::CharacterDevice(0));
        file(&mut upper, "/metadata", b"");
        xattr(&mut upper, "/metadata", &format!("{prefix}metacopy"), b"");
        let id = upper.root.leaf_id(OsStr::new("metadata"))?;
        upper.leaf_mut(id).stat.st_mode = 0o600;
        upper
            .root
            .insert(OsStr::new("a-new-alias"), Inode::leaf(id));
        upper
            .root
            .get_directory_mut(OsStr::new("destination"))?
            .insert(OsStr::new("upper-alias"), Inode::leaf(id));
        file(&mut upper, "/renamed-file", b"");
        xattr(
            &mut upper,
            "/renamed-file",
            &format!("{prefix}metacopy"),
            b"",
        );
        xattr(
            &mut upper,
            "/renamed-file",
            &format!("{prefix}redirect"),
            b"/metadata",
        );
        file(&mut upper, "/renamed-and-written", b"new data");
        xattr(
            &mut upper,
            "/renamed-and-written",
            &format!("{prefix}redirect"),
            b"/metadata",
        );
        let layer = crate::overlay::normalize(&repo, &parent, upper, namespace)?;
        assert_eq!(bytes(&layer, "/metadata", &repo)?, data);
        assert_eq!(bytes(&layer, "/renamed-file", &repo)?, data);
        assert_eq!(bytes(&layer, "/renamed-and-written", &repo)?, b"new data");
        assert_eq!(bytes(&layer, "/destination/keep", &repo)?, b"inherited");
        assert_eq!(bytes(&layer, "/destination/added", &repo)?, b"upper");
        assert_eq!(
            bytes(&layer, "/destination/relative/lower", &repo)?,
            b"nested data"
        );
        assert_eq!(
            bytes(&layer, "/destination/absolute/other", &repo)?,
            b"absolute redirect"
        );
        let destination = layer.root.get_directory(OsStr::new("destination"))?;
        assert!(destination.lookup(OsStr::new("deleted")).is_none());
        assert!(destination.lookup(OsStr::new("unrelated")).is_none());
        assert!(destination.lookup(OsStr::new(".wh.deleted")).is_some());
        assert!(destination.lookup(OsStr::new(".wh..wh..opq")).is_some());
        let id = layer.root.leaf_id(OsStr::new("metadata"))?;
        assert_eq!(layer.root.leaf_id(OsStr::new("a-new-alias"))?, id);
        assert_eq!(destination.leaf_id(OsStr::new("upper-alias"))?, id);
        assert_eq!(layer.leaf(id).stat.st_mode, 0o600);
        assert!(
            matches!(&layer.leaf(id).content, LeafContent::Regular(RegularFile::External(object, size)) if *object == content_id && *size == data.len() as u64)
        );
        assert_eq!(
            destination.leaf_id(OsStr::new("linked"))?,
            destination
                .get_directory(OsStr::new("absolute"))?
                .leaf_id(OsStr::new("linked"))?
        );
        layer.for_each_stat(|s| assert!(s.xattrs.is_empty()));
    }
    assert_eq!(bytes(&parent, "/old/deleted", &repo)?, b"deleted");
    Ok(())
}

#[test]
fn reused_parent_nodes_keep_resolved_contents() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let (repo, _) = Repository::<Sha256HashValue>::init_path(
        CWD,
        temp.path().join("repo"),
        RepositoryConfig::default().set_insecure(),
    )?;
    let data = vec![b'p'; 8193];
    let object = repo.ensure_object(&data)?;
    let mut parent = FileSystem::new(stat());
    directory(&mut parent, "/source");
    directory(&mut parent, "/source/nested");
    add(
        &mut parent,
        "/source/nested/file",
        LeafContent::Regular(RegularFile::External(object.clone(), data.len() as u64)),
    );
    let id = parent
        .root
        .get_directory(OsStr::new("/source/nested"))?
        .leaf_id(OsStr::new("file"))?;
    parent.root.insert(OsStr::new("metadata"), Inode::leaf(id));
    for prefix in ["trusted.overlay.", "user.overlay."] {
        // These are image metadata: the EROFS writer escapes reserved names.
        xattr(
            &mut parent,
            "/metadata",
            &format!("{prefix}redirect"),
            b"/missing",
        );
        redirect(&mut parent, "/source/nested", prefix, b"/missing");
    }
    let object_path = object.to_object_pathname();
    let (dir, name) = object_path.split_once('/').unwrap();
    directory(&mut parent, dir);
    file(
        &mut parent,
        &format!("/{dir}/{name}"),
        b"wrong logical data",
    );

    // Use the same EROFS decoder as OciImage::read_filesystem. The lower
    // inode's object reference must not resolve through its own image tree.
    let image = mkfs_erofs(&ValidatedFileSystem::new(parent)?);
    let parent: FileSystem<Sha256HashValue> = erofs_to_filesystem(&image)?;
    let parent_id = parent.root.leaf_id(OsStr::new("metadata"))?;
    assert!(matches!(
        &parent.leaf(parent_id).content,
        LeafContent::Regular(RegularFile::External(id, size))
            if *id == object && *size == data.len() as u64
    ));
    for (namespace, prefix) in [
        (XattrNamespace::Trusted, "trusted.overlay."),
        (XattrNamespace::User, "user.overlay."),
    ] {
        let mut upper = FileSystem::new(stat());
        directory(&mut upper, "/destination");
        redirect(&mut upper, "/destination", prefix, b"/source");
        file(&mut upper, "/metadata", b"");
        xattr(&mut upper, "/metadata", &format!("{prefix}metacopy"), b"");
        file(&mut upper, "/renamed", b"");
        xattr(&mut upper, "/renamed", &format!("{prefix}metacopy"), b"");
        xattr(
            &mut upper,
            "/renamed",
            &format!("{prefix}redirect"),
            b"/metadata",
        );
        let layer = crate::overlay::normalize(&repo, &parent, upper, namespace)?;
        assert_eq!(bytes(&layer, "/metadata", &repo)?, data);
        assert_eq!(bytes(&layer, "/renamed", &repo)?, data);
        assert_eq!(bytes(&layer, "/destination/nested/file", &repo)?, data);
        let id = layer
            .root
            .get_directory(OsStr::new("/destination/nested"))?
            .leaf_id(OsStr::new("file"))?;
        assert_eq!(
            layer.leaf(id).stat.xattrs,
            parent.leaf(parent_id).stat.xattrs
        );
        assert_eq!(
            layer
                .root
                .get_directory(OsStr::new("/destination/nested"))?
                .stat
                .xattrs,
            parent
                .root
                .get_directory(OsStr::new("/source/nested"))?
                .stat
                .xattrs,
        );
    }
    Ok(())
}

#[test]
fn normalization_uses_selected_xattr_namespace() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let (repo, _) = Repository::<Sha256HashValue>::init_path(
        CWD,
        temp.path().join("repo"),
        RepositoryConfig::default().set_insecure(),
    )?;
    let mut parent = FileSystem::new(stat());
    file(&mut parent, "/metadata", b"parent data");
    for (namespace, prefix, other) in [
        (XattrNamespace::Trusted, "trusted.overlay.", "user.overlay."),
        (XattrNamespace::User, "user.overlay.", "trusted.overlay."),
    ] {
        let mut upper = FileSystem::new(stat());
        file(&mut upper, "/metadata", b"");
        xattr(&mut upper, "/metadata", &format!("{prefix}metacopy"), b"");
        xattr(
            &mut upper,
            "/metadata",
            &format!("{prefix}redirect"),
            b"/metadata",
        );
        xattr(
            &mut upper,
            "/metadata",
            &format!("{other}redirect"),
            b"/missing",
        );
        xattr(
            &mut upper,
            "/metadata",
            &format!("{prefix}overlay.metacopy"),
            b"ordinary image metadata",
        );
        file(&mut upper, "/regular", b"upper data");
        for key in ["metacopy", "whiteout", "redirect", "overlay.redirect"] {
            xattr(&mut upper, "/regular", &format!("{other}{key}"), b"");
        }
        directory(&mut upper, "/dir");
        redirect(&mut upper, "/dir", other, b"/missing");
        let dir = upper.root.get_directory_mut(OsStr::new("dir"))?;
        dir.stat.xattrs.insert(
            OsStr::new(&format!("{prefix}opaque")).into(),
            Box::from(b"x".as_slice()),
        );
        dir.stat.xattrs.insert(
            OsStr::new(&format!("{other}opaque")).into(),
            Box::from(b"y".as_slice()),
        );
        let mut expected_dir = dir.stat.xattrs.clone();
        expected_dir.retain(|key, _| key.as_bytes().starts_with(other.as_bytes()));
        dir.stat.xattrs.insert(
            OsStr::new(&format!("{prefix}overlay.redirect")).into(),
            Box::from(b"/ordinary".as_slice()),
        );
        expected_dir.insert(
            OsStr::new(namespace.name(Xattr::Redirect)).into(),
            Box::from(b"/ordinary".as_slice()),
        );
        let regular_id = upper.root.leaf_id(OsStr::new("regular"))?;
        let mut expected_regular = upper.leaf(regular_id).stat.xattrs.clone();
        for suffix in ["redirect", "overlay.redirect"] {
            xattr(
                &mut upper,
                "/regular",
                &format!("{prefix}overlay.{suffix}"),
                b"/ordinary",
            );
            expected_regular.insert(
                OsStr::new(&format!("{prefix}{suffix}")).into(),
                Box::from(b"/ordinary".as_slice()),
            );
        }

        let layer = crate::overlay::normalize(&repo, &parent, upper, namespace)?;
        assert_eq!(bytes(&layer, "/metadata", &repo)?, b"parent data");
        assert_eq!(bytes(&layer, "/regular", &repo)?, b"upper data");
        let id = layer.root.leaf_id(OsStr::new("regular"))?;
        assert_eq!(layer.leaf(id).stat.xattrs, expected_regular);
        let id = layer.root.leaf_id(OsStr::new("metadata"))?;
        assert_eq!(layer.leaf(id).stat.xattrs.len(), 2);
        assert_eq!(
            layer.leaf(id).stat.xattrs[OsStr::new(namespace.name(Xattr::Metacopy))].as_ref(),
            b"ordinary image metadata"
        );
        assert_eq!(
            layer.leaf(id).stat.xattrs[OsStr::new(&format!("{other}redirect"))].as_ref(),
            b"/missing"
        );
        let dir = layer.root.get_directory(OsStr::new("dir"))?;
        assert_eq!(dir.stat.xattrs, expected_dir);
        assert!(dir.entries().next().is_none());
    }
    Ok(())
}

#[test]
fn read_raw_upper_skips_metacopy_payload() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let (repo, _) = Repository::<Sha256HashValue>::init_path(
        CWD,
        temp.path().join("repo"),
        RepositoryConfig::default().set_insecure(),
    )?;
    let repo = Arc::new(repo);
    let upper = temp.path().join("upper");
    std::fs::create_dir(&upper)?;
    let fd = std::fs::File::create(upper.join("metadata"))?;
    fd.set_len(128 * 1024 * 1024)?;
    drop(fd);
    rustix::fs::setxattr(
        upper.join("metadata"),
        XattrNamespace::User.name(Xattr::Metacopy),
        b"",
        rustix::fs::XattrFlags::empty(),
    )?;
    std::fs::hard_link(upper.join("metadata"), upper.join("alias"))?;
    let runtime = tokio::runtime::Runtime::new()?;
    let raw = runtime.block_on(crate::overlay::read_upper(
        &repo,
        &upper,
        XattrNamespace::User,
    ))?;
    let id = raw.root.leaf_id(OsStr::new("metadata"))?;
    assert!(
        matches!(&raw.leaf(id).content, LeafContent::Regular(RegularFile::External(id, _)) if *id == Sha256HashValue::EMPTY)
    );
    let mut parent = FileSystem::new(stat());
    file(&mut parent, "/metadata", b"real parent content");
    let normalized = crate::overlay::normalize(&repo, &parent, raw, XattrNamespace::User)?;
    assert_eq!(bytes(&normalized, "/alias", &repo)?, b"real parent content");
    assert_eq!(
        std::fs::metadata(upper.join("metadata"))?.len(),
        128 * 1024 * 1024
    );
    assert!(repo.open_object(&Sha256HashValue::EMPTY).is_err());
    // A user xattr on a trusted-overlay upper must not suppress real data.
    let other_upper = temp.path().join("other-upper");
    std::fs::create_dir(&other_upper)?;
    let data = vec![b'd'; 8193];
    std::fs::write(other_upper.join("regular"), &data)?;
    rustix::fs::setxattr(
        other_upper.join("regular"),
        XattrNamespace::User.name(Xattr::Metacopy),
        b"",
        rustix::fs::XattrFlags::empty(),
    )?;
    let raw = runtime.block_on(crate::overlay::read_upper(
        &repo,
        &other_upper,
        XattrNamespace::Trusted,
    ))?;
    assert_eq!(bytes(&raw, "/regular", &repo)?, data);
    let normalized = crate::overlay::normalize(&repo, &parent, raw, XattrNamespace::Trusted)?;
    assert_eq!(bytes(&normalized, "/regular", &repo)?, data);
    let id = normalized.root.leaf_id(OsStr::new("regular"))?;
    assert!(
        normalized
            .leaf(id)
            .stat
            .xattrs
            .contains_key(OsStr::new(XattrNamespace::User.name(Xattr::Metacopy)))
    );
    // Normal lower files win collisions; data-only redirects must be absolute.
    let object_data = vec![b'o'; 1024];
    let object = repo.ensure_object(&object_data)?;
    let parent_data = b"different logical file".as_slice();
    for (prefix, parent_data, expected) in [
        ("/", None, Some(object_data.as_slice())),
        ("/", Some(parent_data), Some(parent_data)),
        ("", Some(parent_data), Some(parent_data)),
        ("", None, None),
    ] {
        let mut upper = FileSystem::new(stat());
        file(&mut upper, "/object", b"");
        xattr(
            &mut upper,
            "/object",
            XattrNamespace::User.name(Xattr::Metacopy),
            b"",
        );
        xattr(
            &mut upper,
            "/object",
            XattrNamespace::User.name(Xattr::Redirect),
            format!("{prefix}{}", object.to_object_pathname()).as_bytes(),
        );
        let mut parent = FileSystem::new(stat());
        if let Some(data) = parent_data {
            let object_path = object.to_object_pathname();
            let (dir, name) = object_path.split_once('/').unwrap();
            directory(&mut parent, dir);
            file(&mut parent, &format!("/{dir}/{name}"), data);
        }
        let normalized = crate::overlay::normalize(&repo, &parent, upper, XattrNamespace::User);
        match expected {
            Some(expected) => assert_eq!(bytes(&normalized?, "/object", &repo)?, expected),
            None => assert!(normalized.is_err()),
        }
    }
    Ok(())
}

#[test]
fn normalization_rejects_unresolved_or_invalid_upper() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let (repo, _) = Repository::<Sha256HashValue>::init_path(
        CWD,
        temp.path().join("repo"),
        RepositoryConfig::default().set_insecure(),
    )?;
    let parent = FileSystem::new(stat());
    for target in [
        b"".as_slice(),
        b"../escape",
        b"/a/../b",
        b"/a/./b",
        b"/bad\0path",
        b"/missing",
    ] {
        let mut upper = FileSystem::new(stat());
        directory(&mut upper, "/dir");
        redirect(&mut upper, "/dir", "user.overlay.", target);
        assert!(
            crate::overlay::normalize(&repo, &parent, upper, XattrNamespace::User).is_err(),
            "redirect {target:?}"
        );
    }
    for (name, key, value) in [
        (
            "/missing",
            XattrNamespace::User.name(Xattr::Metacopy),
            b"".as_slice(),
        ),
        (
            "/bad-whiteout",
            XattrNamespace::User.name(Xattr::Whiteout),
            b"",
        ),
        ("/.wh.reserved", "user.foo", b"bar"),
    ] {
        let mut upper = FileSystem::new(stat());
        file(&mut upper, name, b"not empty");
        xattr(&mut upper, name, key, value);
        assert!(
            crate::overlay::normalize(&repo, &parent, upper, XattrNamespace::User).is_err(),
            "upper {name}"
        );
    }
    Ok(())
}
