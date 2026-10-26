//! Create a child OCI image from a layer tree and its parent image.
//!
//! This module depends on composefs APIs, not runner state, so that the image
//! construction can eventually move to composefs-oci alongside layer generation.

use anyhow::{Context, Result, ensure};
use chrono::{DateTime, SecondsFormat, Utc};
use composefs::{
    erofs::format::FormatVersion, fsverity::FsVerityHashValue, repository::Repository,
    tree::FileSystem,
};
use composefs_oci::{OciDigest, OciImage, oci_image::write_manifest};
use oci_spec::image::{DescriptorBuilder, HistoryBuilder, MediaType};
use std::os::unix::ffi::OsStrExt;
use std::{collections::HashMap, sync::Arc, time::SystemTime};

/// Append a changeset to the parent's layers and publish the ref only once the
/// complete image, including its mountable EROFS, has been stored.
/// `created_by` describes the command responsible for the changeset.
pub fn create_image<H: FsVerityHashValue>(
    repo: &Arc<Repository<H>>,
    parent: &OciImage<H>,
    layer: &FileSystem<H>,
    reference: &str,
    created_by: &str,
) -> Result<OciDigest> {
    ensure!(
        !reference.is_empty()
            && !reference.starts_with('@')
            && !reference.contains('\0')
            && !reference
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == ".."),
        "Invalid OCI commit reference {reference:?}"
    );
    ensure!(
        parent.is_container_image(),
        "Parent is not an OCI container image"
    );
    let (diff_id, layer_verity, size) = crate::canonical_tar::write_layer(repo, layer)?;
    let mut config =
        composefs_oci::open_config(repo, parent.config_digest(), Some(parent.config_verity()))?
            .config;
    let mut rootfs = config.rootfs().clone();
    let mut diff_ids = rootfs.diff_ids().clone();
    diff_ids.push(diff_id.to_string());
    rootfs.set_diff_ids(diff_ids);
    config.set_rootfs(rootfs);
    // A layered image may validly omit history. Preserve that choice rather
    // than creating a partial history that accounts for only the new layer.
    if let Some(mut history) = config
        .history()
        .clone()
        .filter(|history| !history.is_empty() || parent.manifest().layers().is_empty())
    {
        history.push(
            HistoryBuilder::default()
                .created(
                    DateTime::<Utc>::from(SystemTime::now())
                        .to_rfc3339_opts(SecondsFormat::Nanos, true),
                )
                .created_by(created_by)
                .build()?,
        );
        config.set_history(Some(history));
    }
    let mut refs = parent.layer_refs().clone();
    refs.insert(diff_id.to_string().into_boxed_str(), layer_verity);
    let mut fs = parent.read_filesystem(repo, false)?;
    // Whiteouts affect only the parent. Apply them before adding any upper
    // entries: sorted names can precede an opaque marker in canonical tar.
    let (whiteouts, entries): (Vec<_>, Vec<_>) = crate::canonical_tar::entries(layer)
        .into_iter()
        .partition(|entry| {
            entry
                .path
                .file_name()
                .is_some_and(|name| name.as_bytes().starts_with(b".wh."))
        });
    for entry in whiteouts {
        let path = entry.path.parent().context("Whiteout without parent")?;
        if crate::overlay::parent_directory(&fs, path).is_some() {
            composefs_oci::image::process_entry(&mut fs, entry)?;
        }
    }
    for entry in entries {
        composefs_oci::image::process_entry(&mut fs, entry)?;
    }
    fs.transform_for_oci(&Default::default())?;
    let images = fs.commit_images(repo, None)?;
    let (config_digest, config_verity) = composefs_oci::write_config(
        repo,
        &config,
        refs.clone(),
        images.get(&FormatVersion::V2),
        images.get(&FormatVersion::V1),
        &HashMap::new(),
    )?;
    let mut manifest = parent.manifest().clone();
    manifest.set_media_type(Some(MediaType::ImageManifest));
    manifest.set_config(
        DescriptorBuilder::default()
            .media_type(MediaType::ImageConfig)
            .digest(config_digest)
            .size(config.to_string()?.len() as u64)
            .build()?,
    );
    let mut layers = manifest.layers().clone();
    layers.push(
        DescriptorBuilder::default()
            .media_type(MediaType::ImageLayer)
            .digest(diff_id)
            .size(size)
            .build()?,
    );
    manifest.set_layers(layers);
    let digest = composefs_oci::sha256_content_digest(manifest.to_string()?.as_bytes());
    let mut refs: Vec<_> = refs.into_iter().collect();
    refs.sort_by(|a, b| a.0.cmp(&b.0));
    write_manifest(
        repo,
        &manifest,
        &digest,
        &config_verity,
        &refs,
        Some(reference),
    )
    .context("Publishing committed image")?;
    Ok(digest)
}
