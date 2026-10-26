//! OCI image construction from overlay upper trees.
//!
//! These APIs operate without a mounted overlay filesystem. Read an upper with
//! [`overlay::read_upper`], resolve its overlay metadata with
//! [`overlay::normalize`], then store a layer or child OCI image.
//! Both operations take the overlay xattr namespace selected for the mount.
//!
//! The reusable operations are separated from the runner's lifecycle handling
//! so they can eventually move into composefs-rs:
//!
//! - [`overlay::read_upper`] uses the composefs scanner without importing
//!   metacopy placeholder data.
//! - [`overlay::normalize`] resolves metacopy files and directory redirects
//!   against an immutable parent tree and repository, preserving hardlinks and
//!   translating whiteouts into OCI entries.
//! - [`canonical_tar::write_layer`] emits canonical tar headers and padding
//!   inline in a splitstream and references file-content objects. It computes
//!   SHA-256 over the logical tar bytes without writing a tar archive.
//! - [`commit::create_image`] stores a child image's config, manifest and EROFS
//!   image before assigning the destination ref.

pub mod canonical_tar;
pub mod commit;
pub mod overlay;

#[cfg(test)]
mod commit_tests;
