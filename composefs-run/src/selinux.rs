use std::path::Path;

use anyhow::{Context, Result};

/// Apply the container's file label to a path when SELinux labeling is enabled.
pub fn label_path(path: &Path, label: Option<&str>) -> Result<()> {
    if let Some(label) = label {
        rustix::fs::lsetxattr(
            path,
            "security.selinux",
            label.as_bytes(),
            rustix::fs::XattrFlags::empty(),
        )
        .with_context(|| format!("Labeling {} with {label}", path.display()))?;
    }
    Ok(())
}

/// Generate SELinux process and mount labels.
/// Returns (process_label, mount_label), both None if SELinux is not enabled.
pub fn container_labels(label_opts: &[String]) -> (Option<String>, Option<String>) {
    if !Path::new("/sys/fs/selinux").exists() {
        return (None, None);
    }

    let mut process = "system_u:system_r:container_t:s0".to_string();
    let mut file = "system_u:object_r:container_file_t:s0".to_string();

    for opt in label_opts {
        if let Some(typ) = opt.strip_prefix("type:") {
            process = replace_field(&process, 2, typ);
        } else if let Some(level) = opt.strip_prefix("level:") {
            process = replace_field(&process, 3, level);
            file = replace_field(&file, 3, level);
        } else if let Some(user) = opt.strip_prefix("user:") {
            process = replace_field(&process, 0, user);
            file = replace_field(&file, 0, user);
        } else if let Some(role) = opt.strip_prefix("role:") {
            process = replace_field(&process, 1, role);
        } else if let Some(ftype) = opt.strip_prefix("filetype:") {
            file = replace_field(&file, 2, ftype);
        }
    }

    let has_level_opt = label_opts.iter().any(|o| o.starts_with("level:"));
    if !has_level_opt {
        let mcs = generate_mcs();
        process = append_mcs(&process, &mcs);
        file = append_mcs(&file, &mcs);
    }

    (Some(process), Some(file))
}

fn replace_field(label: &str, index: usize, value: &str) -> String {
    let mut parts: Vec<&str> = label.splitn(4, ':').collect();
    while parts.len() <= index {
        parts.push("");
    }
    parts[index] = value;
    parts.join(":")
}

fn append_mcs(label: &str, mcs: &str) -> String {
    let parts: Vec<&str> = label.splitn(4, ':').collect();
    if parts.len() >= 4 {
        format!(
            "{}:{}:{}:{}:{}",
            parts[0], parts[1], parts[2], parts[3], mcs
        )
    } else {
        format!("{label}:{mcs}")
    }
}

fn generate_mcs() -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    std::process::id().hash(&mut hasher);
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .hash(&mut hasher);
    let hash = hasher.finish();

    let c1 = (hash % 1024) as u32;
    let c2 = ((hash / 1024) % 1024) as u32;
    let (lo, hi) = if c1 < c2 { (c1, c2) } else { (c2, c1) };
    let hi = if lo == hi { (hi + 1) % 1024 } else { hi };
    format!("c{lo},c{hi}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replace_field_type() {
        let label = "system_u:system_r:container_t:s0";
        assert_eq!(
            replace_field(label, 2, "custom_t"),
            "system_u:system_r:custom_t:s0"
        );
    }

    #[test]
    fn replace_field_level() {
        let label = "system_u:system_r:container_t:s0";
        assert_eq!(
            replace_field(label, 3, "s0:c100,c200"),
            "system_u:system_r:container_t:s0:c100,c200"
        );
    }

    #[test]
    fn append_mcs_to_label() {
        assert_eq!(
            append_mcs("system_u:system_r:container_t:s0", "c100,c200"),
            "system_u:system_r:container_t:s0:c100,c200"
        );
    }

    #[test]
    fn mcs_format() {
        let mcs = generate_mcs();
        let parts: Vec<&str> = mcs.split(',').collect();
        assert_eq!(parts.len(), 2);
        assert!(parts[0].starts_with('c'));
        assert!(parts[1].starts_with('c'));
        let c1: u32 = parts[0][1..].parse().unwrap();
        let c2: u32 = parts[1][1..].parse().unwrap();
        assert_ne!(c1, c2);
        assert!(c1 < 1024);
        assert!(c2 < 1024);
    }
}
