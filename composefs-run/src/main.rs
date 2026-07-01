//! Minimal container runner using composefs images and crun.

mod fuse;
mod netavark;
mod run;
mod seccomp;
mod selinux;
mod userns;

use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use clap::{CommandFactory, Parser};
use composefs::fsverity::{FsVerityHashValue, Sha256HashValue, Sha512HashValue};
use composefs::repository::{Repository, read_repo_algorithm};
use composefs_oci::OciDigest;
use rustix::fs::{CWD, Mode, OFlags};

/// Arguments for the internal cleanup mode (OCI poststop hook).
#[derive(Debug, Parser)]
pub(crate) struct CleanupArgs {
    /// Container state directory to clean up
    #[clap(long)]
    container_dir: Option<PathBuf>,

    /// Container ID (for netavark teardown)
    #[clap(long)]
    container_id: Option<String>,

    /// Allocated container IP (for netavark teardown + IPAM release)
    #[clap(long)]
    container_ip: Option<std::net::IpAddr>,

    /// PID of the pasta process to kill on cleanup
    #[clap(long)]
    pasta_pid: Option<i32>,
}

#[derive(Clone, Debug)]
pub(crate) struct DeviceSpec {
    src: PathBuf,
    dst: PathBuf,
    perms: String,
}

impl std::str::FromStr for DeviceSpec {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.splitn(3, ':').collect();
        let src = std::fs::canonicalize(parts[0])
            .with_context(|| format!("Device path '{}' not found", parts[0]))?;
        let dst = if parts.len() > 1 && parts[1].starts_with('/') {
            PathBuf::from(parts[1])
        } else {
            src.clone()
        };
        let perms = if parts.len() > 2 {
            parts[2].to_string()
        } else if parts.len() > 1 && !parts[1].starts_with('/') {
            parts[1].to_string()
        } else {
            "rwm".into()
        };
        Ok(DeviceSpec { src, dst, perms })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct VolumeSpec {
    host: PathBuf,
    container: PathBuf,
    read_only: bool,
}

impl std::str::FromStr for VolumeSpec {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.splitn(3, ':').collect();
        ensure!(
            parts.len() >= 2,
            "Volume must be HOST:CONTAINER[:ro], got: {s}"
        );
        let container = PathBuf::from(parts[1]);
        ensure!(
            container.is_absolute(),
            "Container path must be absolute, got: {}",
            container.display()
        );
        Ok(VolumeSpec {
            host: PathBuf::from(parts[0]),
            container,
            read_only: parts.get(2).is_some_and(|o| *o == "ro"),
        })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct HostEntry {
    host: String,
    ip: String,
}

impl std::str::FromStr for HostEntry {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let (host, ip) = s
            .rsplit_once(':')
            .context(format!("--add-host must be HOST:IP, got '{s}'"))?;
        Ok(HostEntry {
            host: host.into(),
            ip: ip.into(),
        })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct PortSpec {
    host_port: u16,
    container_port: u16,
    protocol: String,
}

impl std::str::FromStr for PortSpec {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        ensure!(
            parts.len() == 2,
            "Port must be HOST_PORT:CONTAINER_PORT[/PROTO], got '{s}'"
        );
        let host_port: u16 = parts[0].parse().context("Parsing host port")?;
        let (container_str, protocol) = match parts[1].split_once('/') {
            Some((port, proto)) => (port, proto.to_string()),
            None => (parts[1], "tcp".into()),
        };
        let container_port: u16 = container_str.parse().context("Parsing container port")?;
        Ok(PortSpec {
            host_port,
            container_port,
            protocol,
        })
    }
}

impl std::fmt::Display for PortSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.host_port, self.container_port)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SecurityOpt {
    pub key: String,
    pub value: Option<String>,
}

impl SecurityOpt {
    #[allow(dead_code)]
    pub fn is_true(&self) -> bool {
        self.value
            .as_deref()
            .is_none_or(|v| matches!(v, "true" | "1" | "yes"))
    }

    pub fn is_false(&self) -> bool {
        self.value
            .as_deref()
            .is_some_and(|v| matches!(v, "false" | "0" | "no"))
    }
}

impl std::str::FromStr for SecurityOpt {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        if let Some((key, value)) = s.split_once('=').or_else(|| s.split_once(':')) {
            Ok(SecurityOpt {
                key: key.into(),
                value: Some(value.into()),
            })
        } else {
            Ok(SecurityOpt {
                key: s.into(),
                value: None,
            })
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum NetworkMode {
    Host,
    Pasta,
    Bridge,
    Private,
}

impl std::str::FromStr for NetworkMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "host" => Ok(Self::Host),
            "pasta" => Ok(Self::Pasta),
            "bridge" => Ok(Self::Bridge),
            "private" => Ok(Self::Private),
            _ => anyhow::bail!("Unknown network mode '{s}', expected host|pasta|bridge|private"),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) enum SeccompPolicy {
    #[default]
    Default,
    Image,
}

impl std::str::FromStr for SeccompPolicy {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "default" => Ok(Self::Default),
            "image" => Ok(Self::Image),
            _ => anyhow::bail!("Unknown seccomp policy '{s}', expected default|image"),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) enum SystemdMode {
    #[default]
    Auto,
    Always,
    Off,
}

impl std::str::FromStr for SystemdMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "true" => Ok(Self::Auto),
            "always" => Ok(Self::Always),
            "false" => Ok(Self::Off),
            _ => anyhow::bail!("Unknown systemd mode '{s}', expected true|false|always"),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct UserSpec {
    uid: u32,
    gid: u32,
}

impl std::str::FromStr for UserSpec {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        if s.is_empty() {
            return Ok(UserSpec { uid: 0, gid: 0 });
        }
        let parts: Vec<&str> = s.splitn(2, ':').collect();
        let uid = parts[0].parse::<u32>().with_context(|| {
            format!(
                "Non-numeric user '{}' — only numeric UIDs are supported",
                parts[0]
            )
        })?;
        let gid = if let Some(g) = parts.get(1) {
            g.parse::<u32>().with_context(|| {
                format!("Non-numeric group '{g}' — only numeric GIDs are supported")
            })?
        } else {
            uid
        };
        Ok(UserSpec { uid, gid })
    }
}

/// Minimal container runner using composefs images and crun.
#[derive(Debug, Parser)]
#[clap(name = "cfsrun")]
pub(crate) struct Cli {
    /// Path to the composefs repository (default: /sysroot/composefs for root,
    /// ~/.var/lib/composefs for rootless)
    #[clap(long)]
    repo: Option<PathBuf>,

    /// Mount the rootfs read-only
    #[clap(long)]
    read_only: bool,

    /// When --read-only is set, mount tmpfs on /dev/shm, /run, /tmp, /var/tmp
    #[clap(long, default_value = "true", value_parser = clap::builder::BoolishValueParser::new())]
    read_only_tmpfs: bool,

    /// Persistent overlay directory (upper/ and work/ are created inside it)
    #[clap(long)]
    overlay_dir: Option<PathBuf>,

    /// Bind mount a host directory into the container (-v HOST:CONTAINER[:ro])
    #[clap(short = 'v', long = "volume", value_parser = clap::value_parser!(VolumeSpec))]
    volumes: Vec<VolumeSpec>,

    /// Allocate a pseudo-TTY
    #[clap(short = 't', long)]
    tty: bool,

    /// Accepted for compatibility, ignored
    #[clap(short = 'i', long, hide = true)]
    interactive: bool,

    /// Disable the default init process (catatonit) as PID 1
    #[clap(long)]
    no_init: bool,

    /// Add a host device to the container (HOST_PATH[:CONTAINER_PATH[:PERMISSIONS]])
    #[clap(long, value_parser = clap::value_parser!(DeviceSpec))]
    device: Vec<DeviceSpec>,

    /// Give extended privileges to the container (all caps, no seccomp, device access)
    #[clap(long)]
    privileged: bool,

    /// Add a Linux capability (e.g. SYS_ADMIN, NET_RAW, or ALL)
    #[clap(long)]
    cap_add: Vec<String>,

    /// Drop a Linux capability (e.g. NET_RAW, or ALL)
    #[clap(long)]
    cap_drop: Vec<String>,

    /// Set environment variables (KEY=VALUE)
    #[clap(short = 'e', long = "env")]
    envs: Vec<String>,

    /// Unset environment variables from the image config
    #[clap(long)]
    unsetenv: Vec<String>,

    /// Override the user (uid, uid:gid)
    #[clap(short = 'u', long, value_parser = clap::value_parser!(UserSpec))]
    user: Option<UserSpec>,

    /// Override the working directory
    #[clap(short = 'w', long = "workdir")]
    workdir_override: Option<String>,

    /// Expose a port (currently informational only, no network setup)
    #[clap(long)]
    expose: Vec<String>,

    /// Publish a port (HOST_PORT:CONTAINER_PORT[/PROTO])
    #[clap(short = 'p', long, value_parser = clap::value_parser!(PortSpec))]
    publish: Vec<PortSpec>,

    /// Set the container hostname
    #[clap(long)]
    hostname: Option<String>,

    /// Add a custom host-to-IP mapping (host:ip)
    #[clap(long, value_parser = clap::value_parser!(HostEntry))]
    add_host: Vec<HostEntry>,

    /// Set custom DNS servers
    #[clap(long)]
    dns: Vec<String>,

    /// Set custom DNS search domains
    #[clap(long)]
    dns_search: Vec<String>,

    /// Set custom DNS options
    #[clap(long)]
    dns_option: Vec<String>,

    /// Security options (seccomp=PROFILE|unconfined, no-new-privileges, label=...)
    #[clap(long, value_parser = clap::value_parser!(SecurityOpt))]
    security_opt: Vec<SecurityOpt>,

    /// Seccomp policy: default (use profile file) or image (from image labels)
    #[clap(long, default_value = "default", value_parser = clap::value_parser!(SeccompPolicy))]
    seccomp_policy: SeccompPolicy,

    /// Network mode: host, pasta (rootless default), bridge (rootful default), or private
    #[clap(long, value_parser = clap::value_parser!(NetworkMode))]
    network: Option<NetworkMode>,

    /// Systemd container mode: true (auto-detect), false, or always
    #[clap(long, default_value = "true", value_parser = clap::value_parser!(SystemdMode))]
    systemd: SystemdMode,

    /// Use a host directory as the container rootfs instead of a composefs image
    #[clap(long, conflicts_with = "image")]
    rootfs: Option<PathBuf>,

    /// OCI image ref name or @sha256:... digest
    #[clap(required_unless_present = "rootfs")]
    image: Option<String>,

    /// Command to run (overrides image entrypoint+cmd)
    #[clap(last = true)]
    cmd: Vec<String>,
}

fn main() -> Result<()> {
    clap_complete::CompleteEnv::with_factory(Cli::command).complete();

    match std::env::args().nth(1).as_deref() {
        Some("--internal-cleanup") => return run::cleanup(),
        Some("--internal-fuse-serve") => {
            let args = fuse::FuseServeArgs::parse_from(
                std::iter::once("fuse-serve".into()).chain(std::env::args().skip(2)),
            );
            return fuse::run_server(&args);
        }
        _ => {}
    }

    let cli = Cli::parse();

    let rootless = !rustix::process::geteuid().is_root();
    let container_id = format!("composefs-{}", std::process::id());

    let repo_path = match cli.repo.clone() {
        Some(path) => path,
        None if rootless => composefs::repository::user_path()?,
        None => composefs::repository::system_path(),
    };

    let image = if let Some(ref rootfs) = cli.rootfs {
        ensure!(
            rootfs.is_dir(),
            "--rootfs path '{}' is not a directory",
            rootfs.display()
        );
        ResolvedImage {
            oci_config: oci_spec::image::ImageConfiguration::default(),
            erofs_hex: None,
        }
    } else {
        let repo = ResolvedRepo::open(&repo_path)?;
        repo.resolve_image(cli.image.as_deref().context("No image specified")?)?
    };

    let container_dir = PathBuf::from(format!("/var/tmp/cfsrun-{container_id}"));
    let overlay_dir = cli
        .overlay_dir
        .clone()
        .unwrap_or_else(|| container_dir.clone());

    std::fs::create_dir_all(&container_dir)
        .with_context(|| format!("Creating {}", container_dir.display()))?;
    rustix::fs::chmod(&container_dir, Mode::from_raw_mode(0o700))
        .with_context(|| format!("Setting permissions on {}", container_dir.display()))?;

    let result = run::run(
        rootless,
        &cli,
        &container_id,
        &container_dir,
        &overlay_dir,
        &repo_path,
        &image,
    );

    if result.is_err() {
        let _ = std::fs::remove_dir_all(&container_dir);
    }

    result
}

/// Wraps the algorithm-specific repo so run() don't need generics.
pub(crate) enum ResolvedRepo {
    Sha256(Repository<Sha256HashValue>),
    Sha512(Repository<Sha512HashValue>),
}

impl ResolvedRepo {
    fn open(repo_path: &std::path::Path) -> Result<Self> {
        let repo_fd = rustix::fs::open(
            repo_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| format!("Opening repository at {}", repo_path.display()))?;

        let algorithm = read_repo_algorithm(&repo_fd)?
            .context("No meta.json found — is this a composefs repository?")?;

        match algorithm {
            composefs::fsverity::Algorithm::Sha256 { .. } => Ok(Self::Sha256(
                Repository::open_path(CWD, repo_path).context("Opening composefs repository")?,
            )),
            composefs::fsverity::Algorithm::Sha512 { .. } => Ok(Self::Sha512(
                Repository::open_path(CWD, repo_path).context("Opening composefs repository")?,
            )),
        }
    }

    fn resolve_image(&self, image: &str) -> Result<ResolvedImage> {
        match self {
            Self::Sha256(repo) => resolve_image_typed(repo, image),
            Self::Sha512(repo) => resolve_image_typed(repo, image),
        }
    }

    pub(crate) fn mount_with_options(
        &self,
        erofs_hex: &str,
        options: &composefs::mount::MountOptions,
    ) -> Result<rustix::fd::OwnedFd> {
        match self {
            Self::Sha256(repo) => repo
                .mount_with_options(erofs_hex, options)
                .context("Creating composefs mount"),
            Self::Sha512(repo) => repo
                .mount_with_options(erofs_hex, options)
                .context("Creating composefs mount"),
        }
    }
}

pub(crate) struct ResolvedImage {
    pub(crate) oci_config: oci_spec::image::ImageConfiguration,
    pub(crate) erofs_hex: Option<String>,
}

fn resolve_image_typed<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    image: &str,
) -> Result<ResolvedImage> {
    let img = if let Some(digest_str) = image.strip_prefix('@') {
        let digest: OciDigest = digest_str.parse().context("Parsing manifest digest")?;
        composefs_oci::OciImage::open(repo, &digest, None)?
    } else {
        composefs_oci::OciImage::open_ref(repo, image)?
    };

    let erofs_id = img
        .image_ref(composefs::erofs::format::FormatVersion::default())
        .context("Image has no EROFS — try re-pulling")?;

    let config = composefs_oci::open_config(repo, img.config_digest(), Some(img.config_verity()))?;

    Ok(ResolvedImage {
        oci_config: config.config,
        erofs_hex: Some(erofs_id.to_hex()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_device_spec_basic() {
        let d: DeviceSpec = "/dev/null".parse().unwrap();
        assert_eq!(d.src, PathBuf::from("/dev/null"));
        assert_eq!(d.dst, PathBuf::from("/dev/null"));
        assert_eq!(d.perms, "rwm");
    }

    #[test]
    fn parse_device_spec_with_dest() {
        let d: DeviceSpec = "/dev/null:/dev/zero".parse().unwrap();
        assert_eq!(d.dst, PathBuf::from("/dev/zero"));
        assert_eq!(d.perms, "rwm");
    }

    #[test]
    fn parse_device_spec_with_perms() {
        let d: DeviceSpec = "/dev/null:/dev/zero:r".parse().unwrap();
        assert_eq!(d.perms, "r");
    }

    #[test]
    fn parse_device_spec_perms_only() {
        let d: DeviceSpec = "/dev/null:rw".parse().unwrap();
        assert_eq!(d.dst, PathBuf::from("/dev/null"));
        assert_eq!(d.perms, "rw");
    }

    #[test]
    fn parse_device_spec_bad_path() {
        assert!("/dev/nonexistent_device_xyz".parse::<DeviceSpec>().is_err());
    }

    #[test]
    fn parse_volume_spec_basic() {
        let v: VolumeSpec = "/tmp:/mnt".parse().unwrap();
        assert_eq!(v.host, PathBuf::from("/tmp"));
        assert_eq!(v.container, PathBuf::from("/mnt"));
        assert!(!v.read_only);
    }

    #[test]
    fn parse_volume_spec_ro() {
        let v: VolumeSpec = "/tmp:/mnt:ro".parse().unwrap();
        assert!(v.read_only);
    }

    #[test]
    fn parse_volume_spec_relative_container_fails() {
        assert!("relative:relative".parse::<VolumeSpec>().is_err());
    }

    #[test]
    fn parse_volume_spec_missing_container_fails() {
        assert!("/tmp".parse::<VolumeSpec>().is_err());
    }

    #[test]
    fn parse_host_entry() {
        let h: HostEntry = "mydb:10.0.0.5".parse().unwrap();
        assert_eq!(h.host, "mydb");
        assert_eq!(h.ip, "10.0.0.5");
    }

    #[test]
    fn parse_host_entry_no_colon_fails() {
        assert!("nocolon".parse::<HostEntry>().is_err());
    }

    #[test]
    fn parse_port_spec_tcp() {
        let p: PortSpec = "8080:80".parse().unwrap();
        assert_eq!(p.host_port, 8080);
        assert_eq!(p.container_port, 80);
        assert_eq!(p.protocol, "tcp");
    }

    #[test]
    fn parse_port_spec_udp() {
        let p: PortSpec = "53:53/udp".parse().unwrap();
        assert_eq!(p.protocol, "udp");
    }

    #[test]
    fn parse_port_spec_bad_format() {
        assert!("not-a-port".parse::<PortSpec>().is_err());
    }

    #[test]
    fn parse_security_opt_bare() {
        let s: SecurityOpt = "no-new-privileges".parse().unwrap();
        assert_eq!(s.key, "no-new-privileges");
        assert!(s.value.is_none());
        assert!(s.is_true());
        assert!(!s.is_false());
    }

    #[test]
    fn parse_security_opt_equals() {
        let s: SecurityOpt = "seccomp=unconfined".parse().unwrap();
        assert_eq!(s.key, "seccomp");
        assert_eq!(s.value.as_deref(), Some("unconfined"));
    }

    #[test]
    fn parse_security_opt_colon() {
        let s: SecurityOpt = "label:disable".parse().unwrap();
        assert_eq!(s.key, "label");
        assert_eq!(s.value.as_deref(), Some("disable"));
    }

    #[test]
    fn security_opt_bool_values() {
        assert!("k=true".parse::<SecurityOpt>().unwrap().is_true());
        assert!("k=1".parse::<SecurityOpt>().unwrap().is_true());
        assert!("k=yes".parse::<SecurityOpt>().unwrap().is_true());
        assert!("k=false".parse::<SecurityOpt>().unwrap().is_false());
        assert!("k=0".parse::<SecurityOpt>().unwrap().is_false());
        assert!("k=no".parse::<SecurityOpt>().unwrap().is_false());
        assert!(!"k=false".parse::<SecurityOpt>().unwrap().is_true());
    }

    #[test]
    fn parse_network_modes() {
        assert_eq!("host".parse::<NetworkMode>().unwrap(), NetworkMode::Host);
        assert_eq!("pasta".parse::<NetworkMode>().unwrap(), NetworkMode::Pasta);
        assert_eq!(
            "bridge".parse::<NetworkMode>().unwrap(),
            NetworkMode::Bridge
        );
        assert_eq!(
            "private".parse::<NetworkMode>().unwrap(),
            NetworkMode::Private
        );
        assert!("bogus".parse::<NetworkMode>().is_err());
    }

    #[test]
    fn parse_user_spec() {
        let u: UserSpec = "1000".parse().unwrap();
        assert_eq!((u.uid, u.gid), (1000, 1000));

        let u: UserSpec = "1000:2000".parse().unwrap();
        assert_eq!((u.uid, u.gid), (1000, 2000));

        let u: UserSpec = "".parse().unwrap();
        assert_eq!((u.uid, u.gid), (0, 0));

        assert!("abc".parse::<UserSpec>().is_err());
        assert!("1000:abc".parse::<UserSpec>().is_err());
    }
}
