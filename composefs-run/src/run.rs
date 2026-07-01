use std::fs;
use std::io::IsTerminal;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, ensure};
use clap::Parser;
use composefs::mount::MountOptions;
use oci_spec::runtime::{
    Capability, HookBuilder, HooksBuilder, LinuxBuilder, LinuxCapabilitiesBuilder, LinuxNamespace,
    LinuxNamespaceType, MountBuilder, ProcessBuilder, RootBuilder, Spec, UserBuilder,
};
use rustix::fs::{CWD, Mode, OFlags};
use rustix::mount::{
    FsMountFlags, FsOpenFlags, MountAttrFlags, MountPropagationFlags, fsconfig_create, fsmount,
    fsopen,
};

use crate::{
    CleanupArgs, Cli, HostEntry, NetworkMode, PortSpec, ResolvedImage, SeccompPolicy, SystemdMode,
    UserSpec, fuse, netavark, seccomp, selinux, userns,
};

pub fn run(
    rootless: bool,
    cli: &Cli,
    container_id: &str,
    container_dir: &Path,
    overlay_dir: &Path,
    repo_path: &Path,
    image: &ResolvedImage,
) -> Result<()> {
    if rootless {
        userns::setup().context("Setting up user namespace")?;
    } else {
        unsafe { rustix::thread::unshare_unsafe(rustix::thread::UnshareFlags::NEWNS) }
            .context("unshare(CLONE_NEWNS) — are you running as root?")?;
    }

    rustix::mount::mount_change(
        "/",
        MountPropagationFlags::REC | MountPropagationFlags::PRIVATE,
    )
    .context("Making / recursively private")?;

    let bundle_tmpfs = create_detached_tmpfs().context("Creating detached tmpfs for bundle")?;
    rustix::fs::mkdirat(&bundle_tmpfs, "rootfs", Mode::from_raw_mode(0o755))?;

    let bundle_dir = container_dir.join("bundle");
    fs::create_dir(&bundle_dir)?;

    composefs::mount::mount_at(bundle_tmpfs, CWD, &bundle_dir).context("Attaching bundle tmpfs")?;
    let rootfs_dir = bundle_dir.join("rootfs");

    // ── Rootfs ──────────────────────────────────────────────────────

    if let Some(ref rootfs) = cli.rootfs {
        // --rootfs: skip composefs, use the directory directly
        mount_rootfs_from_path(rootfs, &rootfs_dir, overlay_dir, cli.read_only, rootless)?;
    } else if rootless {
        mount_rootfs_with_fuse(repo_path, image, &rootfs_dir, overlay_dir, cli.read_only)?;
    } else {
        mount_rootfs_with_erofs(repo_path, image, &rootfs_dir, overlay_dir, cli.read_only)?;
    }

    // ── Networking ──────────────────────────────────────────────────────

    let default_network = if rootless {
        NetworkMode::Pasta
    } else {
        NetworkMode::Bridge
    };
    let network = cli.network.clone().unwrap_or(default_network);

    if !rootless {
        ensure!(
            network != NetworkMode::Pasta,
            "--network pasta is only supported in rootless mode"
        );
    } else {
        ensure!(
            network != NetworkMode::Bridge,
            "--network bridge is only supported in rootful mode"
        );
    }

    let mut container_ip = None;
    let mut pasta_pid = None;
    let netns_path = if network != NetworkMode::Host {
        Some(setup_netns(&bundle_dir)?)
    } else {
        None
    };

    if network == NetworkMode::Bridge
        && let Some(ref ns) = netns_path
    {
        container_ip = Some(
            netavark::setup(ns, container_id, &cli.publish).context("Setting up bridge network")?,
        );
    } else if network == NetworkMode::Pasta
        && let Some(ref ns) = netns_path
    {
        pasta_pid = Some(setup_pasta(
            ns,
            &bundle_dir.join("pasta.pid"),
            &cli.publish,
        )?);
    }

    // ── OCI spec + exec ────────────────────────────────────────────────

    let default_config = oci_spec::image::Config::default();
    let oci_config = image
        .oci_config
        .config()
        .as_ref()
        .unwrap_or(&default_config);

    let tty = if cli.tty && !std::io::stdin().is_terminal() {
        eprintln!("warning: -t specified but stdin is not a terminal, ignoring");
        false
    } else {
        cli.tty
    };

    let spec = build_runtime_spec(
        cli,
        oci_config,
        container_id,
        container_dir,
        &bundle_dir,
        tty,
        rootless,
        &network,
        netns_path.as_deref(),
        container_ip,
        pasta_pid,
    )?;

    let config_json = serde_json::to_string_pretty(&spec)?;
    fs::write(bundle_dir.join("config.json"), &config_json)?;

    let err = Command::new("crun")
        .arg("run")
        .arg("--bundle")
        .arg(bundle_dir)
        .arg(container_id)
        .exec();
    Err(err).context("Failed to exec crun")
}

/// OCI poststop hook: unmount and remove the container state directory.
pub fn cleanup() -> Result<()> {
    let args =
        CleanupArgs::parse_from(std::iter::once("cleanup".into()).chain(std::env::args().skip(2)));
    if let Some(dir) = &args.container_dir {
        ensure!(
            dir.parent() == Some(Path::new("/var/tmp"))
                && dir
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("cfsrun-")),
            "--container-dir must be under /var/tmp/cfsrun-*"
        );
        let rootfs = dir.join("bundle/rootfs");
        let _ = rustix::mount::unmount(&rootfs, rustix::mount::UnmountFlags::DETACH);
        if let Some(pid) = args.pasta_pid {
            unsafe { libc::kill(pid, libc::SIGTERM) };
        }
        let netns = dir.join("bundle/netns");
        if netns.exists() {
            if let (Some(id), Some(ip)) = (&args.container_id, args.container_ip) {
                let _ = netavark::teardown(&netns, id, ip);
            }
            let _ = rustix::mount::unmount(&netns, rustix::mount::UnmountFlags::DETACH);
        }
        let bundle = dir.join("bundle");
        let _ = rustix::mount::unmount(&bundle, rustix::mount::UnmountFlags::DETACH);
        let _ = fs::remove_dir_all(dir);
    }
    Ok(())
}

/// Mount a composefs image via FUSE (rootless).
fn mount_rootfs_with_fuse(
    repo_path: &Path,
    image: &ResolvedImage,
    rootfs_dir: &Path,
    overlay_dir: &Path,
    read_only: bool,
) -> Result<()> {
    let dev_fuse = composefs_fuse::open_fuse().context("Opening /dev/fuse")?;
    let fuse_fd_num = dev_fuse.as_raw_fd();

    let fuse_options = composefs_fuse::FuseMountOptions::default();
    let fuse_mnt =
        composefs_fuse::mount_fuse(&dev_fuse, &fuse_options).context("Creating FUSE mount")?;

    let erofs_hex = image.erofs_hex.as_deref().context("No composefs image")?;
    fuse::spawn_server(repo_path, erofs_hex, fuse_fd_num)?;

    let basedir = rustix::fs::open(
        repo_path.join("objects"),
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .context("Opening repository objects directory")?;

    let mut overlay_options = composefs_fuse::OverlayMountOptions::default();

    if !read_only {
        let upper = overlay_dir.join("upper");
        let work = overlay_dir.join("work");
        fs::create_dir(&upper).with_context(|| format!("Creating {}", upper.display()))?;
        fs::create_dir(&work).with_context(|| format!("Creating {}", work.display()))?;

        let upper_fd = rustix::fs::open(
            &upper,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let work_fd = rustix::fs::open(
            &work,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        overlay_options.set_overlay(upper_fd, work_fd);
        overlay_options.set_read_write(true);
    }

    let mount_fd = composefs_fuse::mount_fuse_overlay(fuse_mnt, basedir, &overlay_options)
        .context("Creating overlay mount")?;

    composefs::mount::mount_at(mount_fd, CWD, rootfs_dir)
        .context("Attaching overlay mount at rootfs")?;
    Ok(())
}

/// Mount a composefs image via kernel erofs (rootful).
fn mount_rootfs_with_erofs(
    repo_path: &Path,
    image: &ResolvedImage,
    rootfs_dir: &Path,
    overlay_dir: &Path,
    read_only: bool,
) -> Result<()> {
    let repo = crate::ResolvedRepo::open(repo_path)?;

    let mut mount_options = MountOptions::default();
    if !read_only {
        let upper = overlay_dir.join("upper");
        let work = overlay_dir.join("work");
        fs::create_dir(&upper).with_context(|| format!("Creating {}", upper.display()))?;
        fs::create_dir(&work).with_context(|| format!("Creating {}", work.display()))?;

        let upper_fd = rustix::fs::open(
            &upper,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let work_fd = rustix::fs::open(
            &work,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        mount_options.set_overlay(upper_fd, work_fd);
        mount_options.set_read_write(true);
    }

    let erofs_hex = image.erofs_hex.as_deref().context("No composefs image")?;
    let mount_fd = repo.mount_with_options(erofs_hex, &mount_options)?;
    composefs::mount::mount_at(mount_fd, CWD, rootfs_dir)
        .context("Attaching composefs mount at rootfs")?;
    Ok(())
}

/// Mount a host directory as the container rootfs.
fn mount_rootfs_from_path(
    rootfs: &Path,
    target: &Path,
    overlay_dir: &Path,
    read_only: bool,
    userxattr: bool,
) -> Result<()> {
    if read_only {
        rustix::mount::mount_bind(rootfs, target)
            .with_context(|| format!("bind mount {} at {}", rootfs.display(), target.display()))?;
        // Remount to apply read-only (bind mount ignores flags on first call)
        rustix::mount::mount_remount(target, rustix::mount::MountFlags::RDONLY, "")
            .context("remount read-only")?;
    } else {
        mount_overlay(
            &rootfs.display().to_string(),
            target,
            overlay_dir,
            userxattr,
        )?;
    }
    Ok(())
}

/// Mount an overlay filesystem with the given lower directory path.
fn mount_overlay(lowerdir: &str, target: &Path, overlay_dir: &Path, userxattr: bool) -> Result<()> {
    let upper = overlay_dir.join("upper");
    let work = overlay_dir.join("work");
    fs::create_dir(&upper)
        .or_else(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                Ok(())
            } else {
                Err(e)
            }
        })
        .with_context(|| format!("Creating {}", upper.display()))?;
    fs::create_dir(&work)
        .or_else(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                Ok(())
            } else {
                Err(e)
            }
        })
        .with_context(|| format!("Creating {}", work.display()))?;

    let overlay = composefs::mount::FsHandle::open("overlay").context("fsopen(overlay)")?;
    rustix::mount::fsconfig_set_string(overlay.as_fd(), "lowerdir", lowerdir)?;
    rustix::mount::fsconfig_set_string(overlay.as_fd(), "upperdir", upper.display().to_string())?;
    rustix::mount::fsconfig_set_string(overlay.as_fd(), "workdir", work.display().to_string())?;
    if userxattr {
        rustix::mount::fsconfig_set_flag(overlay.as_fd(), "userxattr")?;
    }
    rustix::mount::fsconfig_create(overlay.as_fd())?;
    let overlay_fd = rustix::mount::fsmount(
        overlay.as_fd(),
        FsMountFlags::FSMOUNT_CLOEXEC,
        MountAttrFlags::empty(),
    )?;
    composefs::mount::mount_at(overlay_fd, CWD, target).context("Attaching overlay mount")?;
    Ok(())
}

/// Create a new network namespace and bind mount it at `bundle_dir/netns`.
fn setup_netns(bundle_dir: &Path) -> Result<PathBuf> {
    let netns_path = bundle_dir.join("netns");
    fs::write(&netns_path, "")?;

    match unsafe { libc::fork() } {
        -1 => anyhow::bail!("fork failed: {}", std::io::Error::last_os_error()),
        0 => {
            if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
                std::process::exit(1);
            }
            let source = std::ffi::CString::new("/proc/self/ns/net").unwrap();
            let target = std::ffi::CString::new(netns_path.as_os_str().as_encoded_bytes()).unwrap();
            let ret = unsafe {
                libc::mount(
                    source.as_ptr(),
                    target.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND,
                    std::ptr::null(),
                )
            };
            std::process::exit(if ret == 0 { 0 } else { 1 });
        }
        child_pid => {
            let mut status = 0i32;
            unsafe { libc::waitpid(child_pid, &mut status, 0) };
            ensure!(
                libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
                "Failed to create network namespace"
            );
        }
    }

    Ok(netns_path)
}

const CATATONIT_PATHS: &[&str] = &[
    "/usr/libexec/catatonit/catatonit",
    "/usr/libexec/podman/catatonit",
    "/usr/local/libexec/podman/catatonit",
    "/usr/local/lib/podman/catatonit",
    "/usr/libexec/catatonit",
    "/usr/bin/catatonit",
];

fn find_catatonit() -> Result<PathBuf> {
    for path in CATATONIT_PATHS {
        let p = Path::new(path);
        if p.exists() {
            return Ok(p.to_owned());
        }
    }
    anyhow::bail!("catatonit not found")
}

fn setup_pasta(netns_path: &Path, pid_file: &Path, publish: &[PortSpec]) -> Result<i32> {
    let mut pasta_cmd = Command::new("pasta");
    pasta_cmd
        .arg("--config-net")
        .arg("--dns-forward")
        .arg("169.254.1.1")
        .arg("--netns")
        .arg(netns_path)
        .arg("--pid")
        .arg(pid_file)
        .arg("--quiet");

    if publish.is_empty() {
        pasta_cmd.arg("-t").arg("none");
        pasta_cmd.arg("-u").arg("none");
    } else {
        for p in publish {
            pasta_cmd.arg("-t").arg(p.to_string());
        }
    }

    let output = pasta_cmd
        .output()
        .context("Running pasta — is it installed?")?;
    ensure!(
        output.status.success(),
        "pasta failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let pid_str = fs::read_to_string(pid_file).context("Reading pasta PID file")?;
    pid_str.trim().parse::<i32>().context("Parsing pasta PID")
}

fn create_detached_tmpfs() -> Result<rustix::fd::OwnedFd> {
    let fs_fd = fsopen("tmpfs", FsOpenFlags::FSOPEN_CLOEXEC).context("fsopen(tmpfs)")?;
    fsconfig_create(&fs_fd).context("fsconfig_create for tmpfs")?;
    let mnt_fd = fsmount(
        &fs_fd,
        FsMountFlags::FSMOUNT_CLOEXEC,
        MountAttrFlags::empty(),
    )
    .context("fsmount for tmpfs")?;
    Ok(mnt_fd)
}

fn generate_etc_config(
    bundle_dir: &Path,
    hostname: &str,
    add_host: &[HostEntry],
    dns: &[String],
    dns_search: &[String],
    dns_option: &[String],
) -> Result<Vec<oci_spec::runtime::Mount>> {
    // /etc/hostname
    let hostname_path = bundle_dir.join("hostname");
    fs::write(&hostname_path, format!("{hostname}\n"))?;

    // /etc/hosts
    let hosts_path = bundle_dir.join("hosts");
    let mut hosts = String::new();
    for entry in add_host {
        hosts.push_str(&format!("{}\t{}\n", entry.ip, entry.host));
    }
    hosts.push_str("127.0.0.1\tlocalhost\n");
    hosts.push_str("::1\t\tlocalhost\n");
    hosts.push_str(&format!("127.0.0.1\t{hostname}\n"));
    fs::write(&hosts_path, &hosts)?;

    // /etc/resolv.conf
    let resolv_path = bundle_dir.join("resolv.conf");
    if !dns.is_empty() || !dns_search.is_empty() || !dns_option.is_empty() {
        let mut resolv = String::new();
        let base = read_host_resolv_conf();
        if dns.is_empty() {
            for line in base.lines() {
                if line.starts_with("nameserver ") {
                    resolv.push_str(line);
                    resolv.push('\n');
                }
            }
        } else {
            for server in dns {
                resolv.push_str(&format!("nameserver {server}\n"));
            }
        }
        if dns_search.is_empty() {
            for line in base.lines() {
                if line.starts_with("search ") {
                    resolv.push_str(line);
                    resolv.push('\n');
                }
            }
        } else {
            resolv.push_str(&format!("search {}\n", dns_search.join(" ")));
        }
        if dns_option.is_empty() {
            for line in base.lines() {
                if line.starts_with("options ") {
                    resolv.push_str(line);
                    resolv.push('\n');
                }
            }
        } else {
            resolv.push_str(&format!("options {}\n", dns_option.join(" ")));
        }
        fs::write(&resolv_path, &resolv)?;
    } else {
        let resolv = read_host_resolv_conf();
        fs::write(&resolv_path, &resolv)?;
    }

    let bind_opts = vec!["bind".into(), "rprivate".into()];
    let mounts = vec![
        MountBuilder::default()
            .destination(PathBuf::from("/etc/hostname"))
            .typ("bind")
            .source(hostname_path)
            .options(bind_opts.clone())
            .build()?,
        MountBuilder::default()
            .destination(PathBuf::from("/etc/hosts"))
            .typ("bind")
            .source(hosts_path)
            .options(bind_opts.clone())
            .build()?,
        MountBuilder::default()
            .destination(PathBuf::from("/etc/resolv.conf"))
            .typ("bind")
            .source(resolv_path)
            .options(bind_opts)
            .build()?,
    ];

    Ok(mounts)
}

/// Read the host's resolv.conf, following through stub resolvers to the real config.
fn read_host_resolv_conf() -> String {
    let content = fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    // systemd-resolved stub: nameserver 127.0.0.53
    if content.lines().any(|l| l.trim() == "nameserver 127.0.0.53")
        && let Ok(real) = fs::read_to_string("/run/systemd/resolve/resolv.conf")
    {
        return real;
    }
    // NetworkManager stub: nameserver 127.0.0.1
    if content.lines().any(|l| l.trim() == "nameserver 127.0.0.1")
        && let Ok(real) = fs::read_to_string("/run/NetworkManager/no-stub-resolv.conf")
    {
        return real;
    }
    content
}

fn is_systemd_command(args: &[String]) -> bool {
    const SYSTEMD_COMMANDS: &[&str] = &[
        "systemd",
        "/usr/sbin/init",
        "/sbin/init",
        "/usr/local/sbin/init",
    ];
    args.first()
        .map(|cmd| SYSTEMD_COMMANDS.iter().any(|s| cmd.ends_with(s)))
        .unwrap_or(false)
}

#[allow(clippy::too_many_arguments)]
fn build_runtime_spec(
    cli: &Cli,
    oci_config: &oci_spec::image::Config,
    container_id: &str,
    container_dir: &Path,
    bundle_dir: &Path,
    tty: bool,
    rootless: bool,
    network: &NetworkMode,
    netns_path: Option<&Path>,
    container_ip: Option<std::net::IpAddr>,
    pasta_pid: Option<i32>,
) -> Result<Spec> {
    use std::collections::HashSet;

    // ── Resolve image + CLI into effective values ───────────────────────

    let mut args = if cli.cmd.is_empty() {
        let mut args = oci_config.entrypoint().clone().unwrap_or_default();
        args.extend(oci_config.cmd().clone().unwrap_or_default());
        ensure!(
            !args.is_empty(),
            "No entrypoint or cmd in image config and no command specified"
        );
        args
    } else {
        cli.cmd.clone()
    };

    let mut env: Vec<String> = oci_config.env().clone().unwrap_or_else(|| {
        vec!["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into()]
    });
    env.push("container=oci".into());
    if cli.tty {
        env.push("TERM=xterm".into());
    }
    env.retain(|e| {
        let key = e.split('=').next().unwrap_or("");
        !cli.unsetenv.iter().any(|u| u == key)
    });
    for e in &cli.envs {
        let key = e.split('=').next().unwrap_or("");
        env.retain(|existing| existing.split('=').next().unwrap_or("") != key);
        env.push(e.clone());
    }

    let cwd = cli
        .workdir_override
        .clone()
        .or_else(|| oci_config.working_dir().clone())
        .unwrap_or_else(|| "/".into());

    let user = if let Some(ref u) = cli.user {
        u.clone()
    } else if let Some(u) = oci_config.user().as_deref() {
        u.parse().unwrap_or(UserSpec { uid: 0, gid: 0 })
    } else {
        UserSpec { uid: 0, gid: 0 }
    };

    let hostname = cli
        .hostname
        .clone()
        .unwrap_or_else(|| container_id[..container_id.len().min(12)].to_string());

    let systemd_mode = match cli.systemd {
        SystemdMode::Always => true,
        SystemdMode::Off => false,
        SystemdMode::Auto => is_systemd_command(&args),
    };

    let use_init = !cli.no_init && !systemd_mode;
    let init_path = if use_init {
        let path = find_catatonit().context("catatonit is required (use --no-init to disable)")?;
        args.insert(0, "/dev/init".into());
        args.insert(1, "--".into());
        Some(path)
    } else {
        None
    };

    let host_network = netns_path.is_none();

    // Capabilities: start from podman's default set (containers.conf),
    // apply --privileged, --cap-add, --cap-drop
    let mut capabilities: HashSet<Capability> = if cli.privileged {
        all_capabilities()
    } else {
        default_capabilities()
    };
    for cap_str in &cli.cap_add {
        if cap_str.eq_ignore_ascii_case("ALL") {
            capabilities = all_capabilities();
        } else {
            capabilities.insert(parse_capability(cap_str)?);
        }
    }
    for cap_str in &cli.cap_drop {
        if cap_str.eq_ignore_ascii_case("ALL") {
            capabilities.clear();
        } else {
            capabilities.remove(&parse_capability(cap_str)?);
        }
    }

    // Security options: parse --security-opt, then apply --privileged overrides
    let mut seccomp_profile: Option<seccomp::SeccompSource> =
        if cli.seccomp_policy == SeccompPolicy::Image {
            let json = oci_config
                .labels()
                .as_ref()
                .and_then(|l| l.get("io.containers.seccomp.profile").cloned());
            ensure!(
                json.is_some(),
                "No seccomp policy defined by image (missing io.containers.seccomp.profile label)"
            );
            Some(seccomp::SeccompSource::Inline(json.unwrap()))
        } else {
            Some(seccomp::SeccompSource::File(PathBuf::from(
                seccomp::DEFAULT_SECCOMP_PROFILE,
            )))
        };
    let mut no_new_privileges = !cli.privileged;
    let mut selinux_disabled = false;
    let mut selinux_nested = false;
    let mut selinux_label_opts: Vec<String> = Vec::new();

    for opt in &cli.security_opt {
        match opt.key.as_str() {
            "no-new-privileges" => no_new_privileges = !opt.is_false(),
            "seccomp" => match opt.value.as_deref() {
                Some("unconfined") => seccomp_profile = None,
                Some(path) => {
                    seccomp_profile = Some(seccomp::SeccompSource::File(PathBuf::from(path)))
                }
                None => {}
            },
            "label" => match opt.value.as_deref() {
                Some("disable") => selinux_disabled = true,
                Some("nested") => selinux_nested = true,
                Some(label_opt) => selinux_label_opts.push(label_opt.to_string()),
                None => {}
            },
            other => anyhow::bail!("Unsupported --security-opt: {other}"),
        }
    }

    // --privileged overrides: no seccomp, no masked/readonly paths, no selinux
    if cli.privileged {
        seccomp_profile = None;
        selinux_disabled = true;
    }

    let use_masked_paths = !cli.privileged;

    let (process_label, mount_label) = if selinux_disabled {
        (None, None)
    } else {
        selinux::container_labels(&selinux_label_opts)
    };

    // ── Phase 2: Build the spec ─────────────────────────────────────────

    let mut spec = Spec::default();

    // Root
    spec.set_root(Some(
        RootBuilder::default()
            .path("rootfs")
            .readonly(cli.read_only)
            .build()?,
    ));

    // Process
    let (uid, gid) = (user.uid, user.gid);
    if systemd_mode {
        env.push(format!(
            "container_uuid={}",
            &container_id[..container_id.len().min(32)]
        ));
    }

    let linux_caps = LinuxCapabilitiesBuilder::default()
        .bounding(capabilities.clone())
        .effective(capabilities.clone())
        .inheritable(capabilities.clone())
        .permitted(capabilities.clone())
        .ambient(capabilities.clone())
        .build()?;

    let mut process = ProcessBuilder::default()
        .args(args.clone())
        .env(env)
        .cwd(&cwd)
        .terminal(tty)
        .no_new_privileges(no_new_privileges)
        .user(UserBuilder::default().uid(uid).gid(gid).build()?)
        .capabilities(linux_caps)
        .build()?;
    if let Some(ref label) = process_label {
        process.set_selinux_label(Some(label.clone()));
    }
    spec.set_process(Some(process));

    // Linux: namespaces, masked/readonly paths, seccomp
    if let Some(linux) = spec.linux().as_ref() {
        let mut namespaces: Vec<LinuxNamespace> = linux
            .namespaces()
            .as_ref()
            .map(|ns| {
                ns.iter()
                    .filter(|n| !(host_network && n.typ() == LinuxNamespaceType::Network))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();

        // If we have an external netns (pasta), set its path on the network namespace
        if let Some(path) = netns_path {
            for ns in &mut namespaces {
                if ns.typ() == LinuxNamespaceType::Network {
                    ns.set_path(Some(path.to_path_buf()));
                }
            }
        }

        let mut masked = if use_masked_paths {
            linux.masked_paths().clone().unwrap_or_default()
        } else {
            vec![]
        };
        if selinux_nested {
            masked.retain(|p| p != "/sys/fs/selinux" && p != "/proc");
        }

        let mut linux_spec = LinuxBuilder::default()
            .namespaces(namespaces)
            .masked_paths(masked)
            .readonly_paths(if use_masked_paths {
                linux.readonly_paths().clone().unwrap_or_default()
            } else {
                vec![]
            })
            .build()?;

        if !rootless {
            linux_spec.set_cgroups_path(Some(PathBuf::from(format!("cfsrun/{container_id}"))));
        }
        if let Some(ref label) = mount_label {
            linux_spec.set_mount_label(Some(label.clone()));
        }

        spec.set_linux(Some(linux_spec));
    }

    // Seccomp: load and apply the resolved profile
    let cap_strings: HashSet<String> = capabilities.iter().map(|c| format!("CAP_{c}")).collect();

    let seccomp_spec = seccomp_profile
        .as_ref()
        .map(|src| src.load(&cap_strings))
        .transpose()?;

    if let Some(seccomp_spec) = seccomp_spec
        && let Some(linux) = spec.linux_mut()
    {
        linux.set_seccomp(Some(seccomp_spec));
    }

    // Hostname
    spec.set_hostname(Some(hostname.clone()));

    // Mounts
    let mut mounts: Vec<_> = spec.mounts().clone().unwrap_or_default();

    // Collect paths that need writable tmpfs mounts.
    // Systemd mode and --read-only overlap on /run and /tmp; systemd mode
    // adds additional paths. We deduplicate by collecting all paths first.
    let mut tmpfs_paths = Vec::new();

    if cli.read_only && cli.read_only_tmpfs {
        // Matches podman --read-only --read-only-tmpfs=true behavior
        tmpfs_paths.extend_from_slice(&["/dev/shm", "/run", "/tmp", "/var/tmp"]);
    }

    if systemd_mode {
        // Systemd needs these writable; extends/overlaps with --readonly
        for path in &["/run", "/run/lock", "/tmp", "/var/log/journal"] {
            if !tmpfs_paths.contains(path) {
                tmpfs_paths.push(path);
            }
        }
    }

    let tmpfs_opts: Vec<String> = if systemd_mode {
        vec![
            "rw".into(),
            "rprivate".into(),
            "nosuid".into(),
            "nodev".into(),
            "tmpcopyup".into(),
        ]
    } else {
        vec!["nosuid".into(), "nodev".into(), "mode=1777".into()]
    };

    for path in &tmpfs_paths {
        mounts.retain(|m| m.destination() != Path::new(path));
        mounts.push(
            MountBuilder::default()
                .destination(PathBuf::from(path))
                .typ("tmpfs")
                .source("tmpfs")
                .options(tmpfs_opts.clone())
                .build()?,
        );
    }

    if systemd_mode {
        // Replace /sys/fs/cgroup with a writable cgroup mount
        mounts.retain(|m| m.destination() != Path::new("/sys/fs/cgroup"));
        mounts.push(
            MountBuilder::default()
                .destination(PathBuf::from("/sys/fs/cgroup"))
                .typ("cgroup")
                .source("cgroup")
                .options(vec!["private".into(), "rw".into()])
                .build()?,
        );
    }

    // Bind mount volumes
    for vol in &cli.volumes {
        let mut opts = vec!["rbind".into()];
        if vol.read_only {
            opts.push("ro".into());
        }
        mounts.push(
            MountBuilder::default()
                .destination(vol.container.clone())
                .typ("none")
                .source(vol.host.clone())
                .options(opts)
                .build()?,
        );
    }

    // Devices
    for dev in &cli.device {
        if rootless {
            let mut opts = vec!["rbind".into(), "nosuid".into(), "noexec".into()];
            opts.push(if dev.perms.contains('w') { "rw" } else { "ro" }.into());
            mounts.push(
                MountBuilder::default()
                    .destination(dev.dst.clone())
                    .typ("none")
                    .source(dev.src.clone())
                    .options(opts)
                    .build()?,
            );
        } else {
            add_device_to_spec(&mut spec, &dev.src, &dev.dst, &dev.perms)?;
            mounts.push(
                MountBuilder::default()
                    .destination(dev.dst.clone())
                    .typ("none")
                    .source(dev.src.clone())
                    .options(vec!["rbind".into()])
                    .build()?,
            );
        }
    }

    // label=nested: bind mount SELinux filesystem into container
    if selinux_nested {
        mounts.push(
            MountBuilder::default()
                .destination(PathBuf::from("/sys/fs/selinux"))
                .typ("bind")
                .source("/sys/fs/selinux")
                .options(vec!["rbind".into()])
                .build()?,
        );
    }

    // /etc config bind mounts (hostname, hosts, resolv.conf)
    // When using pasta networking, default DNS to pasta's DNS forwarder.
    // For bridge networking, use the host's resolv.conf (default).
    let dns: Vec<String> = if cli.dns.is_empty() && *network == NetworkMode::Pasta {
        vec!["169.254.1.1".into()]
    } else {
        cli.dns.clone()
    };
    let etc_mounts = generate_etc_config(
        bundle_dir,
        &hostname,
        &cli.add_host,
        &dns,
        &cli.dns_search,
        &cli.dns_option,
    )?;
    mounts.extend(etc_mounts);

    if let Some(ref path) = init_path {
        mounts.push(
            MountBuilder::default()
                .typ("bind")
                .source(path)
                .destination("/dev/init")
                .options(vec![
                    "bind".into(),
                    "ro".into(),
                    "nosuid".into(),
                    "nodev".into(),
                ])
                .build()?,
        );
    }

    spec.set_mounts(Some(mounts));

    // Poststop hook: unmount bundle and clean up the container directory
    {
        let self_exe = std::env::current_exe().context("Resolving own binary path")?;
        let mut hook_args = vec![
            "cfsrun".into(),
            "--internal-cleanup".into(),
            "--container-dir".into(),
            container_dir.display().to_string(),
            "--container-id".into(),
            container_id.into(),
        ];
        if let Some(ip) = container_ip {
            hook_args.push("--container-ip".into());
            hook_args.push(ip.to_string());
        }
        if let Some(pid) = pasta_pid {
            hook_args.push("--pasta-pid".into());
            hook_args.push(pid.to_string());
        }
        let hook = HookBuilder::default()
            .path(self_exe)
            .args(hook_args)
            .timeout(10)
            .build()?;
        spec.set_hooks(Some(HooksBuilder::default().poststop(vec![hook]).build()?));
    }

    if !cli.publish.is_empty() && host_network {
        eprintln!(
            "note: --publish has no effect with --network=host (ports are already accessible)"
        );
    }

    Ok(spec)
}

fn parse_capability(s: &str) -> Result<Capability> {
    let name = s.to_ascii_uppercase();
    let name = name.strip_prefix("CAP_").unwrap_or(&name);
    name.parse()
        .with_context(|| format!("Unknown capability: {s}"))
}

/// Default capabilities matching podman's containers.conf defaults.
/// These are more restrictive than Docker's defaults, which also include
/// AUDIT_WRITE, MKNOD, and NET_RAW (dropped by podman for security reasons).
fn default_capabilities() -> std::collections::HashSet<Capability> {
    [
        Capability::Chown,
        Capability::DacOverride,
        Capability::Fowner,
        Capability::Fsetid,
        Capability::Kill,
        Capability::NetBindService,
        Capability::Setfcap,
        Capability::Setgid,
        Capability::Setpcap,
        Capability::Setuid,
        Capability::SysChroot,
    ]
    .into_iter()
    .collect()
}

fn all_capabilities() -> std::collections::HashSet<Capability> {
    [
        Capability::AuditControl,
        Capability::AuditRead,
        Capability::AuditWrite,
        Capability::BlockSuspend,
        Capability::Bpf,
        Capability::CheckpointRestore,
        Capability::Chown,
        Capability::DacOverride,
        Capability::DacReadSearch,
        Capability::Fowner,
        Capability::Fsetid,
        Capability::IpcLock,
        Capability::IpcOwner,
        Capability::Kill,
        Capability::Lease,
        Capability::LinuxImmutable,
        Capability::MacAdmin,
        Capability::MacOverride,
        Capability::Mknod,
        Capability::NetAdmin,
        Capability::NetBindService,
        Capability::NetBroadcast,
        Capability::NetRaw,
        Capability::Perfmon,
        Capability::Setfcap,
        Capability::Setgid,
        Capability::Setpcap,
        Capability::Setuid,
        Capability::SysAdmin,
        Capability::SysBoot,
        Capability::SysChroot,
        Capability::SysModule,
        Capability::SysNice,
        Capability::SysPacct,
        Capability::SysPtrace,
        Capability::SysRawio,
        Capability::SysResource,
        Capability::SysTime,
        Capability::SysTtyConfig,
        Capability::Syslog,
        Capability::WakeAlarm,
    ]
    .into_iter()
    .collect()
}

fn add_device_to_spec(spec: &mut Spec, src: &Path, dst: &Path, perms: &str) -> Result<()> {
    use oci_spec::runtime::{LinuxDeviceBuilder, LinuxDeviceCgroupBuilder, LinuxDeviceType};

    let meta = std::fs::metadata(src)
        .with_context(|| format!("Reading device metadata for {}", src.display()))?;
    let rdev = std::os::unix::fs::MetadataExt::rdev(&meta);
    let major = (rdev >> 8) as i64;
    let minor = (rdev & 0xff) as i64;

    let file_type = meta.file_type();
    let dev_type = if std::os::unix::fs::FileTypeExt::is_char_device(&file_type) {
        LinuxDeviceType::C
    } else if std::os::unix::fs::FileTypeExt::is_block_device(&file_type) {
        LinuxDeviceType::B
    } else {
        anyhow::bail!("{} is not a device node", src.display());
    };

    let device = LinuxDeviceBuilder::default()
        .path(dst.to_path_buf())
        .typ(dev_type)
        .major(major)
        .minor(minor)
        .build()?;

    if let Some(linux) = spec.linux_mut() {
        let mut devices = linux.devices().clone().unwrap_or_default();
        devices.push(device);
        linux.set_devices(Some(devices));

        let cgroup_device = LinuxDeviceCgroupBuilder::default()
            .allow(true)
            .typ(dev_type)
            .major(major)
            .minor(minor)
            .access(perms)
            .build()?;

        let mut resources = linux.resources().clone().unwrap_or_default();
        let mut dev_list = resources.devices().clone().unwrap_or_default();
        dev_list.push(cgroup_device);
        resources.set_devices(Some(dev_list));
        linux.set_resources(Some(resources));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cap_various_formats() {
        use oci_spec::runtime::Capability;
        assert_eq!(parse_capability("NET_RAW").unwrap(), Capability::NetRaw);
        assert_eq!(parse_capability("CAP_NET_RAW").unwrap(), Capability::NetRaw);
        assert_eq!(parse_capability("cap_net_raw").unwrap(), Capability::NetRaw);
        assert_eq!(parse_capability("net_raw").unwrap(), Capability::NetRaw);
        assert_eq!(parse_capability("Cap_Net_Raw").unwrap(), Capability::NetRaw);
        assert_eq!(parse_capability("SYS_ADMIN").unwrap(), Capability::SysAdmin);
    }

    #[test]
    fn parse_cap_unknown() {
        assert!(parse_capability("BOGUS_CAP").is_err());
    }

    #[test]
    fn default_caps_are_subset_of_all() {
        let defaults = default_capabilities();
        let all = all_capabilities();
        for cap in &defaults {
            assert!(
                all.contains(cap),
                "default cap {cap} not in all_capabilities"
            );
        }
    }

    #[test]
    fn systemd_commands() {
        assert!(is_systemd_command(&["/usr/sbin/init".into()]));
        assert!(is_systemd_command(&["/sbin/init".into()]));
        assert!(is_systemd_command(&["systemd".into()]));
        assert!(is_systemd_command(&["/usr/lib/systemd/systemd".into()]));
        assert!(!is_systemd_command(&["/usr/bin/bash".into()]));
        assert!(!is_systemd_command(&["echo".into()]));
        assert!(!is_systemd_command(&[]));
    }
}
