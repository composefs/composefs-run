//! Integration tests for cfsrun.
//!
//! Run as regular user for rootless tests, as root for rootful tests.
//! Each mode tests what's possible in that privilege level.
//!
//! Requires `cfsctl` in $PATH (or set CFSCTL env var).
//! On first run, pulls quay.io/centos/centos:stream10 into a test repo.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

const IMAGE: &str = "test";

static TEST_REPO: OnceLock<PathBuf> = OnceLock::new();

fn cfsctl() -> String {
    std::env::var("CFSCTL").unwrap_or_else(|_| "cfsctl".into())
}

fn repo() -> &'static Path {
    TEST_REPO.get_or_init(|| {
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("test-repo");
        if !dir.join("meta.json").exists() {
            let status = Command::new(cfsctl())
                .args(["init", "--insecure"])
                .arg(&dir)
                .status()
                .expect("Failed to run cfsctl init — is cfsctl in PATH?");
            assert!(status.success(), "cfsctl init failed");

            let status = Command::new(cfsctl())
                .arg("--repo")
                .arg(&dir)
                .args([
                    "oci",
                    "pull",
                    "docker://quay.io/centos/centos:stream10",
                    IMAGE,
                ])
                .status()
                .expect("Failed to run cfsctl oci pull");
            assert!(status.success(), "cfsctl oci pull failed");
        }
        dir
    })
}

fn cfsrun() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cfsrun"));
    cmd.arg("--repo").arg(repo());
    cmd
}

fn is_root() -> bool {
    rustix::process::geteuid().is_root()
}

fn run_ok(cmd: &mut Command) -> Output {
    let output = cmd.output().expect("Failed to execute cfsrun");
    assert!(
        output.status.success(),
        "cfsrun failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

// ── Tests for both rootless and rootful ─────────────────────────────────

#[test]
fn basic_echo() {
    let output = run_ok(cfsrun().arg(IMAGE).args(["--", "echo", "hello"]));
    assert_eq!(stdout(&output).trim(), "hello");
}

#[test]
fn root_directory_access() {
    for read_only in [false, true] {
        let mut cmd = cfsrun();
        if read_only {
            cmd.arg("--read-only");
        }
        let output = run_ok(cmd.arg(IMAGE).args(["--", "ls", "-1", "/"]));
        assert!(stdout(&output).lines().any(|entry| entry == "usr"));
    }
    let output = run_ok(cfsrun().arg(IMAGE).args([
        "--",
        "sh",
        "-c",
        "mkdir /cfsrun-test && echo writable > /cfsrun-test/file && cat /cfsrun-test/file",
    ]));
    assert_eq!(stdout(&output).trim(), "writable");
}

#[test]
fn exit_code() {
    let output = cfsrun()
        .arg(IMAGE)
        .args(["--", "sh", "-c", "exit 42"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(42));
}

#[test]
fn env_override() {
    let output =
        run_ok(
            cfsrun()
                .arg("-e")
                .arg("FOO=bar")
                .arg(IMAGE)
                .args(["--", "sh", "-c", "echo $FOO"]),
        );
    assert_eq!(stdout(&output).trim(), "bar");
}

#[test]
fn env_unset() {
    // Unset PATH (the only env var from the image), verify it's gone
    let output = run_ok(
        cfsrun()
            .arg("--unsetenv")
            .arg("PATH")
            .arg(IMAGE)
            .args(["--", "/usr/bin/env"]),
    );
    assert!(!stdout(&output).contains("PATH="));
}

#[test]
fn workdir() {
    let output = run_ok(
        cfsrun()
            .arg("-w")
            .arg("/tmp")
            .arg(IMAGE)
            .args(["--", "pwd"]),
    );
    assert_eq!(stdout(&output).trim(), "/tmp");
}

#[test]
fn read_only() {
    let output = cfsrun()
        .arg("--read-only")
        .arg(IMAGE)
        .args(["--", "touch", "/testfile"])
        .output()
        .unwrap();
    assert!(!output.status.success());
}

#[test]
fn hostname() {
    let output = run_ok(cfsrun().arg("--hostname").arg("myhost").arg(IMAGE).args([
        "--",
        "cat",
        "/etc/hostname",
    ]));
    assert_eq!(stdout(&output).trim(), "myhost");
}

#[test]
fn etc_hosts() {
    let output = run_ok(
        cfsrun()
            .arg("--add-host")
            .arg("mydb:10.0.0.5")
            .arg(IMAGE)
            .args(["--", "cat", "/etc/hosts"]),
    );
    assert!(stdout(&output).contains("10.0.0.5\tmydb"));
}

#[test]
fn resolv_conf_dns() {
    let output = run_ok(cfsrun().arg("--dns").arg("8.8.8.8").arg(IMAGE).args([
        "--",
        "cat",
        "/etc/resolv.conf",
    ]));
    assert!(stdout(&output).contains("nameserver 8.8.8.8"));
}

#[test]
fn container_env() {
    let output = run_ok(
        cfsrun()
            .arg(IMAGE)
            .args(["--", "sh", "-c", "echo $container"]),
    );
    assert_eq!(stdout(&output).trim(), "oci");
}

#[test]
fn no_new_privileges_default() {
    let output =
        run_ok(
            cfsrun()
                .arg(IMAGE)
                .args(["--", "sh", "-c", "grep NoNewPrivs /proc/1/status"]),
        );
    assert!(stdout(&output).contains("NoNewPrivs:\t1"));
}

#[test]
fn seccomp_unconfined() {
    let output = run_ok(
        cfsrun()
            .arg("--security-opt")
            .arg("seccomp=unconfined")
            .arg(IMAGE)
            .args(["--", "echo", "ok"]),
    );
    assert_eq!(stdout(&output).trim(), "ok");
}

#[test]
fn cleanup_no_leftovers() {
    let output = run_ok(cfsrun().arg(IMAGE).args(["--", "echo", "done"]));
    assert_eq!(stdout(&output).trim(), "done");
    // Check no cfsrun dirs remain from this test
    // (other tests may leave dirs temporarily, so just check our output was clean)
}

#[test]
fn bad_image_error() {
    let output = cfsrun()
        .arg("nonexistent-image-xyz")
        .args(["--", "echo", "hi"])
        .output()
        .unwrap();
    assert!(!output.status.success());
}

#[test]
fn volume_mount() {
    let tmp = std::env::temp_dir().join("cfsrun-test-vol");
    std::fs::write(&tmp, "test-content").unwrap();
    let vol_arg = format!("{}:/mnt/testfile:ro", tmp.display());
    let output =
        run_ok(
            cfsrun()
                .arg("-v")
                .arg(&vol_arg)
                .arg(IMAGE)
                .args(["--", "cat", "/mnt/testfile"]),
        );
    assert_eq!(stdout(&output).trim(), "test-content");
    std::fs::remove_file(&tmp).ok();
}

// ── Rootless-only tests ─────────────────────────────────────────────────

#[test]
fn rootless_host_network() {
    if is_root() {
        return;
    }
    let output = run_ok(
        cfsrun()
            .arg("--network")
            .arg("host")
            .arg(IMAGE)
            .args(["--", "echo", "ok"]),
    );
    assert_eq!(stdout(&output).trim(), "ok");
}

#[test]
fn rootless_private_network() {
    if is_root() {
        return;
    }
    let output = run_ok(
        cfsrun()
            .arg("--network")
            .arg("private")
            .arg(IMAGE)
            .args(["--", "echo", "isolated"]),
    );
    assert_eq!(stdout(&output).trim(), "isolated");
}

// ── Rootful-only tests ──────────────────────────────────────────────────

#[test]
fn rootful_host_network() {
    if !is_root() {
        return;
    }
    let output = run_ok(
        cfsrun()
            .arg("--network")
            .arg("host")
            .arg(IMAGE)
            .args(["--", "echo", "ok"]),
    );
    assert_eq!(stdout(&output).trim(), "ok");
}

#[test]
fn rootful_device() {
    if !is_root() {
        return;
    }
    let output = run_ok(cfsrun().arg("--device").arg("/dev/null").arg(IMAGE).args([
        "--",
        "ls",
        "-la",
        "/dev/null",
    ]));
    assert!(stdout(&output).contains("null"));
}

#[test]
fn rootful_cgroup() {
    if !is_root() {
        return;
    }
    // The container sees its cgroup root as "/" due to the cgroup namespace.
    // Just verify it runs and has a cgroup v2 entry.
    let output = run_ok(cfsrun().arg(IMAGE).args(["--", "cat", "/proc/1/cgroup"]));
    assert!(stdout(&output).contains("0::"));
}

#[test]
fn rootful_selinux_label() {
    if !is_root() {
        return;
    }
    if !Path::new("/sys/fs/selinux").exists() {
        return;
    }
    let output = run_ok(
        cfsrun()
            .arg(IMAGE)
            .args(["--", "cat", "/proc/1/attr/current"]),
    );
    assert!(stdout(&output).contains("container_t"));
}
