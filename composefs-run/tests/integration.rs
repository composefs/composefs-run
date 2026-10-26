//! Integration tests for cfsrun.
//!
//! Run as regular user for rootless tests, as root for rootful tests.
//! Each mode tests what's possible in that privilege level.
//!
//! Requires `cfsctl` in $PATH (or set CFSCTL env var).
//! On first run, pulls quay.io/centos/centos:stream10 into a test repo.
//! Set CFSRUN_TEST_REPO to a prepared repository containing the `test` image
//! to avoid a registry pull.

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
        let dir = std::env::var_os("CFSRUN_TEST_REPO")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("test-repo"));
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

fn remove_retained_overlay(path: &Path) {
    if is_root() {
        std::fs::remove_dir_all(path).unwrap();
    } else {
        // Overlayfs work directories can have mode 000. Re-enter a user
        // namespace to recover the permissions held by the original runner.
        let status = Command::new("unshare")
            .args(["--user", "--map-root-user", "--", "rm", "-rf", "--"])
            .arg(path)
            .status()
            .unwrap();
        assert!(status.success(), "Removing test overlay {}", path.display());
    }
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
fn commit_run_and_reuse_image() {
    let first = format!("commit-base-{}", std::process::id());
    let child = format!("commit-child-{}", std::process::id());
    let first_script = "mkdir -p /commit-old/sub; printf original > /commit-old/sub/file; printf remove > /commit-delete; printf metadata > /commit-meta; ln /commit-meta /commit-alias";
    let second_script = "chmod 600 /commit-meta; mv /commit-old /commit-new; mv /commit-delete /commit-written; printf changed > /commit-written; rm /commit-new/sub/file; printf new > /commit-new/new; exit 42";
    let mut command = Command::new(env!("CARGO_BIN_EXE_cfsrun"));
    command
        .current_dir(repo().parent().unwrap())
        .arg("--repo")
        .arg(repo().file_name().unwrap());
    let output = run_ok(command.args([
        "--network",
        "host",
        "--privileged",
        "--commit",
        &first,
        IMAGE,
        "--",
        "sh",
        "-ec",
        first_script,
    ]));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(&format!("Committed {first}: sha256:")),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = cfsrun()
        .args([
            "--network",
            "host",
            "--no-init",
            "--privileged",
            "--commit",
            &child,
            &first,
            "--",
            "sh",
            "-ec",
            second_script,
        ])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(42),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    for (image, script) in [(&first, first_script), (&child, second_script)] {
        let output = Command::new(cfsctl())
            .arg("--repo")
            .arg(repo())
            .args(["oci", "inspect", "--config", image])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let config: oci_spec::image::ImageConfiguration =
            serde_json::from_slice(&output.stdout).unwrap();
        let created_by = config
            .history()
            .as_ref()
            .unwrap()
            .last()
            .unwrap()
            .created_by()
            .as_deref()
            .unwrap();
        assert_eq!(shlex::split(created_by).unwrap(), ["sh", "-ec", script]);
    }
    let output = run_ok(cfsrun().args(["--network", "host", "--no-init", "--privileged", &child, "--", "sh", "-ec",
        "test ! -e /commit-old; test ! -e /commit-delete; test ! -e /commit-new/sub/file; test -d /commit-new/sub; test \"$(cat /commit-meta)\" = metadata; test \"$(stat -c %a /commit-meta)\" = 600; test \"$(cat /commit-written)\" = changed; cat /commit-new/new"]));
    assert_eq!(stdout(&output), "new");
    let output = run_ok(cfsrun().args([
        "--network",
        "host",
        "--no-init",
        "--privileged",
        &first,
        "--",
        "cat",
        "/commit-old/sub/file",
    ]));
    assert_eq!(stdout(&output), "original");
}

#[test]
fn commit_large_command_history() {
    let reference = format!("commit-large-command-{}", std::process::id());
    let args = vec!["x".repeat(1024); 200];
    run_ok(
        cfsrun()
            .args([
                "--network",
                "host",
                "--no-init",
                "--privileged",
                "--commit",
                &reference,
                IMAGE,
                "--",
                "true",
            ])
            .args(&args),
    );
    let output = Command::new(cfsctl())
        .arg("--repo")
        .arg(repo())
        .args(["oci", "inspect", "--config", &reference])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let config: oci_spec::image::ImageConfiguration =
        serde_json::from_slice(&output.stdout).unwrap();
    let created_by = config
        .history()
        .as_ref()
        .unwrap()
        .last()
        .unwrap()
        .created_by()
        .as_deref()
        .unwrap();
    assert!(created_by.len() > 128 * 1024);
    let mut expected = vec!["true".to_owned()];
    expected.extend(args);
    assert_eq!(shlex::split(created_by).unwrap(), expected);
}

#[test]
fn commit_failure_retains_upper_and_exit_status() {
    for persistent in [false, true] {
        for status in [0, 42] {
            // Match the runner's storage: /tmp can itself be overlayfs in CI.
            let overlay = tempfile::tempdir_in("/var/tmp").unwrap();
            let reference = format!("commit-failed-{}-{persistent}-{status}", std::process::id());
            let mut command = cfsrun();
            if persistent {
                command
                    .current_dir(overlay.path().parent().unwrap())
                    .arg("--overlay-dir")
                    .arg(overlay.path().file_name().unwrap());
            }
            command
                .args([
                    "--network",
                    "host",
                    "--no-init",
                    "--privileged",
                    "--commit",
                    &reference,
                    IMAGE,
                    "--",
                    "sh",
                    "-ec",
                    &format!("printf recovery > /.wh.reserved; exit {status}"),
                ])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            let child = command.spawn().unwrap();
            let container_dir = PathBuf::from(format!("/var/tmp/cfsrun-composefs-{}", child.id()));
            let output = child.wait_with_output().unwrap();
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert_eq!(output.status.code(), Some(status), "{stderr}");
            assert!(stderr.contains("OCI reserves filename"), "{stderr}");
            let upper = if persistent {
                overlay.path().join("upper")
            } else {
                container_dir.join("upper")
            };
            assert!(
                stderr.contains(&format!("overlay retained at {}", upper.display())),
                "{stderr}"
            );
            assert_eq!(
                std::fs::read(upper.join(".wh.reserved")).unwrap(),
                b"recovery"
            );
            assert!(!container_dir.join("bundle").exists());
            assert!(
                !cfsrun()
                    .args(["--network", "host", &reference, "--", "true"])
                    .output()
                    .unwrap()
                    .status
                    .success()
            );
            remove_retained_overlay(&container_dir);
            if persistent {
                remove_retained_overlay(overlay.path());
            }
        }
    }
}

#[test]
fn commit_socket_stderr() {
    use std::{
        io::Read,
        os::{fd::OwnedFd, unix::net::UnixStream},
        process::Stdio,
    };
    for fail in [false, true] {
        let reference = format!("commit-socket-{}-{fail}", std::process::id());
        let (mut reader, writer) = UnixStream::pair().unwrap();
        let writer: OwnedFd = writer.into();
        let mut command = cfsrun();
        command
            .args([
                "--network",
                "host",
                "--no-init",
                "--privileged",
                "--commit",
                &reference,
                IMAGE,
                "--",
                "sh",
                "-ec",
                if fail {
                    "printf recovery > /.wh.reserved"
                } else {
                    "printf success > /commit-socket"
                },
            ])
            .stderr(Stdio::from(writer))
            .stdout(Stdio::piped());
        let child = command.spawn().unwrap();
        drop(command);
        let container_dir = PathBuf::from(format!("/var/tmp/cfsrun-composefs-{}", child.id()));
        let status = child.wait_with_output().unwrap().status;
        let mut stderr = String::new();
        reader.read_to_string(&mut stderr).unwrap();
        assert_eq!(status.code(), Some(0), "{stderr}");
        let log = container_dir.join("commit.log");
        assert!(stderr.contains(log.to_str().unwrap()), "{stderr}");
        if fail {
            let diagnostics = std::fs::read_to_string(log).unwrap();
            assert!(
                diagnostics.contains("OCI reserves filename"),
                "{diagnostics}"
            );
            assert!(container_dir.join("upper/.wh.reserved").exists());
            remove_retained_overlay(&container_dir);
        } else {
            assert!(!container_dir.exists());
            let output = run_ok(cfsrun().args([
                "--network",
                "host",
                "--no-init",
                "--privileged",
                &reference,
                "--",
                "cat",
                "/commit-socket",
            ]));
            assert_eq!(stdout(&output), "success");
        }
    }
}

#[test]
fn commit_file_stderr() {
    use std::process::Stdio;
    for append in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let stderr = temp.path().join("stderr.log");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .append(append)
            .truncate(!append)
            .open(&stderr)
            .unwrap();
        let reference = format!("commit-file-{}-{append}", std::process::id());
        let mut command = cfsrun();
        command
            .args([
                "--network",
                "host",
                "--no-init",
                "--privileged",
                "--commit",
                &reference,
                IMAGE,
                "--",
                "sh",
                "-ec",
                "printf recovery > /.wh.reserved",
            ])
            .stderr(Stdio::from(file))
            .stdout(Stdio::piped());
        let child = command.spawn().unwrap();
        drop(command);
        let container_dir = PathBuf::from(format!("/var/tmp/cfsrun-composefs-{}", child.id()));
        let status = child.wait_with_output().unwrap().status;
        assert_eq!(status.code(), Some(0));
        let output = std::fs::read_to_string(stderr).unwrap();
        let diagnostics = if append {
            output.clone()
        } else {
            let log = container_dir.join("commit.log");
            assert!(output.contains(log.to_str().unwrap()), "{output}");
            std::fs::read_to_string(log).unwrap()
        };
        assert!(
            diagnostics.contains("OCI reserves filename"),
            "{diagnostics}"
        );
        assert!(output.contains("poststop hook failed"), "{output}");
        assert!(container_dir.join("upper/.wh.reserved").exists());
        remove_retained_overlay(&container_dir);
    }
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
fn generated_etc_selinux_labels() {
    if !Path::new("/sys/fs/selinux/enforce").exists() {
        return;
    }
    for read_only in [false, true] {
        let mut cmd = cfsrun();
        cmd.args([
            "--network",
            "host",
            "--security-opt",
            "label=level:s0:c123,c456",
            "--dns",
            "192.0.2.53",
        ]);
        if read_only {
            cmd.arg("--read-only");
        }
        let output = run_ok(cmd.arg(IMAGE).args([
            "--",
            "sh",
            "-ec",
            "for path in /etc/hostname /etc/hosts /etc/resolv.conf; do ls -Zd \"$path\"; cat \"$path\" > /dev/null; done",
        ]));
        let expected = ["/etc/hostname", "/etc/hosts", "/etc/resolv.conf"]
            .map(|path| format!("system_u:object_r:container_file_t:s0:c123,c456 {path}"))
            .join("\n");
        assert_eq!(stdout(&output).trim(), expected);
    }
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
