# composefs-run
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fcomposefs%2Fcomposefs-run.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fcomposefs%2Fcomposefs-run?ref=badge_shield)


**NOTE**: This is currently a proof of concept, and not intended for
production use

A minimal container runner that runs OCI containers directly from
[composefs-rs](https://github.com/containers/composefs-rs)
repositories using [crun](https://github.com/containers/crun), without
requiring podman's full runtime infrastructure or persistent state
tracking.

### Features

- Mostly CLI-compatible with `podman run`
- **Rootful mode**: kernel erofs + overlayfs, bridge networking via
  [netavark](https://github.com/containers/netavark)
- **Rootless mode**: FUSE-based composefs + unprivileged overlayfs
  (`userxattr`), user namespace with subuid/subgid mapping,
  [pasta](https://passt.top/) networking
- Minimal host state, containers are just child processes. There is no
  equivalent of podman ps/rm etc.
- No detached mode, always assumes `-i`.
- By default, writable overlays are transient, stored in /var/tmp.
  This can be overridden with `--overlay-dir`
- By default runs catatonit in the container to forward signals

### Quick start

```bash
# Build (requires composefs-rs as a dependency)
cargo build

# Pull an image into a composefs repository
cfsctl init --insecure /tmp/repo
cfsctl --repo /tmp/repo oci pull docker://quay.io/centos/centos:stream10 cs10

# Run a container (rootless — automatic)
target/debug/cfsrun --repo /tmp/repo -t cs10 -- bash

# Run as root (uses kernel erofs + bridge networking)
sudo target/debug/cfsrun --repo /tmp/repo -t cs10 -- bash
```

### Common options

```
cfsrun [OPTIONS] <IMAGE> [-- <CMD>...]

Options:
  --repo <PATH>           Path to composefs repository
  -t, --tty               Allocate a pseudo-TTY
  -e, --env <KEY=VALUE>   Set environment variables
  -u, --user <UID[:GID]>  Override user
  -w, --workdir <PATH>    Override working directory
  -v, --volume <H:C[:ro]> Bind mount
  --device <PATH[:PATH[:PERMS]]>  Add host device
  --read-only             Read-only rootfs
  --overlay-dir <PATH>    Persistent overlay directory
  --network <MODE>        host|pasta|bridge|private
  --hostname <NAME>       Container hostname
  --privileged            Full capabilities, no seccomp/SELinux
  --cap-add/--cap-drop    Modify capabilities
  --security-opt <OPT>    seccomp, label, no-new-privileges
  --dns/--dns-search      DNS configuration
  -p, --publish <H:C>     Port forwarding
  --add-host <HOST:IP>    Extra /etc/hosts entries
```

### Testing

```bash
# Unit tests (no container image needed)
just test-unit

# Integration tests (requires cfsctl in PATH, pulls test image)
just cfsctl=/path/to/cfsctl test-integration

# All tests
just cfsctl=/path/to/cfsctl test
```

### License

Apache-2.0 OR MIT


[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fcomposefs%2Fcomposefs-run.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fcomposefs%2Fcomposefs-run?ref=badge_large)