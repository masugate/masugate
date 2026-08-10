# MasuGate protected filesystem connector

`masugate-connector-filesystem` is an exact Linux reference profile, not a
general-purpose filesystem API. It maps the logical `/workspace` prefix to one
dedicated, connector-owned ext4 mount. The mount must be a mount point of its
own, separate from agent and framework workspaces. The connector rejects
Windows, macOS, overlay filesystems, network filesystems, FUSE, object stores,
agent workspaces, directories, recursive operations, symlinks, hard links,
cross-device paths, and special files.

The worker supplies these immutable deployment values to its entry point:

- `MASUGATE_FILESYSTEM_ROOT`: absolute dedicated ext4 mount point;
- `MASUGATE_FILESYSTEM_EXCLUDED_ROOTS`: comma-separated absolute agent/framework
  roots which must not overlap the protected root;
- `MASUGATE_FILESYSTEM_KERNEL_RELEASE`, `MASUGATE_FILESYSTEM_CONTAINER_RUNTIME`,
  `MASUGATE_FILESYSTEM_MOUNT_SOURCE`, and `MASUGATE_FILESYSTEM_MOUNT_OPTIONS`: the
  exact profiled host values;
- `MASUGATE_FILESYSTEM_LOGICAL_PREFIX=/workspace`.

Startup records the verified profile in a connector-private SQLite journal.
The journal is also the idempotency/fence source of truth. Writes stage sealed
content via the SDK reader, create with an atomic no-clobber link, or use an
atomic same-directory replace after checking the expected prior digest.
Deletes atomically rename one verified regular file into connector-private
same-filesystem quarantine. Connector evidence contains only logical paths,
digests, byte counts, and a quarantine identity; it never includes physical
paths or content.

The profile must be mounted with exactly the profiled ext4 options before the
clean-wheel gate is enabled. A normal project directory, a Docker overlay
layer, and `/tmp` are deliberately not substitutes for that gate.
