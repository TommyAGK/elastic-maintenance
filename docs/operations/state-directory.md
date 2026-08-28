# Production state directory contract

The runtime opens the configured `stateDir` before it creates a listener. The
state directory contains non-secret, versioned JSON state only; credentials,
OIDC tokens, session material, and certificate bodies never belong here.

## Required deployment contract

- The mountpoint must already exist, be owned by the process effective UID, and
  have mode `0700`. The runtime does not create or repair the mountpoint.
- The service is Linux-only for state persistence. It requires descriptor-safe
  path operations and a filesystem that supports `flock`, atomic same-directory
  rename, file `fsync`, and directory `fsync`.
- The deployment must have exactly one replica using one ReadWriteOnce (RWO)
  volume. The process lock rejects a second writer for the same state root.
- Controlled subdirectories are mode `0700`; state documents and lock files are
  mode `0600`, owner-owned, regular, and single-linked. Existing objects are
  validated, never automatically `chmod`ed or `chown`ed. New controlled
  directories and files are created with the required modes.
- The state schema limit is 4 MiB per document. The production runtime uses the
  `state.MaxDocumentBytes` limit when opening the filesystem store.

The fixed state subdirectories are `config-snapshots`, `sources`,
`inventories`, `journals`, `plans`, `jobs`, `reports`, `audit`, and `locks`.
Unexpected root entries, symlinks in controlled paths, unsafe ownership or
permissions on the root/controlled directories and lock files, special files,
and hard links fail closed. Documents are checked with the same policy when
read, written, or removed.

## Space and readiness

The runtime uses `statefs.DefaultMinFreeBytes` (64 MiB) as a preflight,
advisory free-space reserve. It is not a quota and cannot guarantee that a
subsequent write will succeed. A failed preflight or later filesystem health
check makes startup fail or readiness return `503 Service Unavailable`.
Liveness remains independent of state health.

Unsafe root, controlled-directory, process-lock, ownership, permission, or
free-space state fails startup and readiness. Unsafe document objects fail
closed when accessed. The service does not disclose the absolute state path or
state contents in public errors or HTTP responses. It
does not defend against a malicious same-UID process or a PVC/storage
administrator replacing objects; those actors are outside the trusted process
boundary.

## Writes and interruption recovery

State writes use an owner-only temporary file, complete file and directory
`fsync`, and an atomic rename in the destination directory. No-replace writes
remain no-replace. On the next open, interrupted `.statefs-tmp-*` files are
validated and removed safely. A temporary file left by the Linux no-replace
link fallback may be removed after its destination is confirmed, preserving the
committed destination.

After the state store opens, the runtime performs one bounded, coherent read of
the jobs directory before invoking the listener or constructing services. Every
record is strictly decoded, checked against its filename, and classified before
any CAS interruption. Queued and running records are marked `interrupted` with
one UTC recovery timestamp and the policy failure code; terminal records are
not rewritten. Malformed, ambiguous, over-bound, or concurrently changed state
fails startup with a safe category and releases the process lock. A retry is
safe after partial progress because interrupted records are terminal and
preserved.
