# Cyclops Safe Copier

<img src="launcher/cyclops-safe-copier.svg" width="96" align="right" alt="">

A cautious Linux tool for copying important folders to another disk — and then
**proving** the copy is exact, instead of trusting that "copy finished" means "copy correct".

```
cyclops-safe-copy SOURCE DESTINATION [--dry-run | --verify-only | --resume]
```

**What it does:** copies, then verifies. That is all.
It never deletes, moves, renames or symlinks the source, and never prunes either side.
It never changes Git state. Cutover, symlinking and deletion are separate steps you take
yourself; this tool contains no code for any of them, and a test checks the source code
to make sure of that.

Built for project folders, archives and anything where an ordinary drag-and-drop copy
gives too little proof.

> Linux only (it relies on `/proc`, rsync and GNU coreutils). Tested on Ubuntu 24.04,
> ext4 SSD → ext4 HDD.

---

## Install

Requirements:

- Python 3.9+ (standard library only)
- `rsync` 3.1+
- `git` (optional; needed for repository checks)
- `ionice` (optional)
- for the window app only: GTK 3 bindings (`python3-gi`, `gir1.2-gtk-3.0`; present on most GNOME desktops)

```bash
git clone https://github.com/CyclopsEyeTeam/cyclops-safe-copier.git ~/tools/cyclops-safe-copier
bash ~/tools/cyclops-safe-copier/install.sh      # adds `cyclops-safe-copy` + an app-menu entry
cyclops-safe-copy --help
```

`install.sh` only writes `~/.local/bin/cyclops-safe-copy` (a symlink) and
`~/.local/share/applications/cyclops-safe-copier.desktop`. Running
`bash install.sh --uninstall` removes exactly those two again.

## Before you trust it with anything valuable

Run the machine-local acceptance on your own SSD/HDD pair first. See
[Machine-local acceptance](#machine-local-acceptance-ssd--hdd) below. Until it passes, use
the tool only on disposable test folders. The window app shows an amber banner until it
has passed.

## Window app

Open **Cyclops Safe Copier** from your app menu, or run `python3 launcher/cyclops_safe_copier_gui.py`.

- Folder pickers for source and destination.
- Four actions: Check only (dry run), Copy + verify, Resume, Verify existing copy.
- **Stop safely**: behaves like Ctrl-C. The partial copy is kept, and you can resume later.
- A coloured verdict, the full output, and a button that opens the record folder.

The window does not copy anything itself. It runs the same command-line tool and shows
its output. Without GTK it opens a simple terminal wizard instead.

## Usage

| Command | Effect |
|---|---|
| `cyclops-safe-copy SRC DST --dry-run` | Runs the full preflight and shows the exact rsync command. Copies nothing. |
| `cyclops-safe-copy SRC DST` | Preflight → copy → independent verification. |
| `cyclops-safe-copy SRC DST --resume` | Continues an interrupted copy this tool started. Every file is re-checked by checksum; the partial copy is never assumed to be valid. |
| `cyclops-safe-copy SRC DST --verify-only` | Re-proves an existing copy. Writes nothing to either tree. |

`DST` is the directory to create, or an existing **empty** directory.
For a single-file source, `DST` is the path of the new file.
The tool will not merge into a non-empty destination.

Other options:

- `--records-dir DIR`
- `--bwlimit KBPS`
- `--allow-entire-home`
- `--allow-special-files`

## Final states (never just "done")

| State | Exit code |
|---|---|
| `DRY RUN — NOTHING COPIED` | 0 |
| `COPY VERIFIED — SOURCE UNCHANGED` followed by `COPY VERIFIED — runtime/cutover not implied` | 0 |
| `REFUSED — NOTHING COPIED` (a guard stopped it before copying) | 2 |
| `COPY INCOMPLETE — SOURCE UNCHANGED` | 3 |
| `COPY INCOMPLETE — SOURCE CHANGED BY ANOTHER PROCESS` | 3 |
| `COPY COMPLETE — VERIFICATION FAILED` | 4 |
| `VERIFICATION FAILED — NOTHING COPIED` (`--verify-only`) | 4 |

When a run fails, nothing is repaired and nothing is deleted. Both trees are left exactly
as they are, and the report explains what failed.

## Preflight (before anything is written)

**Paths**

- Resolves both paths, shows the filesystem and device for each, and says whether the
  copy is same-filesystem or cross-filesystem.
- Refuses the same location, a destination inside the source, and a source inside the
  destination.
- These checks are done by path, by inode and by mount identity. Symlinks and **bind
  mounts** cannot get past them.

**Protected locations**

- Refuses `/`, `/home`, `/usr`, `/var`, `/etc`, `/boot`, `/proc`, `/sys`, `/dev`, `/run`
  and similar locations, including when they are reached through a bind mount.
- Refuses your entire home directory unless you pass `--allow-entire-home`.
  A home directory is never allowed as the destination.

**Filesystems**

- Refuses a destination that cannot hold Linux metadata faithfully: exFAT, NTFS
  (including fuseblk) and vfat.
- Refuses overlay and FUSE filesystems, because their paths can be aliases for other
  directories.

**The source tree**

- Counts files, directories, symlinks (including dangling ones), hardlink groups,
  logical bytes and on-disk bytes.
- Reports unusual objects: special files, nested mounts, sparse files, absolute or
  escaping symlinks, hardlinks that also point outside the tree, unreadable entries,
  ownership or xattrs that can't be kept without root, and names with newlines or that
  aren't valid UTF-8.
- These checks only read metadata. No file contents are opened.

**Open writers**

- Checks `/proc` for open writers under the source or destination. A writer is matched
  by path, by inode and by mount identity, and shared writable `mmap`s are included.
- If a writer is found, the run **stops**. It never quietly copies data that is
  still changing.

**Space and Git**

- Checks free space and inodes with a safety margin of 5% or 256 MiB, whichever is
  larger. It also checks there is room for the records.
- Lists any Git repositories found.

## Copy

- Runs `ionice -c2 -n7 nice -n19 rsync -a -H -A -X --numeric-ids --modify-window=-1 --open-noatime …`
- This preserves contents, structure, permissions, nanosecond timestamps (files,
  directories and symlinks), symlinks as symlinks, hardlinks, ownership, ACLs, xattrs
  and hidden files.
- `--modify-window=-1` matters. Without it, rsync treats two timestamps in the same
  second as equal, and silently leaves directory mtimes wrong.
- Temporary files are kept in the records staging area, so an interrupted copy leaves
  no junk inside the destination.
- If the tool is killed, even with `kill -9`, rsync is stopped automatically, so no
  orphaned process keeps writing.
- A guard function rejects any rsync command containing `--delete*`,
  `--remove-source-files`, `-L`, `--inplace`, `--update`, filters and similar options.
  Tests cover this guard.

## Verification

A copy only counts as verified if **every** check below passes. A successful rsync exit
is not trusted on its own.

1. **Structural:** both trees are compared path by path on type, mode, uid/gid,
   mtime (to the nanosecond), size, symlink target, device numbers, xattrs and ACLs.
   Hardlink groups, counts and logical bytes must also match.
2. **Content:** SHA-256 manifests are built for both trees and compared. The manifest
   files live in the records directory, outside both trees.
3. **Read-back:** each destination file has its page cache dropped first
   (`sync` + `POSIX_FADV_DONTNEED`), so the hash comes from the disk where the kernel
   allows that.
4. **rsync proof:** a checksum-based `--dry-run --itemize-changes` must report zero
   changes.
5. **Git:** per repository, compares HEAD, symbolic HEAD, all refs (branches, tags,
   stash), root commits, redacted remotes, the index (`ls-files --stage`), status
   (tracked changes, staged, untracked), worktrees, submodules and object counts.
6. **Destination stable:** the destination did not change while it was being verified.
7. **Source unchanged:** compared against the preflight metadata snapshot, including
   ctime and inode.

**How Git is kept read-only:**

- Commands run with `--no-optional-locks` and `GIT_OPTIONAL_LOCKS=0`, so `status` never
  rewrites the index.
- fsmonitor and hooks are disabled, network protocols are blocked, and every
  configured **filter driver** (git-lfs and others) is overridden with an empty command.
  Without that, `git status` could run commands from the repo's config.
- Commands like `clean`, `reset`, `checkout`, `stash`, `gc` and `repack` are never run.
- A dirty repository is valid data and is copied exactly as it is.
- A linked worktree, or a repo with `core.worktree` set, reads the same Git metadata from
  both trees. Those are reported as *not independently comparable*, with a warning; they
  are not given a false PASS.

**Time:** verification reads the source twice and the destination twice. On a SATA HDD,
expect it to take about 4–5 times as long as the copy itself. This is deliberate: verification
is never weakened to make it faster.

## Records

- **Location:** `--records-dir`, or else `$CYCLOPS_SAFE_COPY_RECORDS`, or else
  `<destination disk>/cyclops-safe-copy-records`. By default the records therefore go on
  the HDD, not the SSD.
- **Each run** gets `operations/<id>/` containing `record.json`, `report.txt`, both
  manifests, `rsync-copy.log` and `rsync-proof.txt`.
- **What a record holds:** timestamps, paths, filesystems, counts and sizes, the exact
  commands, manifest hashes, every check result, copy and verify times, warnings and the
  final status.
- **What a record never holds:** file contents or credentials. Remote URLs have userinfo,
  query strings and token-like path segments redacted.
- **Pair state:** `pairs/<id>.json` lets `--resume` only continue copies this tool itself
  started.
- **Locks:** `locks/` holds a per-destination lock, so two runs can never write into one
  destination.

## Known limits (reported, not hidden)

- **Ownership:** without root, entries owned by other users and `security.*`/`trusted.*`
  xattrs cannot be preserved. The tool **refuses** rather than copying them partially;
  run it with `sudo` in that case.
- **SELinux labels** are assigned by policy on the destination, so they are not compared.
  A warning is shown.
- **chattr flags** (immutable, append-only) are not preserved by rsync and are not
  compared.
- **atime** is not treated as part of "unchanged". `O_NOATIME` and `--open-noatime` avoid
  changing it where the kernel allows.
- **Sparse files** are written fully allocated. The content is identical, but the copy
  uses more disk space.
- **Hardlinks that also point outside the source** are only preserved within the tree.
  A warning is shown.

## Tests

```bash
cd cyclops-safe-copier
python3 -m pytest -q                                   # as your normal user
CYCLOPS_TEST_OTHER_FS=/media/HDD/tmp-test python3 -m pytest -q -k cross_filesystem
sudo python3 -m pytest -q                              # also runs bind-mount/overlay/tmpfs cases
```

- There are 110 tests, and every fixture is disposable (`tmp_path`).
- Some tests need root (bind mounts, overlay, a tiny tmpfs for disk-full). Others only
  make sense without root (unreadable files, ownership). Run the suite both ways.

## Machine-local acceptance (SSD → HDD)

Run this on the real machine **before** pointing the tool at anything valuable:

```bash
cd ~/tools/cyclops-safe-copier
python3 acceptance/cyclops_acceptance.py --hdd-dir /media/$USER/<HDD>/cyclops-safe-copy-acceptance
```

It performs every acceptance step and writes `ACCEPTANCE-REPORT.md` on the HDD. Only if
every step passes does it preserve V1: a read-only tarball plus `SHA256SUMS` next to the
report, and the git tag `safe-copier-v1.0.1-accepted` on the tool folder.

- **Tests:** runs both suites, first as you and then with `sudo`. sudo will ask for your
  password once.
- **Records location:** proves the records directory sits on the HDD device, not the SSD.
- **Copies:** does a `--dry-run` and then a real SSD→HDD copy of a small disposable
  fixture, and checks that the output ends exactly `COPY VERIFIED — runtime/cutover not implied`.
- **Independent proof:** proves the source is unchanged using GNU
  `find`/`sha256sum`/`getfattr` (not the tool's own code), including inode and ctime.
- **Interruption:** sends Ctrl-C (SIGINT) partway through a 3 GiB disposable copy, then
  checks:
  - no rsync is left running;
  - no temporary junk is left in the destination;
  - a plain re-run is refused;
  - `--resume` re-checks by checksum and verifies.
- **Reporting:** records copy and verification times, MB/s, and filesystem differences
  (timestamp resolution, xattrs and ACLs, block allocation, mount options, rotational flags).

**Safety:** it only works inside new, empty folders that it creates itself. It never
deletes, moves or symlinks anything. The fixtures (about 3 GiB on each disk) are left for
you to inspect and remove.

**Options:** `--large-gb N` sets the interruption fixture size. Pass `--records-dir DIR`
if you will use an explicit records location in practice.

**If the HDD mount root is not writable by you,** step 2 fails and tells you how to fix
it. Create `<HDD>/cyclops-safe-copy-records` owned by you, or set `CYCLOPS_SAFE_COPY_RECORDS`.

**Changed in 1.0.1:** the final state is now always the last line of output, so
`tail -1` shows the verdict.

## Licence

MIT. See [LICENSE](LICENSE). The software is provided as is, without warranty.
It is built to be cautious, but keep your own backups and run the acceptance first.

How it was tested, including an independent adversarial review and the real-hardware
acceptance results, is described in [docs/VERIFICATION.md](docs/VERIFICATION.md).
