# How Cyclops Safe Copier was verified

## 1. Test-driven development

The test suite was written first and confirmed failing before any implementation code existed.
It now has 110 tests, and every one of them uses disposable `tmp_path` fixtures only.

| Run as | Result |
|---|---|
| normal user | 101 passed, 9 skipped (the skipped tests need root) |
| root (`sudo`) | 107 passed, 3 skipped (the skipped tests only make sense without root) |

Every test therefore runs in at least one mode. Highlights:

- **Awkward content:** hidden files, empty files and directories, names with spaces,
  newlines, Unicode and non-UTF-8 bytes, symlinks (including dangling ones), hardlinks,
  executable/setuid/read-only modes, xattrs and ACLs.
- **Interruptions:**
  - copies interrupted with SIGTERM, SIGINT and SIGKILL, each followed by `--resume`;
  - no orphaned rsync is left writing afterwards;
  - a disk that really fills up;
  - insufficient space caught before copying starts.
- **Detecting change and damage:**
  - the source changed mid-run;
  - silent destination corruption with size and mtime preserved, which rsync's quick-check would miss;
  - mode, mtime or xattr mismatches;
  - stray extra files (detected but never pruned);
  - broken hardlinks.
- **Refusals:**
  - nesting in either direction, including through symlinks or bind mounts;
  - protected system paths, including when reached through bind mounts;
  - the user's entire home directory;
  - a non-empty destination;
  - exFAT, NTFS, overlay and FUSE destinations;
  - concurrent runs;
  - open writers, including through an alias path or a shared writable `mmap`.
- **Git:**
  - dirty repositories with staged and untracked files are copied exactly;
  - credentials are redacted (userinfo, query tokens and token-like path segments);
  - repository filter drivers are never executed;
  - linked worktrees, submodules and `core.worktree`.
- **Static guarantees:**
  - every rsync command passes a destructive-flag guard;
  - the source code contains no deletion, rename or symlink calls (apart from one atomic rename used for records).

## 2. Independent adversarial review

A separate reviewer spent three rounds trying to break the tool on disposable fixtures.
Every finding was reproduced, fixed, and given a regression test.

| Area | Finding | Fix |
|---|---|---|
| Path guards | Nesting, records-dir and protected-path guards could be bypassed through **bind mounts** | Location identity is now checked by path, by inode and by mount (from `/proc/self/mountinfo`); bind mounts inside the source are refused |
| Git | `git status` could run **filter commands from the repository's config** | Every configured filter driver is overridden with an empty command; the destination is re-scanned after the Git checks |
| Open writers | A writer reaching the source through an **alias path** went undetected | Writers are now matched by inode and mount identity as well as by path |
| Open writers | **Shared writable `mmap`s** were missed | Detected now |
| Error handling | Unexpected OS errors, including a full records disk, **crashed** the tool | Every error now ends in a clean, explicit final state |
| Locking | A shared `/tmp` lock could be **redirected through a symlink** | Locks now live only in the records directory and are opened with `O_NOFOLLOW` |
| Records | Records sub-directories could be **planted as symlinks** | Refused |
| Filesystems | **Overlay and FUSE** sources or destinations | Refused |

The final round reported no critical or high issues.

## 3. Real-hardware acceptance (SSD → HDD)

`acceptance/cyclops_acceptance.py` ran on a real desktop running Ubuntu with kernel 7.0.
The source was a 120 GB SATA SSD (ext4) and the destination a 1 TB 7200 rpm SATA HDD (ext4).

| Check | Result |
|---|---|
| Both test suites (user and sudo; the cross-filesystem test ran against the real HDD) | PASS |
| Records directory resolves onto the HDD, nothing written to the SSD | PASS |
| Dry run, then real copy; output ends exactly `COPY VERIFIED — runtime/cutover not implied` | PASS |
| Source fingerprint (GNU `find` + `sha256sum` + `getfattr`, including inode and ctime) identical before and after | PASS |
| Ctrl-C partway through a 3 GiB copy | PASS |

What the Ctrl-C test checked:

- the run ends `COPY INCOMPLETE`;
- no rsync is left running and no temp files are left in the destination;
- a plain re-run is refused;
- `--resume` re-checks every file by checksum and verifies.

Measured on that HDD: copying 3 GiB took 16.4 s (~187 MB/s), and verifying it took 73 s.
The HDD supported nanosecond timestamps, user xattrs and POSIX ACLs.
