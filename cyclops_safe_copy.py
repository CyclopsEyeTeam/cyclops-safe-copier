#!/usr/bin/env python3
"""Cyclops Safe Copier — conservative copy with independent verification.

    cyclops-safe-copy SOURCE DESTINATION [--dry-run | --verify-only | --resume]

Copying and verification only.  This tool never deletes, moves, renames,
symlinks, prunes or otherwise modifies the SOURCE, never prunes the
DESTINATION, and never mutates Git state.  Cutover / symlinking / deletion
are separate, explicitly approved operations and are not implemented here.
"""
from __future__ import annotations

import argparse
import ctypes
import datetime as _dt
import fcntl
import hashlib
import json
import os
import re
import secrets
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

VERSION = "1.0.1"

# --------------------------------------------------------------------------- #
# Final states (never just "done")
# --------------------------------------------------------------------------- #
STATE_DRY = "DRY RUN — NOTHING COPIED"
STATE_REFUSED = "REFUSED — NOTHING COPIED"
STATE_INCOMPLETE = "COPY INCOMPLETE — SOURCE UNCHANGED"
STATE_INCOMPLETE_SRC_CHANGED = "COPY INCOMPLETE — SOURCE CHANGED BY ANOTHER PROCESS"
STATE_VFAIL = "COPY COMPLETE — VERIFICATION FAILED"
STATE_VERIFY_ONLY_FAIL = "VERIFICATION FAILED — NOTHING COPIED"
STATE_VERIFIED = "COPY VERIFIED — SOURCE UNCHANGED"
STATE_RUNTIME = "COPY VERIFIED — runtime/cutover not implied"

EXIT_CODES = {
    STATE_VERIFIED: 0,
    STATE_DRY: 0,
    STATE_REFUSED: 2,
    STATE_INCOMPLETE: 3,
    STATE_INCOMPLETE_SRC_CHANGED: 3,
    STATE_VFAIL: 4,
    STATE_VERIFY_ONLY_FAIL: 4,
}

# Pair-state labels stored in the records directory
PS_IN_PROGRESS = "IN_PROGRESS"
PS_INCOMPLETE = "INCOMPLETE"
PS_VFAIL = "VERIFICATION_FAILED"
PS_VERIFIED = "VERIFIED"

# --------------------------------------------------------------------------- #
# Safety tables
# --------------------------------------------------------------------------- #
FORBIDDEN_EXACT = {b"/", b"/home", b"/root", b"/mnt", b"/media", b"/tmp", b"/opt", b"/srv",
                   b"/lost+found", b"/snap"}
FORBIDDEN_TREES = (b"/proc", b"/sys", b"/dev", b"/run", b"/boot", b"/usr", b"/etc", b"/var",
                   b"/bin", b"/sbin", b"/lib", b"/lib32", b"/lib64", b"/libx32")

UNSUPPORTED_DEST_FS = {"vfat", "msdos", "exfat", "ntfs", "ntfs3", "fuseblk", "iso9660", "udf",
                       "squashfs", "proc", "sysfs", "devtmpfs", "ramfs", "cgroup", "cgroup2"}
ALIASING_FS = {"overlay", "aufs", "unionfs", "mergerfs", "bindfs", "fuse"}
KNOWN_GOOD_FS = {"ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "tmpfs", "bcachefs",
                 "jfs", "reiserfs", "nilfs2"}

RSYNC_FORBIDDEN_LONG = {
    "--remove-source-files", "--copy-links", "--copy-dirlinks", "--keep-dirlinks",
    "--copy-unsafe-links", "--safe-links", "--munge-links", "--inplace", "--append",
    "--append-verify", "--prune-empty-dirs", "--update", "--ignore-existing", "--existing",
    "--force", "--max-delete", "--backup", "--backup-dir", "--suffix", "--size-only",
    "--ignore-errors", "--fake-super", "--super", "--sparse",
    "--preallocate", "--write-devices", "--copy-as", "--chown", "--chmod", "--usermap",
    "--groupmap", "--no-implied-dirs", "--relative", "--files-from", "--exclude",
    "--include", "--filter", "--exclude-from", "--include-from", "--cvs-exclude",
}
RSYNC_FORBIDDEN_SHORT = set("LkKmuSbRCfF")  # copy-links, dirlinks, prune, update, sparse, backup, relative, filters

MiB = 1024 * 1024
HASH_CHUNK = 4 * MiB


class SafetyError(Exception):
    """An internal guard caught an unsafe command.  Never expected in normal use."""


class Refusal(Exception):
    def __init__(self, reasons):
        self.reasons = list(reasons) if isinstance(reasons, (list, tuple)) else [reasons]
        super().__init__("; ".join(self.reasons))


class Interrupted(BaseException):
    pass


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #
def b(p) -> bytes:
    return os.fsencode(p)


def rel_str(r: bytes) -> str:
    """Relative path for records (lossless; non-UTF-8 bytes become surrogates)."""
    return r.decode("utf-8", "surrogateescape")


def disp(p) -> str:
    """Safe single-line display of a path."""
    s = os.fsencode(p).decode("utf-8", "backslashreplace")
    return s.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")


def human(n: int | float | None) -> str:
    if n is None:
        return "?"
    n = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024 or unit == "TiB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.2f} {unit}"
        n /= 1024
    return f"{n:.2f} TiB"


def now_utc() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def is_inside(child: bytes, parent: bytes) -> bool:
    """True if child is parent or below it (pure path test on resolved paths)."""
    if parent == b"/":
        return True
    return child == parent or child.startswith(parent.rstrip(b"/") + b"/")


def nearest_existing(p: bytes) -> bytes:
    while not os.path.lexists(p):
        parent = os.path.dirname(p)
        if parent == p:
            break
        p = parent
    return p


def lstat_entry(p):
    """lstat used for every scanned entry (a seam for tests)."""
    return os.lstat(p)


def sha256_file_bytes(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(MiB), b""):
            h.update(chunk)
    return h.hexdigest()


def atomic_write(path: Path, data: bytes) -> None:
    """Write a records file atomically (tmp + fsync + rename).  Records dir only."""
    path = Path(path)
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def write_json(path: Path, obj) -> None:
    atomic_write(path, (json.dumps(obj, indent=2, ensure_ascii=True, sort_keys=False) + "\n").encode())


IS_ROOT = os.geteuid() == 0


# --------------------------------------------------------------------------- #
# Console that also keeps a transcript for the record
# --------------------------------------------------------------------------- #
class Console:
    def __init__(self, stream=None):
        self.lines: list[str] = []
        self.stream = stream or sys.stdout

    def say(self, text: str = "") -> None:
        for line in text.split("\n"):
            self.lines.append(line)
        try:
            print(text, file=self.stream, flush=True)
        except (BrokenPipeError, ValueError):
            pass

    def section(self, title: str) -> None:
        self.say(f"\n── {title} " + "─" * max(4, 60 - len(title)))

    def text(self) -> str:
        return "\n".join(self.lines) + "\n"


def heartbeat(msg: str) -> None:
    try:
        print(msg, file=sys.stderr, flush=True)
    except (BrokenPipeError, ValueError):
        pass


# --------------------------------------------------------------------------- #
# Filesystem / mount information
# --------------------------------------------------------------------------- #
def _unescape_mount(s: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), s)


def read_mounts() -> list[dict]:
    """Parse /proc/self/mountinfo (later lines over-mount earlier ones)."""
    mounts = []
    try:
        with open("/proc/self/mountinfo", "r", encoding="utf-8", errors="surrogateescape") as f:
            for line in f:
                if " - " not in line:
                    continue
                left, right = line.rstrip("\n").split(" - ", 1)
                lp, rp = left.split(), right.split()
                if len(lp) < 5 or not rp:
                    continue
                mounts.append({"majmin": lp[2], "root": b(_unescape_mount(lp[3])),
                               "mnt": b(_unescape_mount(lp[4])), "fstype": rp[0],
                               "device": _unescape_mount(rp[1]) if len(rp) > 1 else "?"})
    except OSError:
        pass
    return mounts


def _mount_for(real: bytes, mounts: list[dict]) -> dict | None:
    best = None
    for m in mounts:
        if is_inside(real, m["mnt"]) and (best is None or len(m["mnt"]) >= len(best["mnt"])):
            best = m
    return best


def canon(path, mounts: list[dict] | None = None) -> tuple[str, bytes]:
    """Bind-mount-proof identity of a location: (filesystem major:minor, path inside that
    filesystem).  Two paths that reach the same directory through different mounts or
    symlinks get the same canonical form."""
    mounts = read_mounts() if mounts is None else mounts
    real = os.path.realpath(b(path))
    base = nearest_existing(real)
    rest = real[len(base):] if real != base else b""
    m = _mount_for(base, mounts)
    if m is None:
        return ("?", real)
    suffix = base[len(m["mnt"]):] if m["mnt"] != b"/" else base
    inner = (m["root"].rstrip(b"/") + (suffix if suffix.startswith(b"/") or not suffix else b"/" + suffix))
    inner = inner or b"/"
    return (m["majmin"], (inner.rstrip(b"/") + rest) or b"/")


def canon_inside(child, parent, mounts=None) -> bool:
    mounts = read_mounts() if mounts is None else mounts
    c, p = canon(child, mounts), canon(parent, mounts)
    return c[0] == p[0] and is_inside(c[1], p[1])


def fs_info(path) -> dict:
    """Mount point, filesystem type and device for a path (via /proc/self/mountinfo)."""
    real = os.path.realpath(b(path))
    m = _mount_for(real, read_mounts())
    if m is None:
        best = {"mountpoint": "/", "fstype": "unknown", "device": "?", "majmin": "?"}
    else:
        best = {"mountpoint": os.fsdecode(m["mnt"]), "fstype": m["fstype"], "device": m["device"],
                "majmin": m["majmin"]}
    try:
        st = os.stat(nearest_existing(real))
        best["st_dev"] = f"{os.major(st.st_dev)}:{os.minor(st.st_dev)}"
    except OSError:
        best["st_dev"] = "?"
    return best


def mounts_inside(root: bytes) -> list[bytes]:
    """Mount points strictly below root (includes same-device bind mounts)."""
    real = os.path.realpath(b(root))
    return sorted({m["mnt"] for m in read_mounts() if m["mnt"] != real and is_inside(m["mnt"], real)})


def free_space(path) -> tuple[int, int | None]:
    """(bytes available to us, inodes available or None) at the nearest existing ancestor."""
    sv = os.statvfs(nearest_existing(os.path.realpath(b(path))))
    inodes = sv.f_favail if sv.f_files else None
    return sv.f_bavail * sv.f_frsize, inodes


# --------------------------------------------------------------------------- #
# Tree scanning (metadata only — never opens file contents)
# --------------------------------------------------------------------------- #
def ftype(mode: int) -> str:
    if stat.S_ISREG(mode):
        return "file"
    if stat.S_ISDIR(mode):
        return "dir"
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISCHR(mode):
        return "chardev"
    if stat.S_ISBLK(mode):
        return "blockdev"
    return "unknown"


def xattr_compared(name: str) -> bool:
    if name == "security.selinux":
        return False  # label is assigned by policy on the destination
    if name.startswith("user.") or name.startswith("system.posix_acl_"):
        return True
    return IS_ROOT and (name.startswith("trusted.") or name.startswith("security."))


def read_xattrs(full: bytes) -> tuple[dict, list]:
    """Return ({name: sha256(value)} for compared names, [uncompared names])."""
    out, skipped = {}, []
    try:
        names = os.listxattr(full, follow_symlinks=False)
    except OSError:
        return out, skipped
    for n in sorted(names):
        if not xattr_compared(n):
            skipped.append(n)
            continue
        try:
            out[n] = hashlib.sha256(os.getxattr(full, n, follow_symlinks=False)).hexdigest()
        except OSError:
            skipped.append(n)
    return out, skipped


SNAP_FIELDS = ("mode", "uid", "gid", "size", "mtime_ns", "ctime_ns", "ino", "nlink", "dev")


@dataclass
class Scan:
    root: bytes
    is_dir: bool = True
    entries: dict = field(default_factory=dict)   # rel -> comparable metadata
    snap: dict = field(default_factory=dict)      # rel -> change-detection tuple
    files: list = field(default_factory=list)     # regular files (rel), sorted
    counts: dict = field(default_factory=dict)
    logical_bytes: int = 0
    disk_bytes: int = 0
    hardlink_groups: list = field(default_factory=list)
    external_hardlinks: list = field(default_factory=list)
    specials: list = field(default_factory=list)
    devices: list = field(default_factory=list)
    nested_mounts: list = field(default_factory=list)
    sparse: list = field(default_factory=list)
    abs_symlinks: list = field(default_factory=list)
    escaping_symlinks: list = field(default_factory=list)
    dangling: list = field(default_factory=list)
    unreadable: list = field(default_factory=list)
    ownership_problems: list = field(default_factory=list)
    unpreservable_xattrs: list = field(default_factory=list)
    selinux_labels: int = 0
    setid: list = field(default_factory=list)
    newline_names: list = field(default_factory=list)
    non_utf8_names: list = field(default_factory=list)
    git_repos: list = field(default_factory=list)
    errors: list = field(default_factory=list)


def scan_tree(root: bytes, *, progress_label: str = "") -> Scan:
    root = b(root)
    sc = Scan(root=root)
    st_root = lstat_entry(root)
    sc.is_dir = stat.S_ISDIR(st_root.st_mode)
    root_dev = st_root.st_dev
    my_groups = set(os.getgroups()) | {os.getegid()}
    inode_paths: dict = {}
    inode_nlink: dict = {}
    seen_inodes: set = set()
    counts = dict(files=0, directories=0, symlinks=0, dangling_symlinks=0, specials=0,
                  hardlink_groups=0, hardlinked_paths=0, newline_names=0, entries=0)
    last_beat = time.monotonic()
    stack = [b"."]
    while stack:
        rel = stack.pop()
        full = root if rel == b"." else os.path.join(root, rel)
        try:
            st = lstat_entry(full)
        except OSError as e:
            sc.errors.append(f"{disp(rel)}: {e.strerror}")
            sc.unreadable.append(rel)
            continue
        counts["entries"] += 1
        if progress_label and time.monotonic() - last_beat > 10:
            heartbeat(f"  … scanning {progress_label}: {counts['entries']:,} entries")
            last_beat = time.monotonic()
        mode = st.st_mode
        t = ftype(mode)
        name = os.path.basename(rel)
        if b"\n" in rel and rel not in sc.newline_names and b"\n" in name:
            sc.newline_names.append(rel)
            counts["newline_names"] += 1
        try:
            name.decode("utf-8")
        except UnicodeDecodeError:
            sc.non_utf8_names.append(rel)

        meta = {"type": t, "mode": mode, "uid": st.st_uid, "gid": st.st_gid, "mtime_ns": st.st_mtime_ns}
        xa, skipped = read_xattrs(full)
        meta["xattrs"] = xa
        if "security.selinux" in skipped:
            sc.selinux_labels += 1
        bad_x = [n for n in skipped if n != "security.selinux"]
        if bad_x:
            sc.unpreservable_xattrs.append((rel, bad_x))
        if not IS_ROOT and (st.st_uid != os.geteuid() or st.st_gid not in my_groups):
            sc.ownership_problems.append(rel)
        if mode & (stat.S_ISUID | stat.S_ISGID) and t == "file":
            sc.setid.append(rel)

        key = (st.st_dev, st.st_ino)
        if key not in seen_inodes:
            seen_inodes.add(key)
            sc.disk_bytes += (getattr(st, "st_blocks", 0) or 0) * 512
            if t == "file":
                sc.logical_bytes += st.st_size
        if t != "dir" and st.st_nlink > 1:
            inode_paths.setdefault(key, []).append(rel)
            inode_nlink[key] = st.st_nlink

        if t == "file":
            counts["files"] += 1
            meta["size"] = st.st_size
            sc.files.append(rel)
            blocks = getattr(st, "st_blocks", None)
            if blocks is not None and blocks * 512 + 64 * 1024 < st.st_size:
                sc.sparse.append(rel)
            if not os.access(full, os.R_OK):
                sc.unreadable.append(rel)
        elif t == "symlink":
            counts["symlinks"] += 1
            target = os.readlink(full)
            meta["target"] = target
            if not os.path.exists(full):
                counts["dangling_symlinks"] += 1
                sc.dangling.append(rel)
            if target.startswith(b"/"):
                sc.abs_symlinks.append(rel)
            else:
                base = os.path.dirname(rel) if rel != b"." else b""
                norm = os.path.normpath(os.path.join(base, target))
                if norm == b".." or norm.startswith(b"../"):
                    sc.escaping_symlinks.append(rel)
        elif t == "dir":
            if rel != b".":
                counts["directories"] += 1
            if st.st_dev != root_dev:
                sc.nested_mounts.append(rel)
                sc.entries[rel] = meta
                sc.snap[rel] = _snap_tuple(st)
                continue  # never descend into another filesystem
            if not os.access(full, os.R_OK | os.X_OK):
                sc.unreadable.append(rel)
            else:
                try:
                    names = sorted(os.listdir(full))
                except OSError as e:
                    sc.errors.append(f"{disp(rel)}: {e.strerror}")
                    sc.unreadable.append(rel)
                    names = []
                inside_gitdir = b".git" in rel.split(b"/")
                if not inside_gitdir:
                    nameset = set(names)
                    if b".git" in nameset:
                        sc.git_repos.append(rel)
                    elif {b"HEAD", b"objects", b"refs"} <= nameset and name != b".git":
                        sc.git_repos.append(rel)  # bare repository
                for n in reversed(names):
                    stack.append(n if rel == b"." else os.path.join(rel, n))
        else:
            counts["specials"] += 1
            sc.specials.append((rel, t))
            if t in ("chardev", "blockdev"):
                meta["rdev"] = st.st_rdev
                sc.devices.append(rel)
        sc.entries[rel] = meta
        sc.snap[rel] = _snap_tuple(st)

    groups = []
    for key, paths in inode_paths.items():
        if len(paths) > 1:
            groups.append(tuple(sorted(paths)))
        if inode_nlink[key] > len(paths):
            sc.external_hardlinks.append(paths[0])
    sc.hardlink_groups = sorted(groups)
    counts["hardlink_groups"] = len(groups)
    counts["hardlinked_paths"] = sum(len(g) for g in groups)
    sc.files.sort()
    sc.git_repos.sort()
    sc.counts = counts
    return sc


def _snap_tuple(st) -> tuple:
    return (st.st_mode, st.st_uid, st.st_gid, st.st_size, st.st_mtime_ns,
            st.st_ctime_ns, st.st_ino, st.st_nlink, st.st_dev)


def diff_snapshots(a: dict, b_: dict, limit: int = 200) -> dict:
    out = {}
    for rel in sorted(set(a) | set(b_)):
        if rel not in b_:
            out[rel_str(rel)] = ["removed"]
        elif rel not in a:
            out[rel_str(rel)] = ["added"]
        elif a[rel] != b_[rel]:
            out[rel_str(rel)] = [f for f, x, y in zip(SNAP_FIELDS, a[rel], b_[rel]) if x != y]
        if len(out) >= limit:
            out["…"] = ["more changes truncated"]
            break
    return out


# --------------------------------------------------------------------------- #
# Open writers via /proc
# --------------------------------------------------------------------------- #
def find_open_writers(roots: list[bytes], inodes: set | None = None) -> tuple[list[dict], int]:
    """Processes holding files open for writing under any root.  Matches by path, by
    canonical (bind-mount-proof) location, and by (device, inode) of the open file."""
    roots = [r for r in roots if r]
    mounts = read_mounts()
    croots = [canon(r, mounts) for r in roots]
    inodes = inodes or set()
    writers, inaccessible = [], 0
    me = os.getpid()
    for pid_s in os.listdir(b"/proc"):
        if not pid_s.isdigit():
            continue
        fd_dir = b"/proc/" + pid_s + b"/fd"
        try:
            fds = os.listdir(fd_dir)
        except PermissionError:
            inaccessible += 1
            continue
        except OSError:
            continue
        for fd in fds:
            link = fd_dir + b"/" + fd
            try:
                target = os.readlink(link)
            except OSError:
                continue
            if not target.startswith(b"/"):
                continue
            try:
                with open(b"/proc/" + pid_s + b"/fdinfo/" + fd, "rb") as f:
                    m = re.search(rb"flags:\s*([0-7]+)", f.read())
                flags = int(m.group(1), 8) if m else 0
            except OSError:
                continue
            if flags & os.O_ACCMODE not in (os.O_WRONLY, os.O_RDWR):
                continue
            clean = target[:-10] if target.endswith(b" (deleted)") else target
            hit = any(is_inside(clean, r) for r in roots)
            if not hit and inodes:
                try:
                    st = os.stat(link)
                    hit = (st.st_dev, st.st_ino) in inodes
                except OSError:
                    pass
            if not hit and clean.startswith(b"/") and not clean.startswith((b"/proc/", b"/dev/", b"/sys/")):
                try:
                    c = canon(clean, mounts)
                    hit = any(c[0] == cr[0] and is_inside(c[1], cr[1]) for cr in croots)
                except OSError:
                    pass
            if not hit:
                continue
            try:
                with open(b"/proc/" + pid_s + b"/comm", "rb") as f:
                    comm = f.read().strip().decode(errors="replace")
            except OSError:
                comm = "?"
            writers.append({"pid": int(pid_s), "comm": comm, "path": disp(target),
                            "self": int(pid_s) == me})
        # Shared writable memory mappings keep writing even after the fd is closed.
        try:
            with open(b"/proc/" + pid_s + b"/maps", "rb") as f:
                maps = f.read()
        except OSError:
            maps = b""
        for line in maps.splitlines():
            parts = line.split(None, 5)
            if len(parts) < 6 or len(parts[1]) < 4 or parts[1][1:2] != b"w" or parts[1][3:4] != b"s":
                continue
            path = parts[5].strip()
            if path.endswith(b" (deleted)"):
                path = path[:-10]
            hit = path.startswith(b"/") and any(is_inside(path, r) for r in roots)
            if not hit and inodes:
                try:
                    maj, mnr = parts[3].split(b":")
                    hit = (os.makedev(int(maj, 16), int(mnr, 16)), int(parts[4])) in inodes
                except ValueError:
                    pass
            if hit:
                try:
                    with open(b"/proc/" + pid_s + b"/comm", "rb") as f:
                        comm = f.read().strip().decode(errors="replace")
                except OSError:
                    comm = "?"
                writers.append({"pid": int(pid_s), "comm": comm, "path": disp(path) + " (shared writable mmap)",
                                "self": int(pid_s) == me})
                break
    return writers, inaccessible


# --------------------------------------------------------------------------- #
# Path guards
# --------------------------------------------------------------------------- #
def home_dir() -> bytes:
    h = os.environ.get("HOME") or os.path.expanduser("~")
    return os.path.realpath(b(h))


def dangerous_reason(p: bytes, label: str, mounts: list[dict] | None = None) -> str | None:
    if p in FORBIDDEN_EXACT:
        return f"{label} {disp(p)} is a protected system/top-level location"
    for t in FORBIDDEN_TREES:
        if is_inside(p, t):
            return f"{label} {disp(p)} is inside protected system tree {disp(t)}"
    # Same checks by canonical identity, so bind mounts / aliases cannot sneak past.
    mounts = read_mounts() if mounts is None else mounts
    cp = canon(p, mounts)
    for e in FORBIDDEN_EXACT:
        if os.path.isdir(e) and canon(e, mounts) == cp:
            return f"{label} {disp(p)} is another path to protected location {disp(e)}"
    for t in FORBIDDEN_TREES:
        if os.path.isdir(t):
            ct = canon(t, mounts)
            if ct[0] == cp[0] and is_inside(cp[1], ct[1]):
                return f"{label} {disp(p)} reaches protected system tree {disp(t)} through another mount/alias"
    return None


def _inode_nested(inner: bytes, outer: bytes) -> bool:
    """True if any existing ancestor of `inner` is the same inode as `outer`."""
    try:
        o = os.stat(outer)
    except OSError:
        return False
    p = nearest_existing(inner)
    while True:
        try:
            st = os.stat(p)
            if (st.st_dev, st.st_ino) == (o.st_dev, o.st_ino):
                return True
        except OSError:
            pass
        parent = os.path.dirname(p)
        if parent == p:
            return False
        p = parent


def nested(inner: bytes, outer: bytes, mounts: list[dict]) -> bool:
    """inner is outer or below it — by path, by canonical (bind-mount-proof) identity, or by inode."""
    return is_inside(inner, outer) or canon_inside(inner, outer, mounts) or _inode_nested(inner, outer)


def check_path_guards(src: bytes, dst: bytes, *, allow_home: bool, src_given: bytes,
                      dst_given: bytes) -> list[str]:
    reasons = []
    mounts = read_mounts()
    for p, label in ((src, "source"), (dst, "destination")):
        r = dangerous_reason(p, label, mounts)
        if r:
            reasons.append(r)
    if reasons:
        return reasons
    home = home_dir()
    def is_home_like(p):
        return (p == home or nested(home, p, mounts) or os.path.dirname(p) == b"/home"
                or canon(p, mounts) == canon(home, mounts))
    if is_home_like(src) and not allow_home:
        reasons.append(f"source {disp(src)} is (or contains) your entire home directory "
                       f"{disp(home)}; pass --allow-entire-home only if you really mean it")
    if is_home_like(dst):
        reasons.append(f"destination {disp(dst)} is (or contains) your home directory — never allowed")
    if src == dst or canon(src, mounts) == canon(dst, mounts):
        reasons.append("source and destination resolve to the same location")
    elif nested(dst, src, mounts):
        reasons.append("destination is nested inside the source (directly or via a symlink/bind mount)")
    elif nested(src, dst, mounts):
        reasons.append("source is nested inside the destination (directly or via a symlink/bind mount)")
    return reasons


def pair_id(src, dst) -> str:
    s = os.path.realpath(b(src))
    d = os.path.realpath(b(dst))
    return hashlib.sha256(s + b"\0" + d).hexdigest()[:16]


def pair_lock_path(records, src, dst) -> Path:
    """Lock keyed by DESTINATION, so no two runs (from any source) can write into it at once."""
    d = os.path.realpath(b(dst))
    return Path(records) / "locks" / f"dest-{hashlib.sha256(d).hexdigest()[:16]}.lock"


# --------------------------------------------------------------------------- #
# rsync commands
# --------------------------------------------------------------------------- #
_RSYNC_HELP_CACHE: str | None = None


def rsync_supports(flag: str) -> bool:
    global _RSYNC_HELP_CACHE
    if _RSYNC_HELP_CACHE is None:
        try:
            _RSYNC_HELP_CACHE = subprocess.run(["rsync", "--help"], capture_output=True, text=True,
                                               timeout=30).stdout
        except (OSError, subprocess.SubprocessError):
            _RSYNC_HELP_CACHE = ""
    return flag in _RSYNC_HELP_CACHE


def priority_prefix() -> list[str]:
    """Low CPU and I/O priority so copying does not disturb active development."""
    prefix = []
    if shutil.which("ionice"):
        prefix += ["ionice", "-c2", "-n7"]
    if shutil.which("nice"):
        prefix += ["nice", "-n19"]
    return prefix


def _path_args(src: bytes, dst: bytes, is_dir: bool) -> list[str]:
    s, d = os.fsdecode(src), os.fsdecode(dst)
    if is_dir:
        s, d = s.rstrip("/") + "/", d.rstrip("/") + "/"
    return [s, d]


def build_copy_command(src: bytes, dst: bytes, *, is_dir: bool, resume: bool, temp_dir,
                       bwlimit, allow_specials: bool, log_file=None, progress: bool = False) -> list[str]:
    # --modify-window=-1: timestamps must match to the nanosecond.  Without it rsync treats
    # times in the same whole second as equal and silently skips fixing directory mtimes.
    cmd = priority_prefix() + ["rsync", "-a", "-H", "-A", "-X", "--numeric-ids", "--modify-window=-1"]
    if not allow_specials:
        cmd += ["--no-specials", "--no-devices"]
    if rsync_supports("--open-noatime"):
        cmd.append("--open-noatime")
    if resume:
        cmd.append("--checksum")          # re-check every destination file by content
    if temp_dir:
        cmd.append(f"--temp-dir={os.fsdecode(temp_dir)}")
    if bwlimit:
        cmd.append(f"--bwlimit={int(bwlimit)}")
    if log_file:
        cmd += [f"--log-file={os.fsdecode(log_file)}", "--log-file-format=%i %n%L"]
    if progress:
        cmd.append("--info=progress2")
    cmd.append("--")
    cmd += _path_args(src, dst, is_dir)
    assert_safe_rsync(cmd, dry_run=False)
    return cmd


def build_proof_command(src: bytes, dst: bytes, *, is_dir: bool) -> list[str]:
    cmd = priority_prefix() + ["rsync", "--dry-run", "-a", "-H", "-A", "-X", "--numeric-ids",
                               "--modify-window=-1", "--checksum", "--itemize-changes"]
    if rsync_supports("--open-noatime"):
        cmd.append("--open-noatime")
    cmd.append("--")
    cmd += _path_args(src, dst, is_dir)
    assert_safe_rsync(cmd, dry_run=True)
    return cmd


def assert_safe_rsync(cmd: list[str], *, dry_run: bool) -> None:
    """Hard guard: refuse any rsync invocation that could delete, prune, dereference or skip."""
    if "rsync" not in cmd:
        raise SafetyError("not an rsync command")
    args = cmd[cmd.index("rsync") + 1:]
    if "--" not in args:
        raise SafetyError("rsync command must separate options from paths with --")
    sep = args.index("--")
    opts, paths = args[:sep], args[sep + 1:]
    if len(paths) != 2:
        raise SafetyError("rsync command must have exactly one source and one destination")
    for o in opts:
        name = o.split("=", 1)[0]
        if name.startswith("--del") or name.startswith("--remove") or name in RSYNC_FORBIDDEN_LONG:
            raise SafetyError(f"forbidden rsync option {o}")
        if name == "--modify-window" and o != "--modify-window=-1":
            raise SafetyError("timestamps must be compared to the nanosecond (--modify-window=-1 only)")
        if o.startswith("-@"):
            raise SafetyError("use --modify-window=-1 explicitly")
        if o.startswith("-") and not o.startswith("--"):
            bad = set(o[1:]) & RSYNC_FORBIDDEN_SHORT
            if bad:
                raise SafetyError(f"forbidden rsync short option(s) {''.join(sorted(bad))} in {o}")
    if dry_run and not ("-n" in opts or "--dry-run" in opts):
        raise SafetyError("proof command must be a dry run")


def _child_setup(parent_pid: int):
    def _fn():
        # If this tool dies (even by SIGKILL), rsync is told to stop: no orphaned writer.
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            libc.prctl(1, int(signal.SIGTERM), 0, 0, 0)  # PR_SET_PDEATHSIG
        except Exception:
            pass
        if os.getppid() != parent_pid:
            os._exit(99)
    return _fn


def _stop_child(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    try:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=20)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    except ProcessLookupError:
        pass


def run_copy(cmd: list[str]) -> int:
    """Run the rsync copy.  Returns its exit code.  Interrupts stop rsync and re-raise."""
    proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, preexec_fn=_child_setup(os.getpid()))
    try:
        return proc.wait()
    except BaseException:
        _stop_child(proc)
        raise


def run_proof(cmd: list[str]) -> tuple[int, str, str]:
    proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, preexec_fn=_child_setup(os.getpid()))
    try:
        out, err = proc.communicate()
    except BaseException:
        _stop_child(proc)
        raise
    return proc.returncode, out.decode("utf-8", "backslashreplace"), err.decode("utf-8", "backslashreplace")


RSYNC_EXIT_MEANING = {
    0: "success", 1: "syntax or usage error", 2: "protocol incompatibility",
    3: "errors selecting input/output files, dirs", 4: "requested action not supported",
    5: "error starting client-server protocol", 6: "daemon unable to append to log-file",
    10: "error in socket I/O", 11: "error in file I/O (disk full?)", 12: "error in rsync protocol data stream",
    13: "errors with program diagnostics", 14: "error in IPC code", 20: "received SIGUSR1 or SIGINT",
    21: "some error returned by waitpid()", 22: "error allocating core memory buffers",
    23: "partial transfer due to error", 24: "partial transfer due to vanished source files",
    25: "--max-delete limit stopped deletions", 30: "timeout in data send/receive",
    35: "timeout waiting for daemon connection",
}


# --------------------------------------------------------------------------- #
# SHA-256 manifests (with destination read-back)
# --------------------------------------------------------------------------- #
def _open_ro(full: bytes) -> int:
    base = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    noatime = getattr(os, "O_NOATIME", 0)
    if noatime:
        try:
            return os.open(full, base | noatime)
        except PermissionError:
            pass
    return os.open(full, base)


def build_manifest(scan: Scan, out_path: Path, *, readback: bool, label: str) -> dict:
    """Hash every regular file.  readback=True drops cached pages before reading so the
    bytes come from the device where the kernel allows it."""
    root = scan.root
    entries: dict[bytes, tuple[int, str]] = {}
    by_inode: dict = {}
    changed: list[str] = []
    errors: list[str] = []
    total = len(scan.files)
    files_read = bytes_read = cache_drops = 0
    buf = bytearray(HASH_CHUNK)
    mv = memoryview(buf)
    fadvise = getattr(os, "posix_fadvise", None)
    if readback:
        os.sync()
    t0 = last = time.monotonic()
    with open(out_path, "w", encoding="ascii") as out:
        for i, rel in enumerate(scan.files, 1):
            full = root if rel == b"." else os.path.join(root, rel)
            try:
                fd = _open_ro(full)
            except OSError as e:
                errors.append(f"{rel_str(rel)}: {e.strerror}")
                continue
            try:
                st = os.fstat(fd)
                if st.st_size != scan.entries[rel].get("size"):
                    changed.append(rel_str(rel))
                key = (st.st_dev, st.st_ino)
                if key in by_inode:
                    size, digest = by_inode[key]
                else:
                    if readback and fadvise:
                        try:
                            fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
                            cache_drops += 1
                        except OSError:
                            pass
                    h = hashlib.sha256()
                    size = 0
                    while True:
                        n = os.readv(fd, [mv])
                        if not n:
                            break
                        h.update(mv[:n])
                        size += n
                        if time.monotonic() - last > 10:
                            heartbeat(f"  … hashing {label}: {i:,}/{total:,} files")
                            last = time.monotonic()
                    digest = h.hexdigest()
                    by_inode[key] = (size, digest)
                    files_read += 1
                    bytes_read += size
                    if readback and fadvise:
                        try:
                            fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
                        except OSError:
                            pass
            except OSError as e:
                errors.append(f"{rel_str(rel)}: {e.strerror}")
                continue
            finally:
                os.close(fd)
            entries[rel] = (size, digest)
            out.write(json.dumps({"path": rel_str(rel), "size": size, "sha256": digest},
                                 ensure_ascii=True) + "\n")
    return {"entries": entries, "manifest_sha256": sha256_file_bytes(out_path),
            "files_read": files_read, "unique_inodes": len(by_inode), "paths": len(entries),
            "bytes_read": bytes_read, "cache_drops": cache_drops,
            "changed_during_read": changed, "errors": errors,
            "elapsed_seconds": round(time.monotonic() - t0, 3)}


def compare_manifests(src_m: dict, dst_m: dict) -> dict:
    s, d = src_m["entries"], dst_m["entries"]
    missing = sorted(rel_str(k) for k in s.keys() - d.keys())
    extra = sorted(rel_str(k) for k in d.keys() - s.keys())
    mismatched = sorted(rel_str(k) for k in s.keys() & d.keys() if s[k] != d[k])
    ok = (not missing and not extra and not mismatched and not src_m["errors"] and not dst_m["errors"]
          and not src_m["changed_during_read"] and not dst_m["changed_during_read"]
          and src_m["manifest_sha256"] == dst_m["manifest_sha256"])
    return {"ok": ok, "missing": missing[:500], "extra": extra[:500], "mismatched": mismatched[:500],
            "hashed_files": len(s), "source_manifest_sha256": src_m["manifest_sha256"],
            "destination_manifest_sha256": dst_m["manifest_sha256"],
            "read_errors": src_m["errors"] + dst_m["errors"],
            "changed_during_read": src_m["changed_during_read"] + dst_m["changed_during_read"]}


# --------------------------------------------------------------------------- #
# Structural comparison
# --------------------------------------------------------------------------- #
META_FIELDS = ("type", "mode", "uid", "gid", "mtime_ns", "size", "target", "rdev", "xattrs")
COUNT_FIELDS = ("files", "directories", "symlinks", "dangling_symlinks", "specials",
                "hardlink_groups", "hardlinked_paths")


def compare_structure(s: Scan, d: Scan) -> dict:
    missing = sorted(rel_str(k) for k in s.entries.keys() - d.entries.keys())
    extra = sorted(rel_str(k) for k in d.entries.keys() - s.entries.keys())
    md = {}
    for k in sorted(s.entries.keys() & d.entries.keys()):
        a, c = s.entries[k], d.entries[k]
        diffs = [f for f in META_FIELDS if a.get(f) != c.get(f)]
        if diffs:
            md[rel_str(k)] = diffs
    counts_src = {k: s.counts.get(k) for k in COUNT_FIELDS}
    counts_dst = {k: d.counts.get(k) for k in COUNT_FIELDS}
    hardlinks_ok = s.hardlink_groups == d.hardlink_groups
    ok = (not missing and not extra and not md and hardlinks_ok and counts_src == counts_dst
          and s.logical_bytes == d.logical_bytes and not d.unreadable)
    return {"ok": ok, "counts_source": counts_src, "counts_destination": counts_dst,
            "logical_bytes_source": s.logical_bytes, "logical_bytes_destination": d.logical_bytes,
            "on_disk_bytes_source": s.disk_bytes, "on_disk_bytes_destination": d.disk_bytes,
            "missing_in_destination": missing[:500], "extra_in_destination": extra[:500],
            "metadata_mismatches": dict(list(md.items())[:500]),
            "metadata_mismatch_count": len(md), "hardlinks_ok": hardlinks_ok,
            "destination_unreadable": [rel_str(r) for r in d.unreadable][:100],
            "fields_compared": list(META_FIELDS)}


# --------------------------------------------------------------------------- #
# Git (strictly read-only)
# --------------------------------------------------------------------------- #
GIT_SNAPSHOT_COMMANDS = {
    "is_bare": ["rev-parse", "--is-bare-repository"],
    "shallow": ["rev-parse", "--is-shallow-repository"],
    "head_ref": ["symbolic-ref", "-q", "HEAD"],
    "head": ["rev-parse", "-q", "--verify", "HEAD^{commit}"],
    "roots": ["rev-list", "--max-parents=0", "HEAD"],
    "refs": ["for-each-ref", "--format=%(objectname) %(refname)"],
    "remotes": ["remote", "-v"],
    "index": ["ls-files", "--stage", "-z"],
    # submodules are snapshotted as repositories of their own, so status never recurses
    "status": ["status", "--porcelain=v2", "-z", "--untracked-files=all", "--ignore-submodules=all"],
    "worktrees": ["worktree", "list", "--porcelain"],
    "submodules": ["config", "-f", ".gitmodules", "--get-regexp", r"^submodule\."],
    "objects": ["count-objects", "-v"],
}
_URL_USERINFO = re.compile(r"(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*://)[^/\s?#]*@")
# URL path segments that look like tokens: long, mixing letters and digits, or containing "token"
_URL_TOKENISH = re.compile(r"/(?=[^/\s]*\d)(?=[^/\s]*[A-Za-z])[A-Za-z0-9_\-]{20,}(?=/|\s|$)"
                           r"|/[^/\s]*(?:token|secret|passw)[^/\s]*(?=/|\s|$)", re.I)
_URL_QUERY = re.compile(r"(?P<pre>[A-Za-z][A-Za-z0-9+.-]*://[^\s?#]*)[?#]\S*")


def redact_credentials(text: str) -> str:
    """Strip URL userinfo (user:password@, token@) and any query/fragment from URLs."""
    text = _URL_USERINFO.sub(lambda m: m.group("scheme") + "***@", text)
    text = _URL_QUERY.sub(lambda m: m.group("pre") + "?***", text)
    return _URL_TOKENISH.sub("/***", text)


def git_env() -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update({
        "GIT_OPTIONAL_LOCKS": "0",        # git status must not refresh/write the index
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "safe.directory",
        "GIT_CONFIG_VALUE_0": "*",
        "LC_ALL": "C",
    })
    return env


GIT_BASE_OVERRIDES = ["-c", "core.fsmonitor=false", "-c", "gc.auto=0", "-c", "maintenance.auto=false",
                      "-c", "core.hooksPath=/dev/null", "-c", "status.submoduleSummary=false",
                      "-c", "diff.external=", "-c", "core.pager=cat", "-c", "protocol.allow=never"]


def git_run(repo: bytes, args: list[str], extra: list[str] | None = None) -> tuple[int, bytes]:
    cmd = ["git", "--no-optional-locks", *GIT_BASE_OVERRIDES, *(extra or []),
           "-C", os.fsdecode(repo), *args]
    try:
        r = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, env=git_env(),
                           timeout=1800, preexec_fn=_child_setup(os.getpid()))
        return r.returncode, r.stdout
    except subprocess.TimeoutExpired:
        return -1, b""


def _parse_status(raw: bytes) -> dict:
    counts = dict(staged=0, tracked_modified=0, untracked=0, unmerged=0, renamed=0)
    parts = raw.split(b"\0")
    i = 0
    while i < len(parts):
        e = parts[i]
        if e.startswith(b"1 ") or e.startswith(b"2 "):
            xy = e[2:4]
            if xy[:1] != b".":
                counts["staged"] += 1
            if xy[1:2] != b".":
                counts["tracked_modified"] += 1
            if e.startswith(b"2 "):
                counts["renamed"] += 1
                i += 1
        elif e.startswith(b"u "):
            counts["unmerged"] += 1
        elif e.startswith(b"? "):
            counts["untracked"] += 1
        i += 1
    return counts


def git_snapshot(repo: bytes, roots: tuple) -> dict:
    """Read-only facts about one repository.  Raw outputs are compared by digest only;
    remotes are stored redacted; absolute paths are normalised to <ROOT>."""
    snap: dict = {"digests": {}, "rc": {}}
    raw_all = {}
    extra = filter_neutralisers(repo)
    snap["filter_drivers_neutralised"] = len(extra) // 8
    for key, args in GIT_SNAPSHOT_COMMANDS.items():
        rc, out = git_run(repo, args, extra)
        if key == "objects":   # keep object counts; drop on-disk sizes (differ across filesystems)
            out = b"\n".join(l for l in out.splitlines() if not l.startswith((b"size", b"size-")))
        if key == "worktrees":
            for r in sorted(roots, key=len, reverse=True):
                out = out.replace(r.rstrip(b"/"), b"<ROOT>")
        raw_all[key] = out
        snap["rc"][key] = rc
        snap["digests"][key] = hashlib.sha256(out).hexdigest()
    txt = lambda k: raw_all[k].decode("utf-8", "backslashreplace").strip()
    snap["head_ref"] = txt("head_ref") or None
    snap["head"] = txt("head") or None
    snap["bare"] = txt("is_bare") == "true"
    snap["root_commits"] = txt("roots").split()[:5]
    refs = txt("refs").splitlines()
    snap["ref_count"] = len(refs)
    snap["refs"] = refs[:300]
    snap["remotes"] = redact_credentials(txt("remotes")).splitlines()
    snap["index_entries"] = raw_all["index"].count(b"\0")
    snap["counts"] = _parse_status(raw_all["status"])
    snap["worktrees"] = redact_credentials(txt("worktrees")).splitlines()[:50]
    snap["submodules"] = [l.split(" ", 1)[0] for l in txt("submodules").splitlines()][:100]
    return snap


def filter_neutralisers(repo: bytes) -> list[str]:
    """Git runs clean/smudge filter drivers from repository/global config while hashing
    worktree files (e.g. during `git status`).  That would execute arbitrary commands —
    possibly as root, possibly writing into either tree.  Every configured driver is
    overridden with an empty command so no filter can run."""
    rc, out = git_run(repo, ["config", "--null", "--name-only", "--get-regexp", r"^filter\."])
    names = set()
    for key in out.split(b"\0"):
        key = key.decode("utf-8", "surrogateescape").strip()
        if key.startswith("filter.") and key.count(".") >= 2:
            names.add(key[len("filter."):key.rindex(".")])
    extra = []
    for n in sorted(names):
        extra += ["-c", f"filter.{n}.clean=", "-c", f"filter.{n}.smudge=",
                  "-c", f"filter.{n}.process=", "-c", f"filter.{n}.required=false"]
    return extra


def git_not_independent(repo_full: bytes) -> str | None:
    """Reason the copied repo's git view would come from the SAME external place as the
    source's (absolute gitdir link, or core.worktree pointing elsewhere), else None."""
    gitfile = os.path.join(repo_full, b".git")
    try:
        if os.path.isfile(gitfile) and not os.path.islink(gitfile) and os.lstat(gitfile).st_size < 4096:
            with open(gitfile, "rb") as f:
                line = f.read().strip()
            if line.startswith(b"gitdir: /"):
                return ("its .git file holds an absolute gitdir path, so source and copy read the same "
                        "git metadata")
    except OSError:
        pass
    rc, out = git_run(repo_full, ["config", "--get", "core.worktree"])
    if rc == 0 and out.strip():
        return "core.worktree points at a separate working tree, which both sides share"
    return None


def git_points_outside(repo_full: bytes, src_root: bytes) -> list[str]:
    """Absolute gitdir links that point at the source tree (worktrees/submodules)."""
    notes = []
    gitfile = os.path.join(repo_full, b".git")
    try:
        if os.path.isfile(gitfile) and not os.path.islink(gitfile):
            st = os.lstat(gitfile)
            if st.st_size < 4096:
                with open(gitfile, "rb") as f:
                    line = f.read().strip()
                if line.startswith(b"gitdir: /"):
                    notes.append(".git file uses an absolute gitdir path")
    except OSError:
        pass
    wt = os.path.join(repo_full, b".git", b"worktrees")
    if os.path.isdir(wt):
        notes.append("repository has linked worktrees whose metadata holds absolute paths "
                     "to the ORIGINAL location")
    return notes


def compare_git(src_root: bytes, dst_root: bytes, repos: list[bytes]) -> dict:
    if not repos:
        return {"ok": True, "repos": [], "note": "no git repositories found"}
    if not shutil.which("git"):
        return {"ok": None, "repos": [rel_str(r) for r in repos],
                "note": "git is not installed: repositories were byte-verified but not git-compared"}
    results, warnings = [], []
    all_ok = True
    for rel in repos:
        s_full = src_root if rel == b"." else os.path.join(src_root, rel)
        d_full = dst_root if rel == b"." else os.path.join(dst_root, rel)
        s = git_snapshot(s_full, (src_root, dst_root))
        d = git_snapshot(d_full, (src_root, dst_root))
        diff_keys = [k for k in GIT_SNAPSHOT_COMMANDS
                     if s["digests"][k] != d["digests"][k] or s["rc"][k] != d["rc"][k]]
        why_not = git_not_independent(s_full)
        comparable = why_not is None
        ok = (not diff_keys) if comparable else None
        if ok is False:
            all_ok = False
        notes = git_points_outside(s_full, src_root)
        if not comparable:
            notes.append(f"not independently comparable: {why_not}")
        for n in notes:
            warnings.append(f"git repo {rel_str(rel)}: {n} — copy is byte-exact, but runtime use from the "
                            f"destination would need separate repair (cutover not implied)")
        results.append({"path": rel_str(rel), "ok": ok, "comparable": comparable, "differences": diff_keys,
                        "source": s, "destination": {"head": d["head"], "head_ref": d["head_ref"],
                                                     "ref_count": d["ref_count"], "counts": d["counts"],
                                                     "digests": d["digests"]},
                        "notes": notes})
    return {"ok": all_ok, "repos": results, "warnings": warnings}


# --------------------------------------------------------------------------- #
# Records: pair state + lock
# --------------------------------------------------------------------------- #
def real_subdir(records, name: str) -> Path:
    """records/<name>, created if needed, and guaranteed to be a real directory — not a
    symlink someone planted to redirect records into a source tree."""
    p = Path(os.fsdecode(records)) / name
    try:
        p.mkdir(exist_ok=True)
        st = os.lstat(p)
    except OSError as e:
        raise Refusal(f"cannot prepare records subdirectory {disp(p)}: {e.strerror}")
    if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode):
        raise Refusal(f"records subdirectory {disp(p)} is not a real directory (symlink?) — refusing")
    return p


def acquire_lock(records: bytes, src: bytes, dst: bytes):
    """Exclusive per-destination lock inside the records directory (never follows symlinks)."""
    real_subdir(records, "locks")
    path = pair_lock_path(os.fsdecode(records), src, dst)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except OSError as e:
        raise Refusal(f"cannot open lock file {disp(path)} safely ({e.strerror}); "
                      "refusing (it may be a symlink)")
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        os.close(fd)
        raise Refusal(f"lock file {disp(path)} is not a regular file")
    fh = os.fdopen(fd, "a")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        fh.close()
        raise Refusal("another Cyclops Safe Copier run is already working on this destination")
    return _Locks([fh])


class _Locks:
    def __init__(self, handles):
        self.handles = handles

    def close(self):
        for h in self.handles:
            h.close()


def pair_state_path(records: bytes, src: bytes, dst: bytes) -> Path:
    return Path(os.fsdecode(records)) / "pairs" / f"{pair_id(src, dst)}.json"


def load_pair_state(records: bytes, src: bytes, dst: bytes) -> dict | None:
    p = pair_state_path(records, src, dst)
    try:
        return json.loads(p.read_text())
    except (OSError, ValueError):
        return None


def save_pair_state(records: bytes, src: bytes, dst: bytes, status: str, op_id: str) -> None:
    real_subdir(records, "pairs")
    p = pair_state_path(records, src, dst)
    st = load_pair_state(records, src, dst) or {"source": os.fsdecode(src),
                                                "destination": os.fsdecode(dst), "history": []}
    st["last_status"] = status
    st["last_operation"] = op_id
    st["updated_utc"] = now_utc()
    st["history"] = (st.get("history") or [])[-49:] + [{"operation": op_id, "status": status,
                                                        "utc": st["updated_utc"]}]
    write_json(p, st)


def resolve_records_dir(arg: str | None, dst: bytes) -> bytes:
    if arg:
        return os.path.realpath(b(os.path.abspath(os.path.expanduser(arg))))
    env = os.environ.get("CYCLOPS_SAFE_COPY_RECORDS")
    if env:
        return os.path.realpath(b(os.path.abspath(os.path.expanduser(env))))
    info = fs_info(nearest_existing(dst))
    mnt = b(info["mountpoint"])
    if mnt == b"/":
        return os.path.join(home_dir(), b".local", b"state", b"cyclops-safe-copy", b"records")
    if dst == mnt:
        raise Refusal(f"destination {disp(dst)} is the root of a filesystem; pass --records-dir "
                      "so records are kept outside it")
    return os.path.join(mnt, b"cyclops-safe-copy-records")


def records_dir_problems(records: bytes, src: bytes, dst: bytes) -> list[str]:
    out = []
    mounts = read_mounts()
    r = dangerous_reason(records, "records directory", mounts)
    if r:
        out.append(r)
    if nested(records, src, mounts) or nested(records, dst, mounts):
        out.append(f"records directory {disp(records)} must live outside both source and destination "
                   "(checked by path, inode and mount identity)")
    elif nested(src, records, mounts) or nested(dst, records, mounts):
        out.append(f"source/destination must not be inside the records directory {disp(records)}")
    return out


# --------------------------------------------------------------------------- #
# Preflight
# --------------------------------------------------------------------------- #
def _few(items, n=10, fmt=None) -> str:
    fmt = fmt or (lambda x: disp(x))
    shown = ", ".join(fmt(i) for i in items[:n])
    return shown + (f" … (+{len(items) - n} more)" if len(items) > n else "")


def preflight(args, mode: str, src: bytes, dst: bytes, con: Console, ctx: dict):
    blocking, warns, info = [], [], []
    src_fs = fs_info(src)
    dst_fs = fs_info(nearest_existing(dst))
    src_dev = os.stat(src).st_dev
    dst_dev = os.stat(nearest_existing(dst)).st_dev
    cross = src_dev != dst_dev
    con.section("PREFLIGHT")
    con.say(f"  source fs      : {src_fs['fstype']} on {src_fs['device']} "
            f"(mount {src_fs['mountpoint']}, dev {src_fs['st_dev']})")
    con.say(f"  destination fs : {dst_fs['fstype']} on {dst_fs['device']} "
            f"(mount {dst_fs['mountpoint']}, dev {dst_fs['st_dev']})")
    con.say(f"  {'cross-filesystem copy' if cross else 'same-filesystem copy'}")

    src_st = os.lstat(src)
    src_is_dir = stat.S_ISDIR(src_st.st_mode)
    if not (src_is_dir or stat.S_ISREG(src_st.st_mode)):
        raise Refusal(f"source {disp(src)} is neither a directory nor a regular file")
    dst_exists = os.path.lexists(dst)
    ps = ctx.get("pair")

    # ---- destination state -------------------------------------------------
    if mode in ("copy", "dry-run"):
        if dst_exists:
            hint = ""
            if ps and ps.get("last_status") == PS_VERIFIED:
                hint = " A previous copy of this pair was already VERIFIED — use --verify-only to re-check it."
            elif ps:
                hint = (f" Records show an earlier Cyclops copy of this pair ended as "
                        f"{ps.get('last_status')}: re-run with --resume to continue and re-check it.")
            else:
                hint = " If this is the continuation of an interrupted Cyclops copy, re-run with --resume."
            if src_is_dir and not os.path.isdir(dst):
                blocking.append(f"destination {disp(dst)} exists and is not a directory")
            elif src_is_dir:
                n = len(os.listdir(dst))
                if n:
                    blocking.append(f"destination directory is not empty ({n} entries) — refusing to "
                                    f"merge into existing data.{hint}")
            else:
                blocking.append(f"destination {disp(dst)} already exists — refusing to overwrite.{hint}")
        else:
            parent = os.path.dirname(dst)
            if not os.path.isdir(parent):
                blocking.append(f"destination parent {disp(parent)} does not exist — create it "
                                "yourself first (this tool will not create deep paths from a typo)")
    elif mode == "resume":
        if not dst_exists:
            blocking.append("nothing to resume: destination does not exist")
        elif src_is_dir != os.path.isdir(dst) or os.path.islink(dst):
            blocking.append("destination type does not match source type")
        if not ps:
            blocking.append("no record of an earlier Cyclops copy for this exact source → destination "
                            "pair in this records directory; --resume only continues copies this tool started")
        elif ps.get("last_status") == PS_VERIFIED:
            blocking.append("this pair was already VERIFIED — nothing to resume; use --verify-only to re-check it")
    elif mode == "verify-only":
        if not dst_exists:
            blocking.append("destination does not exist — nothing to verify")
        elif src_is_dir != os.path.isdir(dst):
            blocking.append("destination type does not match source type")

    # ---- source scan -----------------------------------------------------
    sc = scan_tree(src, progress_label="source")
    c = sc.counts
    con.say(f"  files {c['files']:,} · directories {c['directories']:,} · symlinks {c['symlinks']:,} "
            f"(dangling {c['dangling_symlinks']:,}) · specials {c['specials']:,} · "
            f"hardlink groups {c['hardlink_groups']:,}")
    con.say(f"  logical bytes {sc.logical_bytes:,} ({human(sc.logical_bytes)}) · "
            f"on-disk {sc.disk_bytes:,} ({human(sc.disk_bytes)})")

    if sc.unreadable:
        blocking.append(f"{len(sc.unreadable)} source entries cannot be read: {_few(sc.unreadable)}")
    for m in mounts_inside(src):
        rel = os.path.relpath(m, src)
        if rel not in sc.nested_mounts:
            sc.nested_mounts.append(rel)
    if sc.nested_mounts:
        blocking.append(f"source contains other mounted filesystems: {_few(sc.nested_mounts)}")
    if sc.specials:
        listing = _few(sc.specials, fmt=lambda x: f"{disp(x[0])} ({x[1]})")
        if not args.allow_special_files:
            blocking.append(f"source contains special files (fifo/socket/device): {listing}; "
                            "re-run with --allow-special-files to copy them as special files")
        else:
            warns.append(f"special files will be copied as special files: {listing}")
            if sc.devices and not IS_ROOT:
                blocking.append("device nodes can only be recreated by root")
    if sc.ownership_problems:
        blocking.append(f"{len(sc.ownership_problems)} entries are owned by another user/group; "
                        f"ownership cannot be preserved without root (e.g. sudo): {_few(sc.ownership_problems)}")
    if sc.unpreservable_xattrs:
        blocking.append(f"extended attributes that cannot be preserved without root: "
                        f"{_few(sc.unpreservable_xattrs, fmt=lambda x: disp(x[0]) + ' ' + ','.join(x[1]))}")
    if sc.selinux_labels:
        warns.append(f"{sc.selinux_labels} entries carry SELinux labels; labels are assigned by policy "
                     "on the destination and are not compared")
    if sc.sparse:
        warns.append(f"{len(sc.sparse)} sparse files will be written fully allocated (content identical): "
                     f"{_few(sc.sparse)}")
    if sc.external_hardlinks:
        warns.append(f"{len(sc.external_hardlinks)} hardlinked files also have links OUTSIDE the source; "
                     f"only links inside the tree are preserved: {_few(sc.external_hardlinks)}")
    if sc.abs_symlinks:
        warns.append(f"{len(sc.abs_symlinks)} absolute symlinks copied as-is (they still point at the "
                     f"original absolute targets): {_few(sc.abs_symlinks)}")
    if sc.escaping_symlinks:
        warns.append(f"{len(sc.escaping_symlinks)} relative symlinks point outside the tree: "
                     f"{_few(sc.escaping_symlinks)}")
    if sc.dangling:
        info.append(f"{len(sc.dangling)} dangling symlinks (copied as symlinks): {_few(sc.dangling)}")
    if sc.newline_names or sc.non_utf8_names:
        info.append(f"unusual names: {len(sc.newline_names)} containing newlines, "
                    f"{len(sc.non_utf8_names)} not valid UTF-8 (handled byte-exactly)")
    if sc.setid:
        info.append(f"{len(sc.setid)} setuid/setgid files: {_few(sc.setid)}")

    if src_fs["fstype"] not in KNOWN_GOOD_FS:
        warns.append(f"source filesystem type {src_fs['fstype']} is not on the known-good list")
    for label, info_ in (("source", src_fs), ("destination", dst_fs)):
        if info_["fstype"] in ALIASING_FS or info_["fstype"].startswith("fuse."):
            blocking.append(f"{label} is on a {info_['fstype']} filesystem: its paths can alias other "
                            "directories (layers/remote views) in ways nesting checks cannot prove safe — refusing")
    if dst_fs["fstype"] in UNSUPPORTED_DEST_FS:
        blocking.append(f"destination filesystem {dst_fs['fstype']} cannot hold Linux permissions, "
                        "ownership, symlinks/hardlinks or xattrs faithfully — refusing")
    elif dst_fs["fstype"] not in KNOWN_GOOD_FS:
        warns.append(f"destination filesystem type {dst_fs['fstype']} is not on the known-good list")

    # ---- open writers ----------------------------------------------------
    roots = [src] + ([dst] if dst_exists else [])
    src_inodes = {(t[8], t[6]) for t in sc.snap.values()}
    writers, inaccessible = find_open_writers(roots, src_inodes)
    if writers:
        lines = "; ".join(f"pid {w['pid']} ({w['comm']}) → {w['path']}" for w in writers[:20])
        blocking.append(f"{len(writers)} open writer(s) under source/destination — refusing to copy "
                        f"changing evidence: {lines}")
        con.say(f"  open writers   : {len(writers)} FOUND")
    else:
        con.say("  open writers   : none found")
    if inaccessible:
        warns.append(f"could not inspect open files of {inaccessible} processes owned by other users "
                     "(run as root to include them)")

    # ---- space -------------------------------------------------------------
    free_b, free_i = free_space(dst)
    margin = max(int(sc.logical_bytes * 0.05), 256 * MiB)
    need = sc.logical_bytes + c["entries"] * 4096 + margin
    existing = 0
    if mode == "resume" and dst_exists:
        existing = scan_tree(dst).disk_bytes
    if mode != "verify-only":
        need_now = max(0, need - existing)
        con.say(f"  free space     : {human(free_b)} available, {human(need_now)} required "
                f"(incl. margin {human(margin)})")
        if free_b < need_now:
            blocking.append(f"insufficient destination space: {human(free_b)} available but "
                            f"{human(need_now)} required including a {human(margin)} safety margin")
        if free_i is not None and free_i < c["entries"] + 1000:
            blocking.append(f"insufficient destination inodes: {free_i:,} free, "
                            f"{c['entries'] + 1000:,} required")

    # records (manifests are kept on the records disk, not in either tree)
    if mode != "dry-run" and ctx.get("records"):
        rec_need = c["files"] * 2 * (220 + 2 * (len(src) + 40)) + c["entries"] * 80 + 16 * MiB
        try:
            rec_free, _ = free_space(ctx["records"])
            if rec_free < rec_need:
                blocking.append(f"insufficient space for records/manifests: {human(rec_free)} free in the "
                                f"records directory, about {human(rec_need)} needed")
        except OSError as e:
            blocking.append(f"cannot check records directory space: {e.strerror}")

    # ---- git -----------------------------------------------------------------
    if sc.git_repos:
        con.say(f"  git repos      : {len(sc.git_repos)} ({_few(sc.git_repos, fmt=lambda r: rel_str(r))})")
    else:
        con.say("  git repos      : none")

    for i in info:
        con.say(f"  note: {i}")
    for w in warns:
        con.say(f"  WARNING: {w}")

    pf = {
        "source_fs": src_fs, "destination_fs": dst_fs, "cross_filesystem": cross,
        "source_is_dir": src_is_dir, "destination_existed": dst_exists,
        "counts": c, "logical_bytes": sc.logical_bytes, "on_disk_bytes": sc.disk_bytes,
        "free_bytes": free_b, "free_inodes": free_i, "required_bytes": need,
        "open_writers": writers, "processes_not_inspectable": inaccessible,
        "git_repositories": [rel_str(r) for r in sc.git_repos],
        "unusual": {
            "specials": [f"{rel_str(r)} ({t})" for r, t in sc.specials][:100],
            "nested_mounts": [rel_str(r) for r in sc.nested_mounts][:100],
            "sparse": [rel_str(r) for r in sc.sparse][:100],
            "external_hardlinks": [rel_str(r) for r in sc.external_hardlinks][:100],
            "absolute_symlinks": [rel_str(r) for r in sc.abs_symlinks][:100],
            "escaping_symlinks": [rel_str(r) for r in sc.escaping_symlinks][:100],
            "dangling_symlinks": [rel_str(r) for r in sc.dangling][:100],
            "unreadable": [rel_str(r) for r in sc.unreadable][:100],
            "newline_names": len(sc.newline_names), "non_utf8_names": len(sc.non_utf8_names),
            "setid_files": [rel_str(r) for r in sc.setid][:100],
        },
        "notes": info, "blocking": blocking,
    }
    return pf, blocking, warns, sc


# --------------------------------------------------------------------------- #
# Verification
# --------------------------------------------------------------------------- #
def _mark(ok) -> str:
    return "PASS" if ok else ("SKIP" if ok is None else "FAIL")


def verify(src: bytes, dst: bytes, snap0: dict, op_dir: Path, con: Console) -> tuple[dict, dict, list]:
    t0 = time.monotonic()
    warns: list[str] = []
    con.section("VERIFICATION")
    src1 = scan_tree(src, progress_label="source")
    dst1 = scan_tree(dst, progress_label="destination")
    structural = compare_structure(src1, dst1)
    cs = structural["counts_source"]
    con.say(f"  [{_mark(structural['ok'])}] structural   files {cs['files']:,} · dirs {cs['directories']:,} · "
            f"symlinks {cs['symlinks']:,} · logical {structural['logical_bytes_source']:,} B · "
            f"hardlinks {'match' if structural['hardlinks_ok'] else 'DIFFER'}")
    if not structural["ok"]:
        if structural["counts_source"] != structural["counts_destination"]:
            con.say(f"         counts source {structural['counts_source']}")
            con.say(f"         counts dest   {structural['counts_destination']}")
        for key, label in (("missing_in_destination", "missing in destination"),
                           ("extra_in_destination", "extra in destination (left untouched)"),
                           ("destination_unreadable", "unreadable in destination")):
            if structural[key]:
                con.say(f"         {label}: {_few(structural[key])}")
        for k, v in list(structural["metadata_mismatches"].items())[:15]:
            con.say(f"         metadata differs: {disp(k)} → {', '.join(v)}")

    src_m = build_manifest(src1, op_dir / "source-manifest.jsonl", readback=False, label="source")
    dst_m = build_manifest(dst1, op_dir / "destination-manifest.jsonl", readback=True, label="destination")
    content = compare_manifests(src_m, dst_m)
    content["destination_readback"] = {
        "files_read": dst_m["files_read"], "unique_inodes": dst_m["unique_inodes"],
        "paths": dst_m["paths"], "bytes_read": dst_m["bytes_read"],
        "ok": (dst_m["files_read"] == dst_m["unique_inodes"] and dst_m["paths"] == len(dst1.files)
               and not dst_m["errors"]),
        "page_cache_dropped_before_read": dst_m["cache_drops"],
        "method": "os.sync() then posix_fadvise(DONTNEED) per file before hashing (best effort)",
    }
    content["elapsed_seconds"] = round(src_m["elapsed_seconds"] + dst_m["elapsed_seconds"], 3)
    con.say(f"  [{_mark(content['ok'])}] content      {content['hashed_files']:,} files SHA-256 · manifest "
            f"{content['source_manifest_sha256'][:16]}… vs {content['destination_manifest_sha256'][:16]}…")
    if not content["ok"]:
        for key in ("mismatched", "missing", "extra", "read_errors", "changed_during_read"):
            if content[key]:
                con.say(f"         {key.replace('_', ' ')}: {_few(content[key])}")
    rb = content["destination_readback"]
    hl = f", {rb['paths']:,} paths incl. hardlinks" if rb["paths"] != rb["unique_inodes"] else ""
    con.say(f"  [{_mark(rb['ok'])}] read-back    {rb['files_read']:,} destination files re-read from disk "
            f"({human(rb['bytes_read'])}{hl}; page cache dropped first)")

    pcmd = build_proof_command(src, dst, is_dir=src1.is_dir)
    prc, pout, perr = run_proof(pcmd)
    changes = [l for l in pout.splitlines() if l.strip()]
    (op_dir / "rsync-proof.txt").write_text(
        "$ " + shlex.join(pcmd) + f"\nexit {prc}\n--- itemized changes ---\n" + pout + "--- stderr ---\n" + perr,
        encoding="utf-8", errors="surrogateescape")
    rsync_proof = {"ok": prc == 0 and not changes, "exit_code": prc, "change_count": len(changes),
                   "changes": changes[:200], "command": shlex.join(pcmd),
                   "stderr": perr.strip().splitlines()[:20]}
    con.say(f"  [{_mark(rsync_proof['ok'])}] rsync proof  checksum dry-run reports "
            f"{len(changes)} change(s), exit {prc}")
    for l in changes[:10]:
        con.say(f"         {l}")

    git = compare_git(src, dst, src1.git_repos)
    if src1.git_repos != dst1.git_repos:
        git["ok"] = False
        git.setdefault("warnings", []).append("set of git repositories differs between source and destination")
    warns += git.get("warnings", [])
    if git["ok"] is None:
        warns.append(git["note"])
    n_nc = sum(1 for r in git.get("repos", []) if isinstance(r, dict) and r.get("comparable") is False)
    git_label = (f"{len(src1.git_repos) - n_nc} repo(s) identical"
                 + (f", {n_nc} not independently comparable (see warnings)" if n_nc else "") if git["ok"] else
                 "none present" if not src1.git_repos else "NOT COMPARED" if git["ok"] is None else
                 "DIFFERENCES: " + "; ".join(f"{r['path']}: {', '.join(r['differences'])}"
                                             for r in git["repos"] if isinstance(r, dict) and not r["ok"]))
    con.say(f"  [{_mark(git['ok'] if src1.git_repos else True)}] git          {git_label}")

    dst2_snap = scan_tree(dst).snap
    changes_dst = diff_snapshots(dst1.snap, dst2_snap)
    destination_stable = not changes_dst
    con.say(f"  [{_mark(destination_stable)}] destination  "
            + ("unchanged throughout verification" if destination_stable else
               f"CHANGED DURING VERIFICATION: {_few(list(changes_dst.keys()))}"))

    src2_snap = scan_tree(src).snap
    changes_src = diff_snapshots(snap0, src1.snap)
    changes_src.update(diff_snapshots(snap0, src2_snap))
    source_unchanged = not changes_src
    con.say(f"  [{_mark(source_unchanged)}] source       "
            + ("unchanged since preflight (metadata snapshot incl. ctime/inode)" if source_unchanged else
               f"CHANGED BY ANOTHER PROCESS during the operation: {_few(list(changes_src.keys()))}"))

    v = {"structural": structural, "content": content, "rsync_proof": rsync_proof,
         "source_unchanged": source_unchanged, "source_changes": changes_src,
         "destination_stable": destination_stable, "destination_changes": changes_dst,
         "elapsed_seconds": round(time.monotonic() - t0, 3)}
    v["ok"] = bool(structural["ok"] and content["ok"] and content["destination_readback"]["ok"]
                   and rsync_proof["ok"]
                   and git["ok"] is not False and source_unchanged and destination_stable)
    return v, git, warns


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
@dataclass
class Result:
    state: str
    exit_code: int
    record: dict
    record_dir: Path | None
    output: str


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cyclops-safe-copy",
        description="Conservatively copy SOURCE to DESTINATION and prove the copy is exact. "
                    "Never deletes, moves or modifies the source.",
        epilog="Final states: 'DRY RUN — NOTHING COPIED', 'COPY INCOMPLETE — SOURCE UNCHANGED', "
               "'COPY COMPLETE — VERIFICATION FAILED', 'COPY VERIFIED — SOURCE UNCHANGED' + "
               "'COPY VERIFIED — runtime/cutover not implied', 'REFUSED — NOTHING COPIED'. "
               "Exit codes: 0 verified/dry-run, 2 refused, 3 incomplete, 4 verification failed.")
    p.add_argument("source")
    p.add_argument("destination", help="directory to create (or an existing EMPTY directory); "
                                       "for a single-file source, the new file path")
    m = p.add_argument_group("modes (pick at most one)")
    m.add_argument("--dry-run", action="store_true", help="preflight only; copy nothing")
    m.add_argument("--verify-only", action="store_true",
                   help="verify an existing destination against the source; copy nothing")
    m.add_argument("--resume", action="store_true",
                   help="continue an interrupted Cyclops copy; re-checks every file by checksum")
    p.add_argument("--records-dir", metavar="DIR",
                   help="where records/manifests go (default: $CYCLOPS_SAFE_COPY_RECORDS, else "
                        "<destination disk>/cyclops-safe-copy-records)")
    p.add_argument("--bwlimit", type=int, metavar="KBPS", help="limit copy bandwidth (KiB/s)")
    p.add_argument("--allow-entire-home", action="store_true",
                   help="permit copying your whole home directory as the source")
    p.add_argument("--allow-special-files", action="store_true",
                   help="copy fifos/sockets (and devices, as root) as special files")
    p.add_argument("--version", action="version", version=f"cyclops-safe-copy {VERSION}")
    return p


def run(argv: list[str], stream=None) -> Result:
    con = Console(stream)
    args = build_parser().parse_args(argv)
    mode = ("dry-run" if args.dry_run else "verify-only" if args.verify_only else
            "resume" if args.resume else "copy")
    op_id = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(3)
    rec = {"operation_id": op_id, "tool_version": VERSION, "timestamp_utc": now_utc(),
           "host": os.uname().nodename, "euid": os.geteuid(), "argv": list(argv), "mode": mode,
           "source": None, "destination": None, "records_dir": None, "preflight": None,
           "copy": None, "verification": None, "git": None, "warnings": [],
           "refusal_reasons": [], "final_status": "IN PROGRESS (if you can read this, the run "
                                                  "was killed before finishing)"}
    ctx: dict = {"op_dir": None, "records": None, "lock": None, "pair": None, "phase": "setup",
                 "src": None, "dst": None, "rec": rec}

    def _raise(signum, _frame):
        raise Interrupted(signal.Signals(signum).name)

    old = {}
    for s in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        try:
            old[s] = signal.signal(s, _raise)
        except (ValueError, OSError):
            pass
    try:
        try:
            state = _run(args, mode, rec, con, ctx)
        except Refusal as r:
            state = STATE_REFUSED
            rec["refusal_reasons"] = r.reasons
            con.section("REFUSED")
            for reason in r.reasons:
                con.say(f"  ✗ {reason}")
        except (Interrupted, KeyboardInterrupt, Exception) as e:
            for sg in old:
                signal.signal(sg, signal.SIG_IGN)
            if isinstance(e, (Interrupted, KeyboardInterrupt)):
                what = f"interrupted by {str(e) or 'SIGINT'}"
            else:
                what = f"unexpected error: {type(e).__name__}: {e}"
                rec["error"] = what
            phase = ctx["phase"]
            con.say(f"\n  ✗ {what} (during {phase})")
            if phase in ("copied", "verify"):
                state = STATE_VFAIL if mode != "verify-only" else STATE_VERIFY_ONLY_FAIL
                rec["warnings"].append(f"verification did not finish ({what}) — the copy is NOT verified")
            elif phase == "copy":
                state = STATE_INCOMPLETE
                rec["warnings"].append(f"copy did not finish ({what})")
                try:
                    ch = diff_snapshots(ctx["snap0"], scan_tree(ctx["src"]).snap)
                    rec["verification"] = {"source_unchanged": not ch, "source_changes": ch}
                    if ch:
                        state = STATE_INCOMPLETE_SRC_CHANGED
                except Exception:
                    rec["warnings"].append("source re-check after the error was skipped")
                ctx["force_pair_state"] = PS_INCOMPLETE
            else:
                state = STATE_REFUSED
                rec["refusal_reasons"] = [f"{what} — stopped before any copying"]
        for s in old:
            signal.signal(s, signal.SIG_IGN)
        return _finish(state, mode, rec, con, ctx)
    finally:
        for s, h in old.items():
            try:
                signal.signal(s, h)
            except (ValueError, OSError):
                pass
        if ctx.get("lock"):
            ctx["lock"].close()


def _save(ctx: dict) -> None:
    if ctx["op_dir"]:
        write_json(ctx["op_dir"] / "record.json", ctx["rec"])


def _run(args, mode: str, rec: dict, con: Console, ctx: dict) -> str:
    con.say(f"════ CYCLOPS SAFE COPIER {VERSION} ════")
    con.say(f"Operation   : {rec['operation_id']}   mode: {mode}")
    if sum([args.dry_run, args.verify_only, args.resume]) > 1:
        raise Refusal("--dry-run, --verify-only and --resume are mutually exclusive")
    if args.bwlimit is not None and args.bwlimit <= 0:
        raise Refusal("--bwlimit must be a positive number of KiB/s")
    if not shutil.which("rsync"):
        raise Refusal("rsync is not installed")

    src_given = b(os.path.abspath(os.path.expanduser(args.source)))
    dst_given = b(os.path.abspath(os.path.expanduser(args.destination)))
    src = os.path.realpath(src_given)
    dst = os.path.realpath(dst_given)
    ctx["src"], ctx["dst"] = src, dst
    rec["source"] = {"given": args.source, "resolved": os.fsdecode(src)}
    rec["destination"] = {"given": args.destination, "resolved": os.fsdecode(dst)}
    con.say(f"Source      : {disp(src)}" + (f"   (given as {disp(src_given)})" if src != src_given else ""))
    con.say(f"Destination : {disp(dst)}" + (f"   (given as {disp(dst_given)})" if dst != dst_given else ""))

    # Validate everything path-related BEFORE creating anything anywhere.
    guard_reasons = check_path_guards(src, dst, allow_home=args.allow_entire_home,
                                      src_given=src_given, dst_given=dst_given)
    try:
        records = resolve_records_dir(args.records_dir, dst)
    except Refusal as r:
        raise Refusal(guard_reasons + r.reasons)
    rproblems = records_dir_problems(records, src, dst)
    if rproblems:
        raise Refusal(guard_reasons + rproblems)

    # Records directory is safe: create it and start this operation's record.
    op_dir = Path(os.fsdecode(records)) / "operations" / rec["operation_id"]
    try:
        os.makedirs(records, exist_ok=True)
        real_subdir(records, "operations")
        op_dir.mkdir(exist_ok=False)
    except OSError as e:
        raise Refusal(guard_reasons + [f"cannot create records directory {disp(records)}: {e.strerror} "
                                       "(pass --records-dir DIR)"])
    ctx["op_dir"], ctx["records"] = op_dir, records
    rec["records_dir"] = os.fsdecode(records)
    con.say(f"Records     : {disp(op_dir)}")
    _save(ctx)
    if guard_reasons:
        raise Refusal(guard_reasons)
    if not os.path.lexists(src):
        raise Refusal(f"source {disp(src)} does not exist")

    ctx["lock"] = acquire_lock(records, src, dst)
    ctx["pair"] = load_pair_state(records, src, dst)

    # ---- PREFLIGHT ------------------------------------------------------
    ctx["phase"] = "preflight"
    pf, blocking, warns, sc = preflight(args, mode, src, dst, con, ctx)
    rec["preflight"] = pf
    ctx["snap0"] = sc.snap
    rec["warnings"] += warns
    _save(ctx)

    if mode == "dry-run":
        cmd = build_copy_command(src, dst, is_dir=sc.is_dir, resume=False, temp_dir=None,
                                 bwlimit=args.bwlimit, allow_specials=args.allow_special_files)
        rec["copy"] = {"would_run": shlex.join(cmd), "executed": False}
        con.section("DRY RUN")
        con.say(f"  would run: {shlex.join(cmd)}")
        if blocking:
            con.say("  A REAL RUN WOULD STOP:")
            for r in blocking:
                con.say(f"    ✗ {r}")
        else:
            con.say("  No blocking problems found. Nothing was copied.")
        return STATE_DRY
    if blocking:
        raise Refusal(blocking)

    # ---- COPY -----------------------------------------------------------
    if mode in ("copy", "resume"):
        ctx["phase"] = "copy"
        con.section("COPY")
        staging = None
        st_dev_dst = os.stat(dst if os.path.exists(dst) else os.path.dirname(dst)).st_dev
        if os.stat(records).st_dev == st_dev_dst:
            staging = os.path.join(os.fsencode(str(real_subdir(records, "staging"))),
                                   pair_id(src, dst).encode())
            try:
                os.mkdir(staging)
            except FileExistsError:
                pass
            if stat.S_ISLNK(os.lstat(staging).st_mode) or not os.path.isdir(staging):
                raise Refusal("records staging directory is not a real directory — refusing")
        else:
            rec["warnings"].append("records directory is on a different filesystem from the destination: "
                                   "rsync temp files are written inside the destination while copying")
        cmd = build_copy_command(src, dst, is_dir=sc.is_dir, resume=(mode == "resume"),
                                 temp_dir=staging, bwlimit=args.bwlimit,
                                 allow_specials=args.allow_special_files,
                                 log_file=op_dir / "rsync-copy.log",
                                 progress=sys.stdout.isatty())
        rec["copy"] = {"command": shlex.join(cmd), "started_utc": now_utc(), "exit_code": None,
                       "elapsed_seconds": None, "resume_rechecks_by_checksum": mode == "resume"}
        con.say(f"  command: {shlex.join(cmd)}")
        save_pair_state(records, src, dst, PS_IN_PROGRESS, rec["operation_id"])
        _save(ctx)
        t0 = time.monotonic()
        interrupted = None
        try:
            rc = run_copy(cmd)
        except (Interrupted, KeyboardInterrupt) as e:
            for s in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
                signal.signal(s, signal.SIG_IGN)
            interrupted = str(e) or "SIGINT"
            rc = None
        elapsed = round(time.monotonic() - t0, 3)
        rec["copy"].update(exit_code=rc, elapsed_seconds=elapsed, finished_utc=now_utc(),
                           exit_meaning=RSYNC_EXIT_MEANING.get(rc, "interrupted" if interrupted else "unknown"))
        if interrupted or rc != 0:
            why = (f"interrupted by {interrupted}; rsync was stopped" if interrupted else
                   f"rsync exited with code {rc} ({RSYNC_EXIT_MEANING.get(rc, 'unknown')})")
            rec["copy"]["interrupted"] = interrupted
            con.say(f"  ✗ copy did not complete: {why}")
            con.say("  The destination holds a PARTIAL copy. It has been left exactly as it is — nothing "
                    "was deleted on either side.")
            con.say("  To continue: re-run the same command with --resume (every file is re-checked "
                    "by checksum; the partial copy is NOT assumed valid).")
            changes = {}
            try:
                changes = diff_snapshots(sc.snap, scan_tree(src).snap)
            except (Interrupted, KeyboardInterrupt, OSError):
                rec["warnings"].append("source re-check after interruption was skipped")
            rec["verification"] = {"source_unchanged": not changes, "source_changes": changes}
            if changes:
                con.say(f"  WARNING: the source was changed by another process during the copy: "
                        f"{_few(list(changes))}")
            save_pair_state(records, src, dst, PS_INCOMPLETE, rec["operation_id"])
            return STATE_INCOMPLETE_SRC_CHANGED if changes else STATE_INCOMPLETE
        ctx["phase"] = "copied"
        con.say(f"  rsync exit 0 in {elapsed:.1f}s — now verifying independently "
                "(a successful copy is not trusted on its own)")
        _save(ctx)

    # ---- VERIFY ---------------------------------------------------------
    ctx["phase"] = "verify"
    v, git, vwarns = verify(src, dst, sc.snap, op_dir, con)
    rec["verification"] = v
    rec["git"] = git
    rec["warnings"] += vwarns
    if v["ok"]:
        return STATE_VERIFIED
    return STATE_VFAIL if mode != "verify-only" else STATE_VERIFY_ONLY_FAIL


def _finish(state: str, mode: str, rec: dict, con: Console, ctx: dict) -> Result:
    rec["final_status"] = state
    rec["finished_utc"] = now_utc()
    records, src, dst = ctx.get("records"), ctx.get("src"), ctx.get("dst")
    def safe(fn, *a):
        try:
            fn(*a)
        except OSError as e:
            msg = f"could not write records ({e.strerror}) — the result below stands, but the record may be incomplete"
            if msg not in rec["warnings"]:
                rec["warnings"].append(msg)

    if records and ctx.get("lock"):
        ps_map = {STATE_VERIFIED: PS_VERIFIED, STATE_VFAIL: PS_VFAIL}
        if ctx.get("force_pair_state") and mode in ("copy", "resume"):
            safe(save_pair_state, records, src, dst, ctx["force_pair_state"], rec["operation_id"])
        elif mode in ("copy", "resume") and state in ps_map:
            safe(save_pair_state, records, src, dst, ps_map[state], rec["operation_id"])
        elif mode == "verify-only" and ctx.get("pair") and state in (STATE_VERIFIED, STATE_VERIFY_ONLY_FAIL):
            safe(save_pair_state, records, src, dst, PS_VERIFIED if state == STATE_VERIFIED else PS_VFAIL,
                 rec["operation_id"])
    con.section("RESULT")
    if rec["warnings"]:
        for w in rec["warnings"]:
            con.say(f"  WARNING: {w}")
    if state in (STATE_VFAIL, STATE_VERIFY_ONLY_FAIL, STATE_INCOMPLETE, STATE_INCOMPLETE_SRC_CHANGED):
        con.say("  Nothing was repaired and nothing was deleted. Both copies are left exactly as they are.")
    if state == STATE_VERIFIED:
        con.say("  The copy is byte- and metadata-exact. Whether an application should RUN from the "
                "destination is a separate decision; no symlinks or cutover were made.")
    if ctx.get("op_dir"):
        con.say(f"  Record: {disp(ctx['op_dir'] / 'record.json')}")
        safe(_save, ctx)
    # The final state is always the LAST line of output, so `tail -1` gives the verdict.
    con.say("")
    con.say(state)
    if state == STATE_VERIFIED:
        con.say(STATE_RUNTIME)
    if ctx.get("op_dir"):
        safe(atomic_write, ctx["op_dir"] / "report.txt", con.text().encode("utf-8", "surrogateescape"))
    return Result(state=state, exit_code=EXIT_CODES[state], record=rec, record_dir=ctx.get("op_dir"),
                  output=con.text())


def main(argv=None) -> int:
    try:
        os.nice(10)
    except OSError:
        pass
    if shutil.which("ionice"):
        subprocess.run(["ionice", "-c2", "-n7", "-p", str(os.getpid())], capture_output=True)
    try:
        return run(sys.argv[1:] if argv is None else argv).exit_code
    except SystemExit as e:
        return int(e.code or 0)


if __name__ == "__main__":
    sys.exit(main())
