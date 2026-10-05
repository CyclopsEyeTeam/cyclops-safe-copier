"""Shared fixtures for the Cyclops Safe Copier suite.

Every fixture is disposable and lives under pytest's tmp_path.
Nothing here touches real user data.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import cyclops_safe_copy as csc  # noqa: E402

TOOL = ROOT / "cyclops_safe_copy.py"
IS_ROOT = os.geteuid() == 0
HAS_SETFACL = shutil.which("setfacl") is not None
HAS_GIT = shutil.which("git") is not None


# --------------------------------------------------------------------------- #
# Independent fingerprint (deliberately NOT using the tool's own code)
# --------------------------------------------------------------------------- #
def _xattrs(p: bytes) -> dict:
    out = {}
    try:
        names = os.listxattr(p, follow_symlinks=False)
    except OSError:
        return out
    for n in names:
        if n == "security.selinux":
            continue
        try:
            out[n] = os.getxattr(p, n, follow_symlinks=False).hex()
        except OSError:
            pass
    return out


def fingerprint(root: Path, *, with_ctime: bool = False, with_inode: bool = False) -> dict:
    """lstat + content + xattr fingerprint of a tree, keyed by relative bytes path."""
    root_b = os.fsencode(str(root))
    fp = {}
    inode_groups: dict = {}

    def visit(rel: bytes):
        full = root_b if rel == b"." else os.path.join(root_b, rel)
        st = os.lstat(full)
        rec = {
            "mode": st.st_mode,
            "uid": st.st_uid,
            "gid": st.st_gid,
            "mtime_ns": st.st_mtime_ns,
            "xattrs": _xattrs(full),
        }
        if with_ctime:
            rec["ctime_ns"] = st.st_ctime_ns
        if with_inode:
            rec["ino"] = st.st_ino
        if stat.S_ISREG(st.st_mode):
            h = hashlib.sha256()
            with open(full, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
            rec["sha256"] = h.hexdigest()
            rec["size"] = st.st_size
            if st.st_nlink > 1:
                inode_groups.setdefault((st.st_dev, st.st_ino), []).append(rel)
        elif stat.S_ISLNK(st.st_mode):
            rec["target"] = os.readlink(full).hex()
        fp[rel.hex()] = rec
        if stat.S_ISDIR(st.st_mode):
            for name in sorted(os.listdir(full)):
                visit(name if rel == b"." else os.path.join(rel, name))

    visit(b".")
    fp["__hardlink_groups__"] = sorted(sorted(g) for g in inode_groups.values() if len(g) > 1)
    fp["__hardlink_groups__"] = [[x.hex() for x in g] for g in fp["__hardlink_groups__"]]
    return fp


# --------------------------------------------------------------------------- #
# Fixture builders
# --------------------------------------------------------------------------- #
def write(p: Path, data: bytes = b"x", mode: int | None = None, mtime_ns: int | None = None):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    if mode is not None:
        p.chmod(mode)
    if mtime_ns is not None:
        os.utime(p, ns=(mtime_ns, mtime_ns))
    return p


def try_setxattr(p, name, value) -> bool:
    try:
        os.setxattr(p, name, value)
        return True
    except OSError:
        return False


def try_setfacl(p: Path, spec: str) -> bool:
    if not HAS_SETFACL:
        return False
    r = subprocess.run(["setfacl", "-m", spec, str(p)], capture_output=True)
    return r.returncode == 0


def make_simple_tree(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    write(root / "readme.txt", b"hello cyclops\n")
    write(root / "sub" / "data.bin", os.urandom(64 * 1024))
    write(root / "sub" / "deeper" / "notes.md", b"# notes\n")
    return root


def make_rich_tree(root: Path) -> dict:
    """Ordinary + every awkward case the spec asks for. Returns feature flags."""
    root.mkdir(parents=True, exist_ok=True)
    t = 1_600_000_000_123_456_789
    feats = {}
    write(root / "plain.txt", b"plain\n", mtime_ns=t)
    write(root / ".hidden_file", b"hidden\n")
    write(root / ".hidden_dir" / "inside.txt", b"inside hidden dir\n")
    write(root / "empty_file", b"")
    (root / "empty_dir").mkdir()
    (root / "nested" / "empty" / "dirs").mkdir(parents=True)
    write(root / "a file with spaces.txt", b"spaces\n")
    write(root / "new\nline.txt", b"newline in name\n")
    write(root / "café ☕ ünïcödé.txt", "unicode body ✓\n".encode())
    # Non-UTF-8 byte filename
    bad = os.path.join(os.fsencode(str(root)), b"latin1-\xe9\xff.bin")
    with open(bad, "wb") as f:
        f.write(b"non-utf8 name\n")
    write(root / "big.bin", os.urandom(300 * 1024))
    write(root / "sub" / "target.txt", b"symlink target\n")
    os.symlink("sub/target.txt", root / "rel_link")
    os.symlink("does/not/exist", root / "dangling_link")
    os.symlink("sub", root / "dir_link")
    write(root / "hl_a", b"hardlinked content\n")
    os.link(root / "hl_a", root / "sub" / "hl_b")
    write(root / "run.sh", b"#!/bin/sh\necho hi\n", mode=0o755)
    write(root / "private.key.txt", b"not a real key\n", mode=0o600)
    feats["xattr"] = try_setxattr(root / "plain.txt", "user.cyclops", b"evidence-tag")
    feats["acl"] = try_setfacl(root / "plain.txt", "u:nobody:r")
    # directory mtimes last (children changes touch them)
    os.utime(root / "sub", ns=(t, t))
    os.utime(root / "empty_dir", ns=(t, t))
    return feats


def git(repo: Path, *args, check=True) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_AUTHOR_NAME="Fixture", GIT_AUTHOR_EMAIL="f@example.invalid",
               GIT_COMMITTER_NAME="Fixture", GIT_COMMITTER_EMAIL="f@example.invalid",
               GIT_CONFIG_NOSYSTEM="1", HOME=str(repo.parent))
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, env=env, check=check)


def make_dirty_git_repo(repo: Path) -> None:
    repo.mkdir(parents=True)
    git(repo, "init", "-q", "-b", "main")
    write(repo / "tracked.txt", b"v1\n")
    write(repo / "keep.txt", b"keep\n")
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "first")
    git(repo, "tag", "v0.1")
    git(repo, "branch", "feature-x")
    git(repo, "remote", "add", "origin", "https://someone:s3cretTOKEN@example.invalid/project.git")
    write(repo / "tracked.txt", b"v2 uncommitted\n")          # tracked modification
    write(repo / "staged.txt", b"staged only\n")
    git(repo, "add", "staged.txt")                              # index state
    write(repo / "untracked dir" / "loose file.txt", b"untracked\n")  # untracked


# --------------------------------------------------------------------------- #
# Running the tool
# --------------------------------------------------------------------------- #
class Runner:
    def __init__(self, tmp_path: Path):
        self.records = tmp_path / "records"

    def __call__(self, src, dst, *extra, records=None):
        argv = [str(src), str(dst), "--records-dir", str(records or self.records), *map(str, extra)]
        return csc.run(argv)

    def cli(self, *args, timeout=120, **kw):
        return subprocess.run([sys.executable, str(TOOL), *map(str, args)],
                              capture_output=True, timeout=timeout, **kw)


@pytest.fixture
def runner(tmp_path):
    return Runner(tmp_path)


def all_records_text(records: Path) -> bytes:
    blob = b""
    for p in records.rglob("*"):
        if p.is_file():
            blob += p.read_bytes()
    return blob
