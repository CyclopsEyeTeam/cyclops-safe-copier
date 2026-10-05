"""TDD suite for Cyclops Safe Copier.  Disposable fixtures only."""
from __future__ import annotations

import json
import os
import re
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from conftest import (HAS_GIT, IS_ROOT, TOOL, all_records_text, csc, fingerprint, git,
                      make_dirty_git_repo, make_rich_tree, make_simple_tree, write)

V = csc.STATE_VERIFIED
RT = csc.STATE_RUNTIME


def assert_verified(res):
    assert res.exit_code == 0, res.output
    assert "[FAIL]" not in res.output, "a verified run must not display any failed check"
    assert res.state == V, res.output
    assert V in res.output and RT in res.output
    assert res.record["final_status"] == V
    lines = [l for l in res.output.splitlines() if l.strip()]
    assert lines[-2:] == [V, RT], "verdict must be the last two lines, ending exactly with the runtime line"


# =========================================================================== #
# Happy paths
# =========================================================================== #
def test_ordinary_directory_copy_verified(tmp_path, runner):
    src = make_simple_tree(tmp_path / "src")
    dst = tmp_path / "dst"
    before = fingerprint(src, with_ctime=True, with_inode=True)
    res = runner(src, dst)
    assert_verified(res)
    assert fingerprint(src, with_ctime=True, with_inode=True) == before, "source changed!"
    assert fingerprint(dst) == fingerprint(src)


def test_rich_tree_hidden_empty_names_links_modes(tmp_path, runner):
    src = tmp_path / "src"
    feats = make_rich_tree(src)
    dst = tmp_path / "dst"
    before = fingerprint(src, with_ctime=True, with_inode=True)
    res = runner(src, dst)
    assert_verified(res)
    assert fingerprint(src, with_ctime=True, with_inode=True) == before
    assert fingerprint(dst) == fingerprint(src)
    # hidden, empty
    assert (dst / ".hidden_file").is_file() and (dst / ".hidden_dir" / "inside.txt").is_file()
    assert (dst / "empty_file").stat().st_size == 0
    assert (dst / "empty_dir").is_dir() and not any((dst / "empty_dir").iterdir())
    assert (dst / "nested" / "empty" / "dirs").is_dir()
    # names
    assert (dst / "new\nline.txt").is_file()
    assert (dst / "café ☕ ünïcödé.txt").is_file()
    assert os.path.exists(os.path.join(os.fsencode(str(dst)), b"latin1-\xe9\xff.bin"))
    # symlinks stay symlinks, including dangling
    assert os.path.islink(dst / "rel_link") and os.readlink(dst / "rel_link") == "sub/target.txt"
    assert os.path.islink(dst / "dangling_link") and not (dst / "dangling_link").exists()
    assert os.path.islink(dst / "dir_link")
    # hardlinks preserved
    assert os.stat(dst / "hl_a").st_ino == os.stat(dst / "sub" / "hl_b").st_ino
    # executable bits & restrictive modes
    assert stat.S_IMODE(os.stat(dst / "run.sh").st_mode) == 0o755
    assert stat.S_IMODE(os.stat(dst / "private.key.txt").st_mode) == 0o600
    # timestamps (ns-level where fs supports)
    assert os.stat(dst / "plain.txt").st_mtime_ns == os.stat(src / "plain.txt").st_mtime_ns
    if feats["xattr"]:
        assert os.getxattr(dst / "plain.txt", "user.cyclops") == b"evidence-tag"
    if feats["acl"]:
        out = subprocess.run(["getfacl", "-c", str(dst / "plain.txt")], capture_output=True, text=True).stdout
        assert "user:nobody:r--" in out
    # preflight reported the unusual-but-allowed things
    pf = res.record["preflight"]
    assert pf["counts"]["dangling_symlinks"] == 1
    assert pf["counts"]["hardlink_groups"] == 1
    assert pf["counts"]["newline_names"] >= 1


def test_executable_bits_preserved(tmp_path, runner):
    src = tmp_path / "src"
    write(src / "tool", b"#!/bin/sh\n", mode=0o750)
    write(src / "suid-like", b"x", mode=0o4755 if IS_ROOT else 0o755)
    write(src / "ro", b"x", mode=0o444)
    res = runner(src, tmp_path / "dst")
    assert_verified(res)
    for n in ("tool", "suid-like", "ro"):
        assert os.stat(tmp_path / "dst" / n).st_mode == os.stat(src / n).st_mode


def test_single_file_copy(tmp_path, runner):
    write(tmp_path / "evidence.bin", os.urandom(50_000), mode=0o640)
    (tmp_path / "out").mkdir()
    res = runner(tmp_path / "evidence.bin", tmp_path / "out" / "evidence-copy.bin")
    assert_verified(res)
    assert fingerprint(tmp_path / "out" / "evidence-copy.bin") == fingerprint(tmp_path / "evidence.bin")


def test_existing_empty_destination_dir_is_accepted(tmp_path, runner):
    src = make_simple_tree(tmp_path / "src")
    (tmp_path / "dst").mkdir()
    assert_verified(runner(src, tmp_path / "dst"))


# =========================================================================== #
# Dry run / verify only
# =========================================================================== #
def test_dry_run_copies_nothing(tmp_path, runner):
    src = make_simple_tree(tmp_path / "src")
    dst = tmp_path / "dst"
    res = runner(src, dst, "--dry-run")
    assert res.exit_code == 0
    assert res.state == csc.STATE_DRY
    assert csc.STATE_DRY in res.output
    assert not dst.exists()
    assert res.record["final_status"] == csc.STATE_DRY
    assert res.record["preflight"]["counts"]["files"] == 3


def test_verify_only_on_good_copy(tmp_path, runner):
    src = make_simple_tree(tmp_path / "src")
    dst = tmp_path / "dst"
    assert_verified(runner(src, dst))
    dst_before = fingerprint(dst, with_ctime=True, with_inode=True)
    res = runner(src, dst, "--verify-only")
    assert_verified(res)
    assert fingerprint(dst, with_ctime=True, with_inode=True) == dst_before, "verify-only wrote to destination"
    assert res.record["mode"] == "verify-only"
    assert res.record["copy"] is None


def test_verify_only_detects_unrelated_destination(tmp_path, runner):
    src = make_simple_tree(tmp_path / "src")
    dst = make_simple_tree(tmp_path / "other")  # same names, different random bytes
    res = runner(src, dst, "--verify-only")
    assert res.exit_code == 4
    assert res.state == csc.STATE_VERIFY_ONLY_FAIL
    assert "sub/data.bin" in res.output


def test_verify_only_requires_existing_destination(tmp_path, runner):
    src = make_simple_tree(tmp_path / "src")
    res = runner(src, tmp_path / "missing", "--verify-only")
    assert res.state == csc.STATE_REFUSED


# =========================================================================== #
# Verification catches problems
# =========================================================================== #
def _flip_byte_keep_stat(p: Path, offset: int = 10):
    st = p.stat()
    data = bytearray(p.read_bytes())
    data[offset] ^= 0xFF
    mode = st.st_mode
    p.chmod(0o600)
    p.write_bytes(bytes(data))
    p.chmod(stat.S_IMODE(mode))
    os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns))


def test_destination_corruption_detected_by_verify_only(tmp_path, runner):
    src = make_simple_tree(tmp_path / "src")
    dst = tmp_path / "dst"
    assert_verified(runner(src, dst))
    _flip_byte_keep_stat(dst / "sub" / "data.bin")  # same size, same mtime: quick-check would miss it
    res = runner(src, dst, "--verify-only")
    assert res.exit_code == 4
    v = res.record["verification"]
    assert v["content"]["ok"] is False
    assert "sub/data.bin" in v["content"]["mismatched"]
    assert v["rsync_proof"]["ok"] is False, "checksum rsync dry-run should also see it"
    assert v["structural"]["ok"] is True
    # never repaired or deleted
    assert (dst / "sub" / "data.bin").exists()


def test_corruption_during_run_reports_verification_failed(tmp_path, runner, monkeypatch):
    src = make_simple_tree(tmp_path / "src")
    dst = tmp_path / "dst"
    real = csc.run_copy

    def copy_then_corrupt(*a, **kw):
        rc = real(*a, **kw)
        _flip_byte_keep_stat(dst / "readme.txt", 2)
        return rc

    monkeypatch.setattr(csc, "run_copy", copy_then_corrupt)
    res = runner(src, dst)
    assert res.exit_code == 4
    assert res.state == csc.STATE_VFAIL
    assert csc.STATE_VERIFIED not in res.output
    assert "readme.txt" in res.output


def test_metadata_mismatch_detected(tmp_path, runner):
    src = make_simple_tree(tmp_path / "src")
    write(src / "x.sh", b"#!/bin/sh\n", mode=0o755)
    dst = tmp_path / "dst"
    assert_verified(runner(src, dst))
    os.chmod(dst / "x.sh", 0o644)
    os.utime(dst / "sub", ns=(1, 1))
    res = runner(src, dst, "--verify-only")
    assert res.exit_code == 4
    md = res.record["verification"]["structural"]["metadata_mismatches"]
    assert "x.sh" in md and "mode" in md["x.sh"]
    assert "sub" in md and "mtime_ns" in md["sub"]


def test_xattr_mismatch_detected(tmp_path, runner):
    src = make_simple_tree(tmp_path / "src")
    if not __import__("conftest").try_setxattr(src / "readme.txt", "user.tag", b"a"):
        pytest.skip("filesystem lacks user xattrs")
    dst = tmp_path / "dst"
    assert_verified(runner(src, dst))
    os.setxattr(dst / "readme.txt", "user.tag", b"b")
    res = runner(src, dst, "--verify-only")
    assert res.exit_code == 4
    assert "xattrs" in res.record["verification"]["structural"]["metadata_mismatches"]["readme.txt"]


def test_extra_file_in_destination_detected_not_pruned(tmp_path, runner):
    src = make_simple_tree(tmp_path / "src")
    dst = tmp_path / "dst"
    assert_verified(runner(src, dst))
    write(dst / "stray.txt", b"stray")
    res = runner(src, dst, "--verify-only")
    assert res.exit_code == 4
    assert "stray.txt" in res.record["verification"]["structural"]["extra_in_destination"]
    assert (dst / "stray.txt").exists(), "tool must never prune the destination"


def test_hardlink_broken_in_destination_detected(tmp_path, runner):
    src = tmp_path / "src"
    write(src / "a", b"same")
    os.link(src / "a", src / "b")
    dst = tmp_path / "dst"
    assert_verified(runner(src, dst))
    # break the link but keep identical bytes + metadata
    st = (dst / "b").stat()
    os.unlink(dst / "b")  # test-side mutation of the disposable destination
    write(dst / "b", b"same", mode=stat.S_IMODE(st.st_mode), mtime_ns=st.st_mtime_ns)
    res = runner(src, dst, "--verify-only")
    assert res.exit_code == 4
    assert res.record["verification"]["structural"]["hardlinks_ok"] is False


def test_source_changed_during_operation(tmp_path, runner, monkeypatch):
    src = make_simple_tree(tmp_path / "src")
    dst = tmp_path / "dst"
    real = csc.run_copy

    def copy_then_external_write(*a, **kw):
        rc = real(*a, **kw)
        with open(src / "readme.txt", "ab") as f:   # "another process" writes to the source
            f.write(b"late write\n")
        return rc

    monkeypatch.setattr(csc, "run_copy", copy_then_external_write)
    res = runner(src, dst)
    assert res.exit_code == 4
    assert res.state == csc.STATE_VFAIL
    assert res.record["verification"]["source_unchanged"] is False
    assert "readme.txt" in json.dumps(res.record["verification"]["source_changes"])
    assert "SOURCE UNCHANGED" not in res.state


# =========================================================================== #
# Interrupt / resume
# =========================================================================== #
def _slow_tree(root: Path, n=8, size=512 * 1024):
    for i in range(n):
        write(root / f"chunk{i:02d}.bin", os.urandom(size))
    return root


def _wait_for_partial(dst: Path, timeout=20):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if dst.exists() and any(p.is_file() for p in dst.rglob("*")):
            return
        time.sleep(0.1)
    raise AssertionError("copy never started")


@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGINT, signal.SIGKILL])
def test_interrupted_copy_then_resume(tmp_path, runner, sig):
    src = _slow_tree(tmp_path / "src")
    dst = tmp_path / "dst"
    rec = tmp_path / "records"
    before = fingerprint(src, with_ctime=True, with_inode=True)
    p = subprocess.Popen([sys.executable, str(TOOL), str(src), str(dst), "--records-dir", str(rec),
                          "--bwlimit", "300"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         start_new_session=True)
    _wait_for_partial(dst)
    time.sleep(0.5)
    if sig == signal.SIGKILL:
        os.killpg(p.pid, signal.SIGKILL)       # crash: python + rsync die together
    else:
        os.kill(p.pid, sig)                    # polite interrupt to the tool only
    out, _ = p.communicate(timeout=60)
    out = out.decode(errors="replace")
    assert p.returncode != 0
    if sig != signal.SIGKILL:
        assert csc.STATE_INCOMPLETE in out, out
        assert "COPY VERIFIED" not in out
    time.sleep(0.5)
    # rsync must not still be writing after the tool died
    snap1 = fingerprint(dst)
    time.sleep(1.0)
    assert fingerprint(dst) == snap1, "orphaned writer still modifying destination"
    assert fingerprint(src, with_ctime=True, with_inode=True) == before
    # no rsync temp junk inside destination
    assert not [n for n in os.listdir(dst) if n.startswith(".chunk")]
    # a plain re-run must refuse (destination not empty)
    again = runner(src, dst, records=rec)
    assert again.state == csc.STATE_REFUSED
    assert "--resume" in again.output
    # resume rechecks and completes
    res = runner(src, dst, "--resume", records=rec)
    assert_verified(res)
    assert res.record["mode"] == "resume"
    assert "--checksum" in res.record["copy"]["command"]
    assert fingerprint(dst) == fingerprint(src)
    assert fingerprint(src, with_ctime=True, with_inode=True) == before


def test_resume_refused_without_prior_record(tmp_path, runner):
    src = make_simple_tree(tmp_path / "src")
    dst = make_simple_tree(tmp_path / "dst")
    res = runner(src, dst, "--resume")
    assert res.state == csc.STATE_REFUSED


def test_resume_refused_after_verified(tmp_path, runner):
    src = make_simple_tree(tmp_path / "src")
    dst = tmp_path / "dst"
    assert_verified(runner(src, dst))
    res = runner(src, dst, "--resume")
    assert res.state == csc.STATE_REFUSED
    assert "--verify-only" in res.output


def test_mutually_exclusive_modes(tmp_path, runner):
    src = make_simple_tree(tmp_path / "src")
    res = runner(src, tmp_path / "d", "--dry-run", "--resume")
    assert res.state == csc.STATE_REFUSED


# =========================================================================== #
# Refusal guards
# =========================================================================== #
DANGEROUS = ["/", "/home", "/usr", "/var", "/etc", "/boot", "/proc", "/sys", "/dev", "/run",
             "/usr/share", "/etc/ssh", "/proc/self", "/dev/shm", "/run/user", "/var/lib"]


@pytest.mark.parametrize("bad", DANGEROUS)
def test_dangerous_source_refused(tmp_path, runner, bad):
    dst = tmp_path / "dst"
    res = runner(bad, dst)
    assert res.state == csc.STATE_REFUSED, res.output
    assert res.exit_code == 2
    assert not dst.exists()


@pytest.mark.parametrize("bad", DANGEROUS)
def test_dangerous_destination_refused(tmp_path, runner, bad):
    src = make_simple_tree(tmp_path / "src")
    res = runner(src, bad)
    assert res.state == csc.STATE_REFUSED, res.output
    assert res.exit_code == 2


def test_home_refused_unless_explicitly_allowed(tmp_path, runner, monkeypatch):
    home = make_simple_tree(tmp_path / "fakehome")
    monkeypatch.setenv("HOME", str(home))
    res = runner(home, tmp_path / "dst1")
    assert res.state == csc.STATE_REFUSED and "home" in res.output.lower()
    # an ancestor of home is refused too
    anc_res = runner(tmp_path, tmp_path.parent / (tmp_path.name + "-dst"))
    assert anc_res.state == csc.STATE_REFUSED
    # explicit permission
    ok = runner(home, tmp_path / "dst2", "--allow-entire-home")
    assert_verified(ok)


def test_home_as_destination_always_refused(tmp_path, runner, monkeypatch):
    home = tmp_path / "fakehome"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    src = make_simple_tree(tmp_path / "src")
    res = runner(src, home, "--allow-entire-home")
    assert res.state == csc.STATE_REFUSED


def test_same_location_refused(tmp_path, runner):
    src = make_simple_tree(tmp_path / "src")
    assert runner(src, src).state == csc.STATE_REFUSED
    os.symlink(src, tmp_path / "alias")
    assert runner(src, tmp_path / "alias").state == csc.STATE_REFUSED
    assert runner(tmp_path / "alias", src).state == csc.STATE_REFUSED


def test_destination_nested_in_source_refused(tmp_path, runner):
    src = make_simple_tree(tmp_path / "src")
    res = runner(src, src / "sub" / "backup")
    assert res.state == csc.STATE_REFUSED
    assert not (src / "sub" / "backup").exists()


def test_source_nested_in_destination_refused(tmp_path, runner):
    outer = tmp_path / "outer"
    src = make_simple_tree(outer / "inner")
    assert runner(src, outer).state == csc.STATE_REFUSED


def test_nesting_through_symlink_refused(tmp_path, runner):
    src = make_simple_tree(tmp_path / "src")
    os.symlink(src / "sub", tmp_path / "sneaky")
    res = runner(src, tmp_path / "sneaky" / "newdir")
    assert res.state == csc.STATE_REFUSED


def test_nonempty_destination_refused(tmp_path, runner):
    src = make_simple_tree(tmp_path / "src")
    dst = tmp_path / "dst"
    write(dst / "precious.txt", b"existing")
    res = runner(src, dst)
    assert res.state == csc.STATE_REFUSED
    assert (dst / "precious.txt").read_bytes() == b"existing"
    assert not (dst / "readme.txt").exists()


def test_missing_destination_parent_refused(tmp_path, runner):
    src = make_simple_tree(tmp_path / "src")
    res = runner(src, tmp_path / "no" / "such" / "parent" / "dst")
    assert res.state == csc.STATE_REFUSED
    assert not (tmp_path / "no").exists()


def test_records_dir_inside_source_or_destination_refused(tmp_path, runner):
    src = make_simple_tree(tmp_path / "src")
    dst = tmp_path / "dst"
    assert runner(src, dst, records=src / "rec").state == csc.STATE_REFUSED
    assert runner(src, dst, records=dst / "rec").state == csc.STATE_REFUSED
    assert not (src / "rec").exists()


def test_missing_source_refused(tmp_path, runner):
    assert runner(tmp_path / "ghost", tmp_path / "dst").state == csc.STATE_REFUSED


def test_insufficient_space_refused(tmp_path, runner, monkeypatch):
    src = make_simple_tree(tmp_path / "src")
    monkeypatch.setattr(csc, "free_space", lambda p: (10_000, 10**9))
    res = runner(src, tmp_path / "dst")
    assert res.state == csc.STATE_REFUSED
    assert "space" in res.output.lower()
    assert not (tmp_path / "dst").exists()


@pytest.mark.skipif(not IS_ROOT, reason="needs root to mount a tiny tmpfs")
def test_disk_full_during_copy_reports_incomplete(tmp_path, runner, monkeypatch):
    src = tmp_path / "src"
    for i in range(6):
        write(src / f"f{i}.bin", os.urandom(256 * 1024))
    mnt = tmp_path / "tiny"
    mnt.mkdir()
    subprocess.run(["mount", "-t", "tmpfs", "-o", "size=600k", "tmpfs", str(mnt)], check=True)
    try:
        monkeypatch.setattr(csc, "free_space", lambda p: (10**12, 10**9))  # lie so preflight passes
        before = fingerprint(src, with_ctime=True, with_inode=True)
        res = runner(src, mnt / "dst")
        assert res.state == csc.STATE_INCOMPLETE, res.output
        assert res.exit_code == 3
        assert fingerprint(src, with_ctime=True, with_inode=True) == before
        assert (mnt / "dst").exists(), "partial copy must be left in place, never deleted"
    finally:
        subprocess.run(["umount", "-l", str(mnt)])


def test_unsupported_destination_filesystem_refused(tmp_path, runner, monkeypatch):
    src = make_simple_tree(tmp_path / "src")
    real = csc.fs_info

    def fake(path):
        info = real(path)
        if str(tmp_path / "dst") in os.fsdecode(path) or os.fsdecode(path) == str(tmp_path):
            info = dict(info, fstype="exfat")
        return info

    monkeypatch.setattr(csc, "fs_info", fake)
    res = runner(src, tmp_path / "dst")
    assert res.state == csc.STATE_REFUSED
    assert "exfat" in res.output


def test_open_writer_refused(tmp_path, runner):
    src = make_simple_tree(tmp_path / "src")
    holder = subprocess.Popen([sys.executable, "-c",
                               "import sys,time;f=open(sys.argv[1],'ab');print('ready',flush=True);time.sleep(60)",
                               str(src / "sub" / "deeper" / "notes.md")], stdout=subprocess.PIPE)
    try:
        assert holder.stdout.readline().strip() == b"ready"
        res = runner(src, tmp_path / "dst")
        assert res.state == csc.STATE_REFUSED
        assert str(holder.pid) in res.output
        assert "notes.md" in res.output
        assert not (tmp_path / "dst").exists()
        # dry run reports it but still copies nothing
        dr = runner(src, tmp_path / "dst", "--dry-run")
        assert dr.state == csc.STATE_DRY and str(holder.pid) in dr.output
    finally:
        holder.kill()
        holder.wait()


def test_fifo_refused_without_flag_and_copied_with_flag(tmp_path, runner):
    src = make_simple_tree(tmp_path / "src")
    os.mkfifo(src / "pipe")
    res = runner(src, tmp_path / "dst")
    assert res.state == csc.STATE_REFUSED and "pipe" in res.output
    ok = runner(src, tmp_path / "dst", "--allow-special-files")
    assert_verified(ok)
    assert stat.S_ISFIFO(os.lstat(tmp_path / "dst" / "pipe").st_mode)


@pytest.mark.skipif(IS_ROOT, reason="root can read everything")
def test_unreadable_source_entry_refused(tmp_path, runner):
    src = make_simple_tree(tmp_path / "src")
    write(src / "locked.txt", b"x", mode=0o000)
    res = runner(src, tmp_path / "dst")
    assert res.state == csc.STATE_REFUSED and "locked.txt" in res.output


@pytest.mark.skipif(IS_ROOT, reason="only meaningful for non-root")
def test_unpreservable_ownership_refused(tmp_path, runner, monkeypatch):
    src = make_simple_tree(tmp_path / "src")
    real = csc.lstat_entry

    class FakeSt:
        st_uid = 0
        st_gid = 0

        def __init__(self, st):
            self._st = st

        def __getattr__(self, n):
            return getattr(self._st, n)

    def fake_lstat(p):
        return FakeSt(real(p))

    monkeypatch.setattr(csc, "lstat_entry", fake_lstat)
    assert runner(src, tmp_path / "dst").state == csc.STATE_REFUSED


def test_concurrent_run_on_same_pair_refused(tmp_path, runner):
    import fcntl
    src = make_simple_tree(tmp_path / "src")
    dst = tmp_path / "dst"
    lock_path = csc.pair_lock_path(tmp_path / "records", src, dst)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with open(lock_path, "w") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert runner(src, dst).state == csc.STATE_REFUSED
    assert_verified(runner(src, dst))


# =========================================================================== #
# Git awareness
# =========================================================================== #
@pytest.mark.skipif(not HAS_GIT, reason="git missing")
def test_dirty_git_repo_with_untracked_files_copies_exactly(tmp_path, runner):
    src = tmp_path / "src"
    make_dirty_git_repo(src / "project")
    write(src / "not-a-repo.txt", b"loose\n")
    status_before = git(src / "project", "status", "--porcelain=v2", "-uall").stdout
    before = fingerprint(src, with_ctime=True, with_inode=True)
    dst = tmp_path / "dst"
    res = runner(src, dst)
    assert_verified(res)
    assert fingerprint(src, with_ctime=True, with_inode=True) == before, "git inspection mutated source"
    g = res.record["git"]
    assert g["ok"] is True
    assert len(g["repos"]) == 1
    repo = g["repos"][0]
    assert repo["path"] == "project"
    snap = repo["source"]
    assert snap["head_ref"] == "refs/heads/main"
    assert snap["counts"]["tracked_modified"] >= 1
    assert snap["counts"]["staged"] >= 1
    assert snap["counts"]["untracked"] == 1
    assert any("v0.1" in r for r in snap["refs"])
    assert any("feature-x" in r for r in snap["refs"])
    # credentials never recorded
    assert b"s3cretTOKEN" not in all_records_text(tmp_path / "records")
    assert b"s3cretTOKEN" not in res.output.encode()
    assert "***" in json.dumps(snap["remotes"])
    # copy is still dirty in the same way
    assert git(dst / "project", "status", "--porcelain=v2", "-uall").stdout == status_before


@pytest.mark.skipif(not HAS_GIT, reason="git missing")
def test_git_ref_mismatch_detected(tmp_path, runner):
    src = tmp_path / "src"
    make_dirty_git_repo(src / "project")
    dst = tmp_path / "dst"
    assert_verified(runner(src, dst))
    head = (dst / "project" / ".git" / "refs" / "tags" / "v0.1")
    write(head, b"0" * 40 + b"\n")
    res = runner(src, dst, "--verify-only")
    assert res.exit_code == 4
    assert res.record["git"]["ok"] is False


@pytest.mark.skipif(not HAS_GIT, reason="git missing")
def test_git_commands_are_read_only():
    for argv in csc.GIT_SNAPSHOT_COMMANDS.values():
        assert argv[0] not in {"clean", "reset", "checkout", "stash", "gc", "repack", "prune",
                               "fetch", "pull", "push", "commit", "add", "rm", "mv", "restore",
                               "switch", "merge", "rebase", "update-index", "worktree prune"}


# =========================================================================== #
# Filesystems
# =========================================================================== #
def test_same_filesystem_copy_recorded(tmp_path, runner):
    src = make_simple_tree(tmp_path / "src")
    res = runner(src, tmp_path / "dst")
    assert_verified(res)
    assert res.record["preflight"]["cross_filesystem"] is False


def _other_fs_dir(tmp_path):
    env = os.environ.get("CYCLOPS_TEST_OTHER_FS")
    if env:
        d = Path(env) / f"csc-test-{os.getpid()}-{time.time_ns()}"
        d.mkdir(parents=True)
        return d, None
    if IS_ROOT:
        mnt = tmp_path / "otherfs"
        mnt.mkdir()
        subprocess.run(["mount", "-t", "tmpfs", "-o", "size=512m", "tmpfs", str(mnt)], check=True)
        return mnt, mnt
    pytest.skip("set CYCLOPS_TEST_OTHER_FS=/path/on/another/disk (or run as root) for cross-fs test")


def test_cross_filesystem_copy(tmp_path, runner):
    other, to_unmount = _other_fs_dir(tmp_path)
    try:
        src = tmp_path / "src"
        make_rich_tree(src)
        res = runner(src, other / "dst")
        assert_verified(res)
        assert res.record["preflight"]["cross_filesystem"] is True
        assert fingerprint(other / "dst") == fingerprint(src)
    finally:
        if to_unmount:
            subprocess.run(["umount", "-l", str(to_unmount)])


# =========================================================================== #
# Records & output contract
# =========================================================================== #
def test_record_contents_and_location(tmp_path, runner):
    src = tmp_path / "src"
    write(src / "secret-body.txt", b"UNIQUE-CONTENT-MARKER-9f3a\n")
    write(src / "b.txt", b"b\n")
    dst = tmp_path / "dst"
    res = runner(src, dst)
    assert_verified(res)
    r = res.record
    for key in ("operation_id", "timestamp_utc", "source", "destination", "tool_version",
                "preflight", "copy", "verification", "git", "warnings", "final_status"):
        assert key in r, key
    assert r["preflight"]["source_fs"]["fstype"]
    assert r["preflight"]["destination_fs"]["fstype"]
    assert r["preflight"]["counts"]["files"] == 2
    assert r["copy"]["command"].startswith(("ionice", "nice", "rsync"))
    assert "rsync" in r["copy"]["command"]
    assert r["copy"]["elapsed_seconds"] >= 0
    assert r["verification"]["elapsed_seconds"] >= 0
    c = r["verification"]["content"]
    assert re.fullmatch(r"[0-9a-f]{64}", c["source_manifest_sha256"])
    assert c["source_manifest_sha256"] == c["destination_manifest_sha256"]
    assert c["destination_readback"]["files_read"] == 2
    assert c["destination_readback"]["ok"] is True
    # records live outside both trees
    rd = res.record_dir.resolve()
    assert not str(rd).startswith(str(src.resolve()))
    assert not str(rd).startswith(str(dst.resolve()))
    assert (rd / "source-manifest.jsonl").is_file()
    assert (rd / "destination-manifest.jsonl").is_file()
    assert (rd / "record.json").is_file() and (rd / "report.txt").is_file()
    # no file contents in records
    assert b"UNIQUE-CONTENT-MARKER" not in all_records_text(tmp_path / "records")
    # nothing of ours leaked into the destination
    assert sorted(os.listdir(dst)) == ["b.txt", "secret-body.txt"]


def test_never_reports_plain_done(tmp_path, runner):
    src = make_simple_tree(tmp_path / "src")
    res = runner(src, tmp_path / "dst")
    for line in res.output.splitlines():
        assert line.strip().lower() not in {"done", "done.", "ok", "success"}


def test_cli_entrypoint_and_help(tmp_path, runner):
    r = runner.cli("--help")
    assert r.returncode == 0
    for flag in (b"--dry-run", b"--verify-only", b"--resume"):
        assert flag in r.stdout
    src = make_simple_tree(tmp_path / "src")
    wrapper = TOOL.parent / "bin" / "cyclops-safe-copy"
    r = subprocess.run([str(wrapper), str(src), str(tmp_path / "dst"), "--records-dir",
                        str(tmp_path / "rec")], capture_output=True, timeout=120)
    assert r.returncode == 0, r.stdout + r.stderr
    assert csc.STATE_RUNTIME.encode() in r.stdout


# =========================================================================== #
# Static safety guarantees
# =========================================================================== #
def test_rsync_commands_are_never_destructive(tmp_path):
    for resume in (False, True):
        cmd = csc.build_copy_command(b"/a/src", b"/b/dst", is_dir=True, resume=resume,
                                     temp_dir=None, bwlimit=None, allow_specials=False)
        csc.assert_safe_rsync(cmd, dry_run=False)
        assert cmd[-2:] == ["/a/src/", "/b/dst/"]
    proof = csc.build_proof_command(b"/a/src", b"/b/dst", is_dir=True)
    csc.assert_safe_rsync(proof, dry_run=True)
    assert "--checksum" in proof and ("-n" in proof or "--dry-run" in proof)
    for bad in ("--delete", "--delete-after", "--remove-source-files", "-L", "--copy-links",
                "--inplace", "--prune-empty-dirs", "--update", "--ignore-existing"):
        with pytest.raises(csc.SafetyError):
            csc.assert_safe_rsync(["rsync", "-a", bad, "--", "/a/", "/b/"], dry_run=False)
    with pytest.raises(csc.SafetyError):
        csc.assert_safe_rsync(["rsync", "-a", "--checksum", "--", "/a/", "/b/"], dry_run=True)


def test_source_code_contains_no_deletion_primitives():
    code = TOOL.read_text()
    for token in ("shutil.rmtree", "os.remove(", "os.unlink(", "os.rmdir(", ".unlink(",
                  "rmtree", "os.removedirs", "--delete\"", "'--delete'",
                  "\"git\", \"clean\"", "\"reset\"", "\"checkout\"", "\"stash\"", "\"gc\"",
                  "os.symlink(", "os.rename(", "shutil.move"):
        assert token not in code, f"forbidden primitive {token!r} present"
    # the only rename permitted is atomic record writing
    assert code.count("os.replace(") == 1


# =========================================================================== #
# Review round 1 — regressions for adversarial findings
# =========================================================================== #
needs_root = pytest.mark.skipif(not IS_ROOT, reason="needs root for bind mounts")


class _Bind:
    def __init__(self, target, at):
        self.target, self.at = Path(target), Path(at)

    def __enter__(self):
        self.at.mkdir(parents=True, exist_ok=True)
        subprocess.run(["mount", "--bind", str(self.target), str(self.at)], check=True)
        return self.at

    def __exit__(self, *exc):
        subprocess.run(["umount", "-l", str(self.at)])


@needs_root
def test_destination_inside_source_via_bind_alias_refused(tmp_path, runner):
    src = make_simple_tree(tmp_path / "src")
    before = fingerprint(src, with_ctime=True, with_inode=True)
    with _Bind(src / "sub", tmp_path / "alias") as alias:
        res = runner(src, alias / "copy")
        assert res.state == csc.STATE_REFUSED, res.output
    assert not (src / "sub" / "copy").exists()
    assert fingerprint(src, with_ctime=True, with_inode=True) == before


@needs_root
def test_source_inside_destination_via_bind_alias_refused(tmp_path, runner):
    outer = tmp_path / "outer"
    make_simple_tree(outer / "inner")
    with _Bind(outer / "inner", tmp_path / "alias") as alias:
        res = runner(alias, outer, "--verify-only")
        assert res.state == csc.STATE_REFUSED, res.output


@needs_root
def test_records_dir_inside_source_via_bind_alias_refused(tmp_path, runner):
    src = make_simple_tree(tmp_path / "src")
    with _Bind(src / "sub", tmp_path / "ralias") as ralias:
        res = runner(src, tmp_path / "dst", "--dry-run", records=ralias / "records")
        assert res.state == csc.STATE_REFUSED, res.output
    assert not (src / "sub" / "records").exists()


@needs_root
def test_protected_root_via_bind_alias_refused(tmp_path, runner):
    with _Bind("/etc", tmp_path / "rootbind") as rb:
        assert runner(rb, tmp_path / "dst", "--dry-run").state == csc.STATE_REFUSED
        src = make_simple_tree(tmp_path / "src")
        assert runner(src, rb / "cyclops-dst").state == csc.STATE_REFUSED
    assert not Path("/etc/cyclops-dst").exists()


@needs_root
def test_bind_mount_inside_source_refused(tmp_path, runner):
    src = make_simple_tree(tmp_path / "src")
    other = make_simple_tree(tmp_path / "other")
    with _Bind(other, src / "mounted"):
        res = runner(src, tmp_path / "dst")
        assert res.state == csc.STATE_REFUSED
        assert "mounted" in res.output


@needs_root
def test_open_writer_via_bind_alias_detected(tmp_path, runner):
    src = make_simple_tree(tmp_path / "src")
    with _Bind(src / "sub", tmp_path / "alias") as alias:
        holder = subprocess.Popen([sys.executable, "-c",
                                   "import sys,time;f=open(sys.argv[1],'ab');print('ready',flush=True);time.sleep(60)",
                                   str(alias / "data.bin")], stdout=subprocess.PIPE)
        try:
            assert holder.stdout.readline().strip() == b"ready"
            res = runner(src, tmp_path / "dst")
            assert res.state == csc.STATE_REFUSED, res.output
            assert str(holder.pid) in res.output
        finally:
            holder.kill()
            holder.wait()


@pytest.mark.skipif(not HAS_GIT, reason="git missing")
def test_git_filter_drivers_are_never_executed(tmp_path, runner):
    src = tmp_path / "src"
    repo = src / "repo"
    repo.mkdir(parents=True)
    git(repo, "init", "-q", "-b", "main")
    write(repo / ".gitattributes", b"*.txt filter=evil\n")
    write(repo / "a.txt", b"hello\n")
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "x")
    marker = tmp_path / "FILTER-RAN"
    git(repo, "config", "filter.evil.clean", f"touch {marker}; cat")
    git(repo, "config", "filter.evil.process", f"sh -c 'touch {marker}'")
    os.utime(repo / "a.txt", ns=(1, 1))  # stat-dirty so status would re-hash through the filter
    res = runner(src, tmp_path / "dst")
    assert_verified(res)
    assert not marker.exists(), "git ran a filter driver from repository config"


def test_destination_changed_during_verification_detected(tmp_path, runner, monkeypatch):
    src = make_simple_tree(tmp_path / "src")
    dst = tmp_path / "dst"
    real = csc.compare_git

    def sneaky(s, d, repos):
        write(dst / "planted-during-verify", b"x")
        return real(s, d, repos)

    monkeypatch.setattr(csc, "compare_git", sneaky)
    res = runner(src, dst)
    assert res.state == csc.STATE_VFAIL, res.output
    assert res.record["verification"]["destination_stable"] is False


def test_credentials_redacted():
    r = csc.redact_credentials
    s = r("origin\thttps://user:p@ss-SECRET1@host.example/x.git (fetch)\n"
          "tok\thttps://host.example/x.git?access_token=SECRET2#frag (push)\n"
          "ssh\tssh://git:SECRET3@host:22/x.git (fetch)\n"
          "plain\thttps://SECRET4@github.com/me/x.git (fetch)")
    for secret in ("SECRET1", "SECRET2", "SECRET3", "SECRET4", "p@ss"):
        assert secret not in s, s
    assert "host.example/x.git" in s


@pytest.mark.skipif(not HAS_GIT, reason="git missing")
def test_credentials_in_query_and_password_never_recorded(tmp_path, runner):
    src = tmp_path / "src"
    repo = src / "r"
    repo.mkdir(parents=True)
    git(repo, "init", "-q")
    git(repo, "remote", "add", "a", "https://u:p@ss-SECRET1@host.invalid/x.git")
    git(repo, "remote", "add", "b", "https://host.invalid/x.git?access_token=SECRET2")
    res = runner(src, tmp_path / "dst")
    assert_verified(res)
    blob = all_records_text(tmp_path / "records") + res.output.encode()
    assert b"SECRET1" not in blob and b"SECRET2" not in blob


def test_unexpected_error_in_verification_is_clean_failure(tmp_path, runner, monkeypatch):
    src = make_simple_tree(tmp_path / "src")

    def boom(*a, **k):
        raise PermissionError(13, "Permission denied (simulated)")

    monkeypatch.setattr(csc, "compare_git", boom)
    res = runner(src, tmp_path / "dst")
    assert res.state == csc.STATE_VFAIL
    assert "Permission denied" in res.output
    assert res.record["final_status"] == csc.STATE_VFAIL
    ps = csc.load_pair_state(os.fsencode(str(tmp_path / "records")), os.fsencode(str(src)),
                             os.fsencode(str(tmp_path / "dst")))
    assert ps["last_status"] == csc.PS_VFAIL


def test_unexpected_error_in_preflight_is_clean_refusal(tmp_path, runner, monkeypatch):
    src = make_simple_tree(tmp_path / "src")

    def boom(*a, **k):
        raise OSError(5, "Input/output error (simulated)")

    monkeypatch.setattr(csc, "find_open_writers", boom)
    res = runner(src, tmp_path / "dst")
    assert res.state == csc.STATE_REFUSED
    assert "Input/output error" in res.output
    assert not (tmp_path / "dst").exists()


def test_interrupt_between_copy_and_verification(tmp_path, runner, monkeypatch):
    src = make_simple_tree(tmp_path / "src")
    dst = tmp_path / "dst"

    def interrupted(*a, **k):
        raise csc.Interrupted("SIGTERM")

    monkeypatch.setattr(csc, "verify", interrupted)
    res = runner(src, dst)
    assert res.state == csc.STATE_VFAIL
    assert csc.STATE_VERIFIED not in res.output
    monkeypatch.undo()
    assert_verified(runner(src, dst, "--resume"))


@pytest.mark.skipif(IS_ROOT, reason="root can read everything")
def test_unreadable_destination_is_clean_refusal(tmp_path, runner):
    src = make_simple_tree(tmp_path / "src")
    dst = tmp_path / "dst"
    write(dst / "x", b"x")
    dst.chmod(0o000)
    try:
        res = runner(src, dst)
        assert res.state == csc.STATE_REFUSED
    finally:
        dst.chmod(0o755)


@pytest.mark.skipif(not HAS_GIT, reason="git missing")
def test_linked_worktree_and_submodule_handled(tmp_path, runner):
    src = tmp_path / "src"
    lib = tmp_path / "libsrc"
    lib.mkdir()
    git(lib, "init", "-q", "-b", "main")
    write(lib / "lib.txt", b"lib\n")
    git(lib, "add", ".")
    git(lib, "commit", "-q", "-m", "lib")
    main = src / "main"
    main.mkdir(parents=True)
    git(main, "init", "-q", "-b", "main")
    write(main / "m.txt", b"m\n")
    git(main, "add", ".")
    git(main, "commit", "-q", "-m", "m")
    git(main, "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(lib), "vendor/lib")
    git(main, "commit", "-q", "-m", "sub")
    git(main, "worktree", "add", "-q", str(src / "wt"), "-b", "wtbranch")
    res = runner(src, tmp_path / "dst")
    assert_verified(res)
    repos = {r["path"]: r for r in res.record["git"]["repos"]}
    assert "main" in repos and "wt" in repos
    assert "vendor/lib" in json.dumps(repos["main"]["source"]["submodules"])
    assert repos["wt"]["comparable"] is False
    assert any("worktree" in w or "gitdir" in w for w in res.record["warnings"])


# =========================================================================== #
# Review round 2
# =========================================================================== #
def test_lock_file_symlink_is_never_followed(tmp_path, runner):
    src = make_simple_tree(tmp_path / "src")
    dst = tmp_path / "dst"
    lock = csc.pair_lock_path(tmp_path / "records", src, dst)
    lock.parent.mkdir(parents=True)
    os.symlink(src / "PLANTED", lock)
    res = runner(src, dst)
    assert res.state == csc.STATE_REFUSED
    assert not (src / "PLANTED").exists()


def test_no_shared_tmp_lock_is_created(tmp_path, runner):
    src = make_simple_tree(tmp_path / "src")
    assert_verified(runner(src, tmp_path / "dst"))
    assert "cyclops-safe-copy-locks" not in TOOL.read_text(), "no world-writable shared lock location"


@needs_root
def test_overlay_source_or_destination_refused(tmp_path, runner):
    lower, upper, work, merged = (tmp_path / n for n in ("lower", "upper", "work", "merged"))
    for d in (lower, upper, work, merged):
        d.mkdir()
    write(lower / "f.txt", b"x")
    subprocess.run(["mount", "-t", "overlay", "overlay", "-o",
                    f"lowerdir={lower},upperdir={upper},workdir={work}", str(merged)], check=True)
    try:
        res = runner(merged, upper / "copy")
        assert res.state == csc.STATE_REFUSED, res.output
        assert not (merged / "copy").exists()
        assert "overlay" in res.output
    finally:
        subprocess.run(["umount", "-l", str(merged)])


@needs_root
def test_records_disk_full_is_clean(tmp_path, runner):
    src = tmp_path / "src"
    for i in range(3000):
        write(src / f"d{i % 30}" / f"file-with-a-longish-name-{i:05d}.txt", b"x")
    rec = tmp_path / "rec"
    rec.mkdir()
    subprocess.run(["mount", "-t", "tmpfs", "-o", "size=160k", "tmpfs", str(rec)], check=True)
    try:
        res = runner(src, tmp_path / "dst", records=rec)
        assert res.state in (csc.STATE_REFUSED, csc.STATE_VFAIL), res.output
        assert res.state != csc.STATE_VERIFIED
    finally:
        subprocess.run(["umount", "-l", str(rec)])


def test_shared_writable_mmap_detected_as_writer(tmp_path, runner):
    src = make_simple_tree(tmp_path / "src")
    code = r'''
import ctypes, os, sys, time
libc = ctypes.CDLL(None, use_errno=True)
libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
fd = os.open(sys.argv[1], os.O_RDWR)
p = libc.mmap(None, 4096, 3, 1, fd, 0)   # PROT_READ|PROT_WRITE, MAP_SHARED
os.close(fd)
print("ready", flush=True)
time.sleep(60)
'''
    holder = subprocess.Popen([sys.executable, "-c", code, str(src / "sub" / "data.bin")], stdout=subprocess.PIPE)
    try:
        assert holder.stdout.readline().strip() == b"ready"
        res = runner(src, tmp_path / "dst")
        assert res.state == csc.STATE_REFUSED, res.output
        assert str(holder.pid) in res.output
    finally:
        holder.kill()
        holder.wait()


@pytest.mark.skipif(not HAS_GIT, reason="git missing")
def test_git_core_worktree_elsewhere_not_claimed_identical(tmp_path, runner):
    outside = tmp_path / "outside-worktree"
    outside.mkdir()
    src = tmp_path / "src"
    repo = src / "r"
    repo.mkdir(parents=True)
    git(repo, "init", "-q")
    git(repo, "config", "core.worktree", str(outside))
    res = runner(src, tmp_path / "dst")
    assert_verified(res)
    r = res.record["git"]["repos"][0]
    assert r["comparable"] is False and r["ok"] is None


def test_path_tokens_redacted():
    s = csc.redact_credentials("x\thttps://host.example/ghp_A1b2C3d4E5f6G7h8I9j0K1l2/repo.git (fetch)")
    assert "ghp_A1b2C3d4E5f6G7h8I9j0K1l2" not in s
    assert "host.example" in s and "repo.git" in s


def test_unexpected_error_during_copy_rechecks_source(tmp_path, runner, monkeypatch):
    src = make_simple_tree(tmp_path / "src")

    def boom(cmd):
        with open(src / "readme.txt", "ab") as f:
            f.write(b"external write")
        raise OSError(5, "simulated I/O error")

    monkeypatch.setattr(csc, "run_copy", boom)
    res = runner(src, tmp_path / "dst")
    assert res.state == csc.STATE_INCOMPLETE_SRC_CHANGED, res.output


@pytest.mark.parametrize("sub", ["locks", "pairs", "operations", "staging"])
def test_records_subdir_symlink_into_source_refused(tmp_path, runner, sub):
    src = make_simple_tree(tmp_path / "src")
    rec = tmp_path / "records"
    rec.mkdir()
    os.symlink(src / "sub", rec / sub)
    before = fingerprint(src, with_ctime=True, with_inode=True)
    res = runner(src, tmp_path / "dst", records=rec)
    assert res.state != csc.STATE_VERIFIED
    assert fingerprint(src, with_ctime=True, with_inode=True) == before


def test_final_state_is_last_line_for_every_outcome(tmp_path, runner):
    src = make_simple_tree(tmp_path / "src")
    for argv, expected in (((src, tmp_path / "d1", "--dry-run"), csc.STATE_DRY),
                           ((src, src / "inside"), csc.STATE_REFUSED),
                           ((src, make_simple_tree(tmp_path / "other"), "--verify-only"), csc.STATE_VERIFY_ONLY_FAIL)):
        res = runner(*argv)
        assert [l for l in res.output.splitlines() if l.strip()][-1] == expected
    res = runner(src, tmp_path / "d2")
    assert res.output.rstrip("\n").splitlines()[-1] == csc.STATE_RUNTIME
    report = (res.record_dir / "report.txt").read_text()
    assert report.rstrip("\n").splitlines()[-1] == csc.STATE_RUNTIME
