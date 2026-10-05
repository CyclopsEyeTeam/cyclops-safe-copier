#!/usr/bin/env python3
"""Cyclops Safe Copier — machine-local acceptance run (SSD → HDD).

Runs the eight acceptance steps on the REAL disks of this machine, using only
fresh, disposable fixtures that this script creates itself:

  1. both test suites (normal user, then sudo)
  2. records location resolves onto the HDD (not the SSD)
  3. --dry-run of a small SSD fixture onto the HDD
  4. one real SSD→HDD copy of that fixture
  5. output ends exactly "COPY VERIFIED — runtime/cutover not implied"
  6. independent proof (coreutils, not the tool's code) that the source is unchanged
  7. deliberate interruption of a larger fixture copy, then --resume
  8. elapsed copy/verification times + filesystem differences

If — and only if — every step passes, Safe Copier V1 is preserved: an immutable
tarball + SHA256SUMS next to the report, and an annotated git tag on the tool's
own directory.

It never touches real project/evidence/session data: it refuses unless both
working directories are new (or empty), and it never deletes, moves or
symlinks anything.  Fixtures are left in place for you to inspect/remove.

Usage:
  python3 acceptance/cyclops_acceptance.py --hdd-dir /media/<you>/<HDD>/cyclops-safe-copy-acceptance
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tarfile
import time
from pathlib import Path

TOOL_DIR = Path(__file__).resolve().parent.parent
TOOL = TOOL_DIR / "bin" / "cyclops-safe-copy"
VERIFIED = "COPY VERIFIED — SOURCE UNCHANGED"
RUNTIME = "COPY VERIFIED — runtime/cutover not implied"
DRY = "DRY RUN — NOTHING COPIED"
INCOMPLETE = "COPY INCOMPLETE — SOURCE UNCHANGED"
REFUSED = "REFUSED — NOTHING COPIED"
MiB = 1024 * 1024


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
class Report:
    def __init__(self, out_dir: Path):
        self.dir = out_dir
        self.steps: list[dict] = []
        self.timings: list[dict] = []
        self.fs_notes: list[str] = []
        self.log_path = out_dir / "acceptance.log"

    def log(self, text: str = "") -> None:
        print(text, flush=True)
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(text + "\n")

    def step(self, num: str, name: str, status: str, details: list[str] | str) -> None:
        details = [details] if isinstance(details, str) else details
        self.steps.append({"step": num, "name": name, "status": status, "details": details})
        self.log(f"\n[{status}] step {num}: {name}")
        for d in details:
            self.log(f"        {d}")

    def all_passed(self) -> bool:
        need = {"1a", "1b", "2", "3", "4", "5", "6", "7", "8"}
        got = {s["step"] for s in self.steps if s["status"] == "PASS"}
        return need <= got and not any(s["status"] == "FAIL" for s in self.steps)

    def save(self, ctx: dict) -> Path:
        lines = ["# Cyclops Safe Copier — machine-local acceptance report", "",
                 f"- Date (UTC): {ctx['started']}",
                 f"- Host: {os.uname().nodename} · kernel {os.uname().release}",
                 f"- Tool: {ctx.get('tool_version', '?')} at `{TOOL_DIR}`",
                 f"- SSD fixtures: `{ctx['ssd_dir']}`",
                 f"- HDD destinations: `{ctx['hdd_dir']}`",
                 f"- Records directory used: `{ctx.get('records_dir', '?')}`", "",
                 "## Results", "", "| Step | Check | Result |", "|---|---|---|"]
        self.steps.sort(key=lambda s: s["step"])
        for s in self.steps:
            lines.append(f"| {s['step']} | {s['name']} | **{s['status']}** |")
        lines += ["", "## Details", ""]
        for s in self.steps:
            lines.append(f"### Step {s['step']} — {s['name']} — {s['status']}")
            lines += [f"- {d}" for d in s["details"]] + [""]
        lines += ["## Timings (from the tool's own records)", "",
                  "| Operation | Mode | Data | Copy s | Copy MB/s | Verify s | Verify MB/s (data) |",
                  "|---|---|---|---|---|---|---|"]
        for t in self.timings:
            lines.append(f"| {t['label']} | {t['mode']} | {t['data']} | {t['copy_s']} | {t['copy_rate']} | "
                         f"{t['verify_s']} | {t['verify_rate']} |")
        lines += ["", "## Filesystem observations", ""] + [f"- {n}" for n in self.fs_notes]
        verdict = ("ALL MACHINE-LOCAL ACCEPTANCE CHECKS PASSED" if self.all_passed()
                   else "ACCEPTANCE NOT PASSED — see FAIL/SKIP rows above")
        lines += ["", "## Verdict", "", f"**{verdict}**", "",
                  "No real project, evidence or session data was copied, moved, symlinked or deleted. "
                  "Fixtures were left in place for inspection."]
        if ctx.get("tag_note"):
            lines += ["", "## V1 preservation", ""] + [f"- {n}" for n in ctx["tag_note"]]
        path = self.dir / "ACCEPTANCE-REPORT.md"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def sh(cmd, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def findmnt(path: Path) -> dict:
    r = sh(["findmnt", "-no", "SOURCE,FSTYPE,OPTIONS,TARGET", "--target", str(path)])
    parts = r.stdout.split()
    if len(parts) >= 4:
        return {"source": parts[0], "fstype": parts[1], "options": parts[2], "target": " ".join(parts[3:])}
    return {"source": "?", "fstype": "?", "options": "?", "target": "?"}


def disk_info(source: str) -> str:
    """Describe the physical disk behind a mount source (rotational flag, model)."""
    if not source.startswith("/dev/"):
        return f"{source} (not a block device)"
    r = sh(["lsblk", "-sno", "NAME,TYPE,ROTA,MODEL,TRAN,SIZE", source])
    disks = [l.split(None, 5) for l in r.stdout.splitlines() if " disk " in f" {l} " or " loop " in f" {l} "]
    if not disks:
        return f"{source}: lsblk gave no disk info"
    d = disks[-1]
    name = d[0].lstrip("└─├│ `-")
    rota = d[2] if len(d) > 2 else "?"
    model = " ".join(d[3:]) if len(d) > 3 else ""
    kind = "rotational (HDD)" if rota == "1" else "non-rotational (SSD/flash)" if rota == "0" else "unknown"
    return f"{source} on disk {name}: {kind}; {model}".strip()


def rotational(source: str) -> str | None:
    r = sh(["lsblk", "-sno", "TYPE,ROTA", source])
    vals = [l.split() for l in r.stdout.splitlines() if l.strip().startswith(("disk", "loop"))]
    return vals[-1][1] if vals and len(vals[-1]) > 1 else None


def run_tool(args: list, log: Path) -> tuple[int, str]:
    """Run the real CLI exactly as you would (your environment, incl. any
    CYCLOPS_SAFE_COPY_RECORDS you have set)."""
    r = subprocess.run([str(TOOL), *map(str, args)], capture_output=True, text=True)
    with open(log, "a", encoding="utf-8") as f:
        f.write(f"$ cyclops-safe-copy {shlex.join(map(str, args))}\n{r.stdout}{r.stderr}\nexit {r.returncode}\n\n")
    return r.returncode, r.stdout


def last_lines(out: str, n: int) -> list[str]:
    return [l for l in out.splitlines() if l.strip()][-n:]


def record_path(out: str) -> Path | None:
    m = re.search(r"Record: (.+record\.json)", out)
    return Path(m.group(1).strip()) if m else None


def independent_fingerprint(root: Path, out_file: Path, *, with_identity: bool) -> str:
    """Fingerprint built ONLY with GNU coreutils/findutils (+getfattr if present) —
    deliberately not the tool's own Python code.  with_identity adds inode + ctime
    (proves the source was not even touched); without it the listing is comparable
    between source and copy."""
    fmt = "%P\\t%y\\t%m\\t%U\\t%G\\t%s\\t%T@\\t%l"
    if with_identity:
        fmt += "\\t%i\\t%C@\\t%n"
    meta = subprocess.run(["find", str(root), "-printf", fmt + "\\0"], capture_output=True, check=True).stdout
    meta_sorted = b"\0".join(sorted(meta.split(b"\0")))
    files = subprocess.run(["find", ".", "-type", "f", "-print0"], cwd=root, capture_output=True,
                           check=True).stdout
    names = sorted(n for n in files.split(b"\0") if n)
    hashes = b""
    for i in range(0, len(names), 500):
        hashes += subprocess.run(["sha256sum", "--", *[n.decode("utf-8", "surrogateescape") for n in names[i:i + 500]]],
                                 cwd=root, capture_output=True, check=True).stdout
    xattrs = b""
    if shutil.which("getfattr"):
        # user xattrs + POSIX ACLs; SELinux labels are assigned per filesystem, so excluded.
        raw = subprocess.run(["getfattr", "-R", "-h", "-d", "-m", r"^(user\.|system\.posix_acl)", "-e", "hex", "."],
                             cwd=root, capture_output=True).stdout
        blocks = [blk.strip() for blk in raw.split(b"\n\n") if blk.strip()]
        xattrs = b"\n\n".join(sorted(blocks))   # traversal order differs between filesystems
    blob = b"META\n" + meta_sorted + b"\nSHA256\n" + hashes + b"\nXATTR\n" + xattrs
    out_file.write_bytes(blob)
    return hashlib.sha256(blob).hexdigest()


def tree_bytes(root: Path) -> int:
    total = 0
    for dp, dn, fn in os.walk(root):
        for n in fn:
            try:
                st = os.lstat(os.path.join(dp, n))
                if not os.path.islink(os.path.join(dp, n)):
                    total += st.st_size
            except OSError:
                pass
    return total


def fmt_rate(nbytes: int, secs) -> str:
    if not secs:
        return "—"
    return f"{nbytes / MiB / secs:.1f}"


def add_timing(rep: Report, label: str, rec_file: Path | None, data_bytes: int) -> None:
    if not rec_file or not rec_file.exists():
        return
    r = json.loads(rec_file.read_text())
    c = (r.get("copy") or {}).get("elapsed_seconds")
    v = (r.get("verification") or {}).get("elapsed_seconds")
    rep.timings.append({"label": label, "mode": r.get("mode"), "data": f"{data_bytes / MiB:.1f} MiB",
                        "copy_s": c if c is not None else "—", "copy_rate": fmt_rate(data_bytes, c),
                        "verify_s": v if v is not None else "—", "verify_rate": fmt_rate(data_bytes, v)})


# --------------------------------------------------------------------------- #
# Fixtures (disposable; created here, never anything pre-existing)
# --------------------------------------------------------------------------- #
def make_small_fixture(root: Path) -> None:
    import random
    rnd = random.Random(1)

    def w(rel, data, mode=None):
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        if mode:
            p.chmod(mode)

    for i in range(150):
        w(f"notes/day-{i:03d}.md", f"# disposable note {i}\n".encode() * rnd.randint(1, 60))
    for i in range(30):
        w(f"assets/blob-{i:02d}.bin", os.urandom(rnd.randint(20_000, 400_000)))
    w("assets/medium.bin", os.urandom(6 * MiB))
    w(".hidden/config.json", b'{"disposable": true}\n')
    w("scripts/run.sh", b"#!/bin/sh\necho acceptance\n", 0o755)
    w("scripts/private.txt", b"not secret\n", 0o600)
    w("odd names/café ☕ ünï.log", b"unicode\n" * 100)
    w("odd names/new\nline.txt", b"newline in name\n")
    w("empty/empty.file", b"")
    (root / "empty" / "empty-dir").mkdir(parents=True, exist_ok=True)
    os.symlink("../notes/day-001.md", root / "odd names" / "link-to-note")
    os.symlink("nowhere", root / "odd names" / "dangling")
    os.link(root / "assets" / "blob-00.bin", root / "assets" / "blob-00-hardlink.bin")
    try:
        os.setxattr(root / "notes" / "day-000.md", "user.cyclops.acceptance", b"1")
    except OSError:
        pass
    if shutil.which("git"):
        repo = root / "mini-repo"
        repo.mkdir()
        g = lambda *a: subprocess.run(["git", "-C", str(repo), "-c", "user.name=Acceptance",
                                       "-c", "user.email=acceptance@example.invalid", *a],
                                      check=True, capture_output=True)
        g("init", "-q")
        w("mini-repo/app.txt", b"v1\n")
        g("add", ".")
        g("commit", "-q", "-m", "v1")
        g("tag", "v1")
        g("branch", "side")
        w("mini-repo/app.txt", b"v2 uncommitted\n")
        w("mini-repo/untracked/new.txt", b"untracked\n")


def make_large_fixture(root: Path, gib: float, rep: Report) -> int:
    root.mkdir(parents=True)
    chunk = 64 * MiB
    n = max(8, int(gib * 1024 * MiB // chunk))
    t0 = time.monotonic()
    for i in range(n):
        with open(root / f"chunk-{i:04d}.bin", "wb") as f:
            for _ in range(chunk // (8 * MiB)):
                f.write(os.urandom(8 * MiB))
    for i in range(200):
        (root / "small").mkdir(exist_ok=True)
        (root / "small" / f"s{i:03d}.txt").write_bytes(os.urandom(1000 + i))
    os.sync()
    rep.log(f"  large fixture: {n} × 64 MiB + 200 small files in {time.monotonic() - t0:.1f}s")
    return n


# --------------------------------------------------------------------------- #
# Steps
# --------------------------------------------------------------------------- #
def parse_pytest(out: str) -> str:
    m = re.findall(r"(\d+ (?:passed|failed|skipped|error|errors|xfailed|xpassed))", out.splitlines()[-1] if out else "")
    return ", ".join(m) if m else (out.splitlines()[-1] if out else "no output")


def step1(rep: Report, ctx: dict, skip_sudo: bool) -> bool:
    py = sys.executable
    other = ctx["hdd_dir"] / "pytest-cross-fs"
    other.mkdir(exist_ok=True)
    env = os.environ.copy()
    env.update(CYCLOPS_TEST_OTHER_FS=str(other), PYTHONDONTWRITEBYTECODE="1")
    env.pop("CYCLOPS_SAFE_COPY_RECORDS", None)
    if sh([py, "-m", "pytest", "--version"]).returncode != 0:
        rep.step("1a", "test suite as normal user", "FAIL",
                 ["pytest is not installed for this Python. Install it, e.g. `sudo apt install python3-pytest`."])
        return False
    rep.log("\n… running the test suite as the normal user (cross-filesystem test targets the HDD)")
    r = subprocess.run([py, "-m", "pytest", "-q", "-rs", "-p", "no:cacheprovider"], cwd=TOOL_DIR,
                       capture_output=True, text=True, env=env)
    (rep.dir / "pytest-user.txt").write_text(r.stdout + r.stderr)
    summary = parse_pytest(r.stdout.strip())
    cross_ran = "CYCLOPS_TEST_OTHER_FS" not in r.stdout and r.returncode == 0
    skipped = [l for l in r.stdout.splitlines() if l.startswith("SKIPPED")]
    rep.step("1a", "test suite as normal user", "PASS" if r.returncode == 0 else "FAIL",
             [f"result: {summary}", f"cross-filesystem test ran against the real HDD: {'yes' if cross_ran else 'NO'}"]
             + [f"skip: {s}" for s in skipped][:12] + ["full output: pytest-user.txt"])
    ok_user = r.returncode == 0

    if skip_sudo:
        rep.step("1b", "test suite with sudo", "SKIP", ["--skip-sudo given"])
        return False
    rep.log("\n… running the test suite with sudo (bind-mount / overlay / tmpfs cases). "
            "sudo may ask for your password.")
    probe = subprocess.run(["sudo", py, "-m", "pytest", "--version"], capture_output=True, text=True)
    if probe.returncode != 0:
        rep.step("1b", "test suite with sudo", "FAIL",
                 ["root's Python cannot import pytest (or sudo failed). A system-wide install fixes it: "
                  "`sudo apt install python3-pytest`.", probe.stderr.strip()[:300]])
        return False
    r = subprocess.run(["sudo", "env", "PYTHONDONTWRITEBYTECODE=1", py, "-m", "pytest", "-q", "-rs",
                        "-p", "no:cacheprovider"], cwd=TOOL_DIR, capture_output=True, text=True)
    (rep.dir / "pytest-sudo.txt").write_text(r.stdout + r.stderr)
    skipped = [l for l in r.stdout.splitlines() if l.startswith("SKIPPED")]
    rep.step("1b", "test suite with sudo", "PASS" if r.returncode == 0 else "FAIL",
             [f"result: {parse_pytest(r.stdout.strip())}"] + [f"skip: {s}" for s in skipped][:12]
             + ["full output: pytest-sudo.txt"])
    return ok_user and r.returncode == 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--hdd-dir", required=True, help="NEW (or empty) directory on the HDD for acceptance copies")
    ap.add_argument("--ssd-dir", default=str(Path.home() / "cyclops-safe-copy-acceptance"),
                    help="NEW (or empty) directory on the SSD for disposable fixtures")
    ap.add_argument("--large-gb", type=float, default=3.0, help="size of the interruption fixture (default 3)")
    ap.add_argument("--records-dir", help="records directory you intend to use in practice "
                                          "(default: the tool's own default / $CYCLOPS_SAFE_COPY_RECORDS)")
    ap.add_argument("--skip-sudo", action="store_true", help="skip the sudo test run (acceptance cannot pass)")
    ap.add_argument("--no-tag", action="store_true", help="do not preserve/tag V1 even if everything passes")
    a = ap.parse_args()

    ssd = Path(os.path.expanduser(a.ssd_dir)).resolve()
    hdd = Path(os.path.expanduser(a.hdd_dir)).resolve()
    for p, label in ((ssd, "--ssd-dir"), (hdd, "--hdd-dir")):
        if p.exists() and (not p.is_dir() or any(p.iterdir())):
            print(f"REFUSED: {label} {p} exists and is not empty. Give a NEW folder name; this script only "
                  "works in folders it creates, so it can never touch real data.")
            return 2
        if not p.parent.is_dir():
            print(f"REFUSED: parent of {label} ({p.parent}) does not exist.")
            return 2
    ssd.mkdir(exist_ok=True)
    hdd.mkdir(exist_ok=True)
    if os.stat(ssd).st_dev == os.stat(hdd).st_dev:
        print("REFUSED: --ssd-dir and --hdd-dir are on the same filesystem; this must be a real SSD→HDD pair.")
        return 2

    started = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    out_dir = hdd / f"acceptance-report-{started.replace(':', '')}"
    out_dir.mkdir()
    rep = Report(out_dir)
    tool_log = out_dir / "tool-runs.log"
    ctx = {"started": started, "ssd_dir": ssd, "hdd_dir": hdd}
    ctx["tool_version"] = sh([str(TOOL), "--version"]).stdout.strip()
    rep.log(f"Cyclops Safe Copier acceptance — {ctx['tool_version']} — {started}")
    rep.log(f"SSD fixtures : {ssd}\nHDD copies   : {hdd}\nReport       : {out_dir}")

    s_m, h_m = findmnt(ssd), findmnt(hdd)
    rep.fs_notes += [f"SSD side: {s_m['fstype']} on {s_m['source']} mounted at {s_m['target']} "
                     f"(options {s_m['options']}); {disk_info(s_m['source'])}",
                     f"HDD side: {h_m['fstype']} on {h_m['source']} mounted at {h_m['target']} "
                     f"(options {h_m['options']}); {disk_info(h_m['source'])}"]
    for n in rep.fs_notes:
        rep.log(n)
    rs, rh = rotational(s_m["source"]), rotational(h_m["source"])
    if rs == "1" or rh == "0":
        rep.fs_notes.append(f"NOTE: rotational flags are SSD side={rs}, HDD side={rh} — check the two paths "
                            "really are the SSD and the HDD")

    try:
        # ---- 1. test suites ---------------------------------------------------
        if not step1(rep, ctx, a.skip_sudo):
            rep.log("\nTest suites did not both pass — stopping before any real-disk copy (as required).")
            return finish(rep, ctx, a)

        # ---- fixtures -----------------------------------------------------------
        small = ssd / "small-fixture"
        make_small_fixture(small)
        small_bytes = tree_bytes(small)
        large_gib = a.large_gb
        need = int(large_gib * 1024 * MiB * 1.1) + 512 * MiB
        if shutil.disk_usage(ssd).free < need or shutil.disk_usage(hdd).free < need * 2:
            rep.step("7", "interrupt + resume", "FAIL", [f"not enough free space for a {large_gib} GiB fixture; "
                                                         "re-run with a smaller --large-gb"])
            return finish(rep, ctx, a)

        records_args = ["--records-dir", a.records_dir] if a.records_dir else []
        ssd_state_fallback = Path.home() / ".local" / "state" / "cyclops-safe-copy"
        fallback_before = ssd_state_fallback.exists()

        # ---- 2 + 3. dry run & records location --------------------------------
        dst_small = hdd / "small-copy"
        rc, out = run_tool([small, dst_small, "--dry-run", *records_args], tool_log)
        rec = record_path(out)
        dry_ok = rc == 0 and last_lines(out, 1) == [DRY] and not dst_small.exists()
        if rc == 2 and "records directory" in out:
            rep.step("2", "records location resolves onto the HDD", "FAIL",
                     ["the tool could not create its default records directory on the HDD (permissions?).",
                      "Fix: create it once, owned by you, e.g. `sudo mkdir <HDD mount>/cyclops-safe-copy-records && "
                      "sudo chown $USER: <that dir>` — or export CYCLOPS_SAFE_COPY_RECORDS=<dir on HDD> / pass "
                      "--records-dir; then re-run this acceptance.",
                      "Continuing with an explicit records dir inside --hdd-dir so the remaining checks still run."])
            records_args = ["--records-dir", str(hdd / "records")]
            rc, out = run_tool([small, dst_small, "--dry-run", *records_args], tool_log)
            rec = record_path(out)
            dry_ok = rc == 0 and last_lines(out, 1) == [DRY] and not dst_small.exists()
            records_failed = True
        else:
            records_failed = False
        records_dir = rec.parent.parent.parent if rec else None
        ctx["records_dir"] = records_dir
        rep.step("3", "--dry-run of small SSD fixture onto the HDD", "PASS" if dry_ok else "FAIL",
                 [f"exit {rc}; last line: {last_lines(out, 1)}", f"destination created: {dst_small.exists()}",
                  f"fixture: {small_bytes / MiB:.1f} MiB"])
        if not dry_ok:
            return finish(rep, ctx, a)

        # ---- 4 + 5 + 6. real copy, exact ending, independent source proof ----
        fp_before = independent_fingerprint(small, out_dir / "small-source-before.fp", with_identity=True)
        rc, out = run_tool([small, dst_small, *records_args], tool_log)
        rec_small = record_path(out)
        fp_after = independent_fingerprint(small, out_dir / "small-source-after.fp", with_identity=True)
        rep.step("4", "real SSD→HDD copy of the small fixture", "PASS" if rc == 0 else "FAIL",
                 [f"exit {rc}", f"record: {rec_small}"])
        ending = last_lines(out, 2)
        rep.step("5", "output ends exactly with the runtime line", "PASS" if ending == [VERIFIED, RUNTIME] else "FAIL",
                 [f"last two lines: {ending}"])
        src_cmp = independent_fingerprint(small, out_dir / "small-source.cmp", with_identity=False)
        dst_cmp = independent_fingerprint(dst_small, out_dir / "small-dest.cmp", with_identity=False)
        rep.step("6", "independent proof the source is unchanged (coreutils, not the tool)",
                 "PASS" if fp_before == fp_after else "FAIL",
                 [f"source fingerprint before: {fp_before}", f"source fingerprint after : {fp_after}",
                  "fingerprint = find -printf (type, mode, owner, size, mtime ns, symlink target, inode, ctime ns, "
                  "link count) + sha256sum of every file + getfattr dump",
                  f"bonus — copy vs source (content + metadata, no inode/ctime): "
                  f"{'IDENTICAL' if src_cmp == dst_cmp else 'DIFFERENT'} ({dst_cmp[:16]}… vs {src_cmp[:16]}…)"])
        if src_cmp != dst_cmp:
            rep.steps[-1]["status"] = "FAIL"
        add_timing(rep, "small fixture copy", rec_small, small_bytes)

        # records really on the HDD
        if records_dir and not records_failed:
            on_hdd = os.stat(records_dir).st_dev == os.stat(hdd).st_dev
            on_ssd = os.stat(records_dir).st_dev == os.stat(ssd).st_dev
            rec_bytes = tree_bytes(records_dir)
            fallback_new = ssd_state_fallback.exists() and not fallback_before
            mt = findmnt(records_dir)
            ok2 = on_hdd and not on_ssd and not fallback_new
            rep.step("2", "records location resolves onto the HDD", "PASS" if ok2 else "FAIL",
                     [f"records directory: {records_dir}",
                      f"its filesystem: {mt['source']} ({mt['fstype']}) at {mt['target']} — "
                      f"same device as the HDD: {on_hdd}; same device as the SSD: {on_ssd}",
                      f"records + manifests written so far: {rec_bytes / 1024:.1f} KiB, all on that device",
                      f"SSD fallback ~/.local/state/cyclops-safe-copy newly created: {fallback_new}",
                      "how chosen: " + ("--records-dir" if a.records_dir else
                                        "$CYCLOPS_SAFE_COPY_RECORDS" if os.environ.get("CYCLOPS_SAFE_COPY_RECORDS")
                                        else "tool default (<HDD mount>/cyclops-safe-copy-records)")])

        # ---- 7. deliberate interruption of a larger copy + resume -------------
        large = ssd / "large-fixture"
        n_chunks = make_large_fixture(large, large_gib, rep)
        large_bytes = tree_bytes(large)
        dst_large = hdd / "large-copy"
        lfp_before = independent_fingerprint(large, out_dir / "large-source-before.fp", with_identity=True)
        details = []
        with open(out_dir / "large-interrupted-run.txt", "w") as lf:
            p = subprocess.Popen([str(TOOL), str(large), str(dst_large), *records_args], stdout=lf,
                                 stderr=subprocess.STDOUT, start_new_session=True)
            t0 = time.monotonic()
            while time.monotonic() - t0 < 600:
                done = len(list(dst_large.glob("chunk-*.bin"))) if dst_large.exists() else 0
                if done >= 3 or p.poll() is not None:
                    break
                time.sleep(0.2)
            interrupted_at = len(list(dst_large.glob("chunk-*.bin"))) if dst_large.exists() else 0
            finished_first = p.poll() is not None
            if not finished_first:
                os.kill(p.pid, signal.SIGINT)        # what Ctrl-C does
            rc_int = p.wait(timeout=300)
        landed_bytes = tree_bytes(dst_large) if dst_large.exists() else 0
        out_int = (out_dir / "large-interrupted-run.txt").read_text()
        details.append(f"fixture: {n_chunks} × 64 MiB + 200 small ({large_bytes / MiB:.0f} MiB); "
                       f"SIGINT sent after {interrupted_at} of {n_chunks} chunks had landed")
        ok7 = True
        if finished_first:
            ok7 = False
            details.append("copy finished before it could be interrupted — re-run with a larger --large-gb")
        if rc_int != 3 or last_lines(out_int, 1) != [INCOMPLETE]:
            ok7 = False
        details.append(f"interrupted run: exit {rc_int}, last line {last_lines(out_int, 1)}")
        time.sleep(2)
        lingering = [l for l in sh(["pgrep", "-af", "rsync"]).stdout.splitlines() if str(dst_large) in l]
        snap1 = sorted((q.name, q.stat().st_size) for q in dst_large.glob("*")) if dst_large.exists() else []
        time.sleep(2)
        snap2 = sorted((q.name, q.stat().st_size) for q in dst_large.glob("*")) if dst_large.exists() else []
        if lingering or snap1 != snap2:
            ok7 = False
        details.append(f"rsync still running after interrupt: {'YES — ' + lingering[0] if lingering else 'no'}; "
                       f"destination stable afterwards: {snap1 == snap2}")
        junk = [q.name for q in dst_large.rglob(".chunk-*")] if dst_large.exists() else []
        details.append(f"rsync temp files inside destination: {junk or 'none'}")
        if junk:
            ok7 = False
        rc_plain, out_plain = run_tool([large, dst_large, *records_args], tool_log)
        plain_ok = rc_plain == 2 and "--resume" in out_plain and last_lines(out_plain, 1) == [REFUSED]
        details.append(f"plain re-run (without --resume): exit {rc_plain}, refused and pointed at --resume: {plain_ok}")
        ok7 &= plain_ok
        rc_res, out_res = run_tool([large, dst_large, "--resume", *records_args], tool_log)
        rec_res = record_path(out_res)
        res_ok = rc_res == 0 and last_lines(out_res, 2) == [VERIFIED, RUNTIME]
        resume_cmd = json.loads(rec_res.read_text())["copy"]["command"] if rec_res else ""
        details.append(f"--resume: exit {rc_res}, last lines {last_lines(out_res, 2)}; "
                       f"re-checked by checksum: {'--checksum' in resume_cmd}")
        ok7 &= res_ok and "--checksum" in resume_cmd
        lfp_after = independent_fingerprint(large, out_dir / "large-source-after.fp", with_identity=True)
        lsrc = independent_fingerprint(large, out_dir / "large-source.cmp", with_identity=False)
        ldst = independent_fingerprint(dst_large, out_dir / "large-dest.cmp", with_identity=False)
        details.append(f"independent: source unchanged through interrupt+resume: {lfp_before == lfp_after}; "
                       f"copy identical to source: {lsrc == ldst}")
        ok7 &= lfp_before == lfp_after and lsrc == ldst
        rep.step("7", "deliberate interruption of a larger copy, then --resume", "PASS" if ok7 else "FAIL", details)
        rec_int = record_path(out_int)
        add_timing(rep, "large copy (interrupted part, bytes landed)", rec_int, landed_bytes)
        add_timing(rep, "large copy --resume (checksum re-check + rest)", rec_res, large_bytes)

        # ---- 8. timings + filesystem differences ------------------------------
        fs_details = filesystem_observations(rep, ssd, hdd, rec_small, rec_res)
        rep.step("8", "elapsed times and filesystem differences reported",
                 "PASS" if rep.timings else "FAIL",
                 [f"{t['label']}: copy {t['copy_s']} s ({t['copy_rate']} MB/s), verify {t['verify_s']} s "
                  f"({t['verify_rate']} MB/s of data)" for t in rep.timings] + fs_details)
    except Exception as e:  # report, never hide
        rep.step("X", "acceptance script error", "FAIL", [f"{type(e).__name__}: {e}"])
    return finish(rep, ctx, a)


def filesystem_observations(rep: Report, ssd: Path, hdd: Path, rec_small, rec_res) -> list[str]:
    notes = []
    probe = hdd / "fs-probe"
    probe.mkdir(exist_ok=True)
    f = probe / "probe.txt"
    f.write_bytes(b"probe")
    os.utime(f, ns=(1_700_000_000_123_456_789, 1_700_000_000_123_456_789))
    got = os.stat(f).st_mtime_ns
    notes.append(f"HDD timestamp resolution: wrote …123456789 ns, read back …{got % 10**9:09d} ns "
                 f"({'nanosecond' if got == 1_700_000_000_123_456_789 else 'COARSER — would break ns verification'})")
    try:
        os.setxattr(f, "user.cyclops.probe", b"1")
        notes.append("HDD user xattrs: supported")
    except OSError as e:
        notes.append(f"HDD user xattrs: NOT supported ({e.strerror})")
    if shutil.which("setfacl"):
        r = sh(["setfacl", "-m", f"u:{os.getuid()}:r", str(f)])
        notes.append("HDD POSIX ACLs: " + ("supported" if r.returncode == 0 else f"NOT supported ({r.stderr.strip()})"))
    for label, recf in (("small copy", rec_small), ("large resume", rec_res)):
        if recf and recf.exists():
            r = json.loads(recf.read_text())
            st = (r.get("verification") or {}).get("structural") or {}
            notes.append(f"{label}: on-disk bytes source {st.get('on_disk_bytes_source', '?'):,} vs destination "
                         f"{st.get('on_disk_bytes_destination', '?'):,} (block allocation differs by filesystem; "
                         "content and logical sizes are verified equal)")
            for w in r.get("warnings", []):
                notes.append(f"{label} tool warning: {w}")
    rep.fs_notes += notes
    return notes


def finish(rep: Report, ctx: dict, a) -> int:
    passed = rep.all_passed()
    if passed and not a.no_tag:
        ctx["tag_note"] = preserve_v1(rep, ctx)
    elif not passed:
        ctx["tag_note"] = ["Not preserved/tagged: acceptance did not fully pass."]
    else:
        ctx["tag_note"] = ["Not tagged: --no-tag given."]
    path = rep.save(ctx)
    rep.log(f"\nReport: {path}")
    rep.log("ALL MACHINE-LOCAL ACCEPTANCE CHECKS PASSED" if passed else "ACCEPTANCE NOT PASSED")
    return 0 if passed else 1


def preserve_v1(rep: Report, ctx: dict) -> list[str]:
    notes = []
    files = [p for p in sorted(TOOL_DIR.rglob("*")) if p.is_file()
             and "__pycache__" not in p.parts and ".git" not in p.parts and ".pytest_cache" not in p.parts]
    sums = "".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(TOOL_DIR)}\n" for p in files)
    version = ctx.get("tool_version", "cyclops-safe-copy").split()[-1]
    name = f"cyclops-safe-copier-{version}-accepted"
    (rep.dir / f"{name}.SHA256SUMS").write_text(sums)
    tar_path = rep.dir / f"{name}.tar.gz"
    with tarfile.open(tar_path, "w:gz") as t:
        for p in files:
            t.add(p, arcname=f"cyclops-safe-copier/{p.relative_to(TOOL_DIR)}")
    tar_sha = hashlib.sha256(tar_path.read_bytes()).hexdigest()
    notes.append(f"immutable snapshot: {tar_path} (sha256 {tar_sha})")
    notes.append(f"per-file checksums: {rep.dir / (name + '.SHA256SUMS')}")
    try:
        os.chmod(tar_path, 0o444)
        os.chmod(rep.dir / f"{name}.SHA256SUMS", 0o444)
    except OSError:
        pass
    if not shutil.which("git"):
        return notes + ["git not installed: no tag created (snapshot above is the preserved V1)."]
    top = sh(["git", "-C", str(TOOL_DIR), "rev-parse", "--show-toplevel"])
    tag = f"safe-copier-v{version}-accepted"
    ident = []
    if not sh(["git", "config", "user.email"]).stdout.strip():
        ident = ["-c", "user.name=Cyclops Safe Copier acceptance", "-c", "user.email=acceptance@localhost"]
    if top.returncode == 0 and Path(top.stdout.strip()).resolve() != TOOL_DIR:
        return notes + [f"tool folder is inside another git repository ({top.stdout.strip()}); left untouched. "
                        f"Tag it yourself if wanted: git tag -a {tag}"]
    if top.returncode != 0:
        sh(["git", "-C", str(TOOL_DIR), "init", "-q"])
    if sh(["git", "-C", str(TOOL_DIR), "rev-parse", "-q", "--verify", f"refs/tags/{tag}"]).returncode == 0:
        return notes + [f"tag {tag} already exists; not changed"]
    sh(["git", "-C", str(TOOL_DIR), "add", "-A"])
    dirty = sh(["git", "-C", str(TOOL_DIR), "status", "--porcelain"]).stdout.strip()
    if dirty:
        c = sh(["git", *ident, "-C", str(TOOL_DIR), "commit", "-q", "-m",
                f"Cyclops Safe Copier {version} — accepted on {os.uname().nodename}"])
        if c.returncode != 0:
            return notes + [f"git commit failed: {c.stderr.strip()[:200]}"]
    msg = (f"Cyclops Safe Copier {version} passed machine-local SSD→HDD acceptance on "
           f"{os.uname().nodename} at {ctx['started']}.\nSnapshot sha256: {tar_sha}\nReport: {rep.dir}")
    t = sh(["git", *ident, "-C", str(TOOL_DIR), "tag", "-a", tag, "-m", msg])
    if t.returncode != 0:
        return notes + [f"git tag failed: {t.stderr.strip()[:200]}"]
    head = sh(["git", "-C", str(TOOL_DIR), "rev-parse", "HEAD"]).stdout.strip()
    return notes + [f"git tag {tag} created on commit {head[:12]} in {TOOL_DIR}"]


if __name__ == "__main__":
    sys.exit(main())
