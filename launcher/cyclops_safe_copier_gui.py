#!/usr/bin/env python3
"""Cyclops Safe Copier — desktop window.

A friendly front-end for the accepted command-line tool (cyclops_safe_copy.py).
It never copies anything itself: it builds the same command you would type,
runs it, streams the output, and shows the final verdict.  All safety guards,
verification and records stay in the command-line tool.

Falls back to a plain terminal wizard if GTK is not available.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import threading
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOL_DIR = HERE.parent
TOOL = TOOL_DIR / "cyclops_safe_copy.py"
ICON = HERE / "cyclops-safe-copier.svg"
ACCEPT_TAG_PREFIX = "safe-copier-v"
CONFIG = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "cyclops-safe-copier" / "gui.json"

MODES = [
    ("dry-run", "Check only (dry run)", "Runs every safety check and shows the exact command. Copies nothing."),
    ("copy", "Copy + verify", "Copies, then proves the copy is exact. The source is never changed."),
    ("resume", "Resume an interrupted copy", "Continues a copy this tool started. Re-checks every file by checksum."),
    ("verify-only", "Verify an existing copy", "Re-proves a copy made earlier. Writes nothing to either side."),
]
STATE_STYLE = {
    "COPY VERIFIED": ("verified", "Copy verified — source unchanged. Runtime/cutover not implied."),
    "DRY RUN": ("info", "Dry run — nothing was copied."),
    "REFUSED": ("warn", "Refused — nothing was copied. See the reason above."),
    "COPY INCOMPLETE": ("warn", "Copy incomplete — partial copy left as is. Use “Resume” to continue."),
    "COPY COMPLETE — VERIFICATION FAILED": ("bad", "Verification FAILED — nothing repaired or deleted."),
    "VERIFICATION FAILED": ("bad", "Verification FAILED — nothing was copied or changed."),
}


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #
def acceptance_tag() -> str | None:
    if not shutil.which("git"):
        return None
    try:
        top = subprocess.run(["git", "-C", str(TOOL_DIR), "rev-parse", "--show-toplevel"],
                             capture_output=True, text=True, timeout=10)
        if top.returncode != 0 or Path(top.stdout.strip()).resolve() != TOOL_DIR.resolve():
            return None
        r = subprocess.run(["git", "-C", str(TOOL_DIR), "tag", "-l", f"{ACCEPT_TAG_PREFIX}*-accepted"],
                           capture_output=True, text=True, timeout=10)
        tags = r.stdout.split()
        return tags[-1] if tags else None
    except (OSError, subprocess.SubprocessError):
        return None


def tool_version() -> str:
    try:
        r = subprocess.run([sys.executable, str(TOOL), "--version"], capture_output=True, text=True, timeout=20)
        return r.stdout.strip().split()[-1]
    except (OSError, subprocess.SubprocessError, IndexError):
        return "?"


def build_command(src: str, dst: str, mode: str, records: str = "", bwlimit: str = "") -> list[str]:
    cmd = [sys.executable, str(TOOL), src, dst]
    if mode != "copy":
        cmd.append(f"--{mode}")
    if records.strip():
        cmd += ["--records-dir", records.strip()]
    if bwlimit.strip():
        cmd += ["--bwlimit", bwlimit.strip()]
    return cmd


def classify(state_line: str) -> tuple[str, str]:
    for key, val in STATE_STYLE.items():
        if state_line.startswith(key):
            return val
    return ("bad", state_line or "No final state reported.")


def load_config() -> dict:
    try:
        return json.loads(CONFIG.read_text())
    except (OSError, ValueError):
        return {}


def save_config(cfg: dict) -> None:
    try:
        CONFIG.parent.mkdir(parents=True, exist_ok=True)
        CONFIG.write_text(json.dumps(cfg, indent=2))
    except OSError:
        pass


ACCEPTANCE_CMD = (f"cd {shlex.quote(str(TOOL_DIR))} && python3 acceptance/cyclops_acceptance.py "
                  "--hdd-dir /media/$USER/<HDD>/cyclops-safe-copy-acceptance")


# --------------------------------------------------------------------------- #
# GTK window
# --------------------------------------------------------------------------- #
def run_gtk() -> int:
    import gi
    gi.require_version("Gtk", "3.0")
    gi.require_version("Gdk", "3.0")
    from gi.repository import Gdk, GLib, Gtk

    GLib.set_prgname("cyclops-safe-copier")
    GLib.set_application_name("Cyclops Safe Copier")

    css = b"""
    .banner { padding: 8px 12px; border-radius: 8px; }
    .banner-ok   { background: #1f6f4a; color: #ffffff; }
    .banner-warn { background: #8a5a00; color: #ffffff; }
    .result { padding: 12px 14px; border-radius: 10px; font-weight: bold; font-size: 115%; }
    .result-verified { background: #1f6f4a; color: #ffffff; }
    .result-info     { background: #2d4f7c; color: #ffffff; }
    .result-warn     { background: #8a5a00; color: #ffffff; }
    .result-bad      { background: #9b2226; color: #ffffff; }
    .result-idle     { background: alpha(currentColor, 0.08); }
    .hint { opacity: 0.75; }
    textview.log text { background: #101418; color: #d8e1e8; }
    textview.log { font-family: monospace; font-size: 95%; }
    """
    provider = Gtk.CssProvider()
    provider.load_from_data(css)
    Gtk.StyleContext.add_provider_for_screen(Gdk.Screen.get_default(), provider,
                                             Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)

    class Win(Gtk.ApplicationWindow):
        def __init__(self, app):
            super().__init__(application=app, title="Cyclops Safe Copier")
            self.set_default_size(820, 720)
            if ICON.exists():
                try:
                    self.set_icon_from_file(str(ICON))
                except GLib.Error:
                    pass
            self.proc: subprocess.Popen | None = None
            self.cfg = load_config()
            self.last_record: str | None = None
            self.accepted = acceptance_tag()
            self.dst_auto = True

            hb = Gtk.HeaderBar(show_close_button=True, title="Cyclops Safe Copier",
                               subtitle=f"v{tool_version()} · copy · verify · never delete")
            self.set_titlebar(hb)

            root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10, margin=14)
            self.add(root)

            # acceptance banner
            ban = Gtk.Box(spacing=10)
            ban.get_style_context().add_class("banner")
            if self.accepted:
                ban.get_style_context().add_class("banner-ok")
                ban.pack_start(Gtk.Label(label=f"✔  Accepted on this machine ({self.accepted})", xalign=0), True, True, 0)
            else:
                ban.get_style_context().add_class("banner-warn")
                lab = Gtk.Label(xalign=0, wrap=True)
                lab.set_markup("<b>Not yet accepted on this machine.</b> Use disposable test folders only — "
                               "nothing valuable until acceptance passes.")
                ban.pack_start(lab, True, True, 0)
                b = Gtk.Button(label="How to run acceptance")
                b.connect("clicked", self.show_acceptance)
                ban.pack_end(b, False, False, 0)
            root.pack_start(ban, False, False, 0)

            grid = Gtk.Grid(column_spacing=8, row_spacing=8)
            root.pack_start(grid, False, False, 0)

            grid.attach(Gtk.Label(label="Source", xalign=1), 0, 0, 1, 1)
            self.src = Gtk.Entry(hexpand=True, placeholder_text="Folder (or file) to copy — it is never changed")
            self.src.set_text(self.cfg.get("src", ""))
            self.src.connect("changed", self.on_src_changed)
            grid.attach(self.src, 1, 0, 1, 1)
            bs = Gtk.Button(label="Choose…")
            bs.connect("clicked", self.pick_source)
            grid.attach(bs, 2, 0, 1, 1)

            grid.attach(Gtk.Label(label="Copy to", xalign=1), 0, 1, 1, 1)
            self.dst = Gtk.Entry(hexpand=True, placeholder_text="New (or empty) folder on the other disk")
            self.dst.set_text(self.cfg.get("dst", ""))
            self.dst.connect("changed", self.on_dst_edited)
            grid.attach(self.dst, 1, 1, 1, 1)
            bd = Gtk.Button(label="Choose…")
            bd.set_tooltip_text("Pick the folder on the destination disk; a new sub-folder named after the "
                                "source is used inside it")
            bd.connect("clicked", self.pick_dest)
            grid.attach(bd, 2, 1, 1, 1)
            self.dst_hint = Gtk.Label(xalign=0, wrap=True)
            self.dst_hint.get_style_context().add_class("hint")
            grid.attach(self.dst_hint, 1, 2, 2, 1)

            # modes
            mbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
            grid.attach(Gtk.Label(label="Action", xalign=1, valign=Gtk.Align.START), 0, 3, 1, 1)
            grid.attach(mbox, 1, 3, 2, 1)
            self.mode_buttons = {}
            group = None
            for key, title, hint in MODES:
                rb = Gtk.RadioButton.new_with_label_from_widget(group, title)
                group = group or rb
                rb.set_tooltip_text(hint)
                self.mode_buttons[key] = rb
                row = Gtk.Box(spacing=10)
                row.pack_start(rb, False, False, 0)
                h = Gtk.Label(label=hint, xalign=0)
                h.get_style_context().add_class("hint")
                row.pack_start(h, False, False, 0)
                mbox.pack_start(row, False, False, 0)
            self.mode_buttons["dry-run"].set_active(True)

            # advanced
            exp = Gtk.Expander(label="Advanced")
            adv = Gtk.Grid(column_spacing=8, row_spacing=6, margin_top=6)
            exp.add(adv)
            adv.attach(Gtk.Label(label="Records folder", xalign=1), 0, 0, 1, 1)
            self.records = Gtk.Entry(hexpand=True, placeholder_text="blank = tool default "
                                     "(on the destination disk, never the SSD)")
            self.records.set_text(self.cfg.get("records", ""))
            adv.attach(self.records, 1, 0, 1, 1)
            br = Gtk.Button(label="Choose…")
            br.connect("clicked", lambda *_: self.pick_into(self.records, "Choose records folder"))
            adv.attach(br, 2, 0, 1, 1)
            adv.attach(Gtk.Label(label="Bandwidth limit", xalign=1), 0, 1, 1, 1)
            self.bw = Gtk.Entry(placeholder_text="KiB/s, blank = unlimited (copy already runs at low priority)")
            adv.attach(self.bw, 1, 1, 1, 1)
            grid.attach(exp, 1, 4, 2, 1)

            # buttons
            bb = Gtk.Box(spacing=8)
            self.run_btn = Gtk.Button(label="Run")
            self.run_btn.get_style_context().add_class("suggested-action")
            self.run_btn.connect("clicked", self.on_run)
            self.stop_btn = Gtk.Button(label="Stop safely", sensitive=False)
            self.stop_btn.set_tooltip_text("Interrupts like Ctrl-C: the partial copy is kept; resume later")
            self.stop_btn.connect("clicked", self.on_stop)
            self.rec_btn = Gtk.Button(label="Open record folder", sensitive=False)
            self.rec_btn.connect("clicked", self.open_record)
            self.cmd_btn = Gtk.Button(label="Copy command")
            self.cmd_btn.set_tooltip_text("Copy the equivalent terminal command to the clipboard")
            self.cmd_btn.connect("clicked", self.copy_command)
            bb.pack_start(self.run_btn, False, False, 0)
            bb.pack_start(self.stop_btn, False, False, 0)
            bb.pack_end(self.rec_btn, False, False, 0)
            bb.pack_end(self.cmd_btn, False, False, 0)
            root.pack_start(bb, False, False, 0)

            # result banner
            self.result = Gtk.Label(label="Ready. Start with “Check only” to see what would happen.",
                                    xalign=0, wrap=True)
            self.result.get_style_context().add_class("result")
            self.result.get_style_context().add_class("result-idle")
            root.pack_start(self.result, False, False, 0)

            # log
            sw = Gtk.ScrolledWindow(vexpand=True)
            self.view = Gtk.TextView(editable=False, cursor_visible=False, monospace=True,
                                     wrap_mode=Gtk.WrapMode.WORD_CHAR, left_margin=8, right_margin=8,
                                     top_margin=6, bottom_margin=6)
            self.view.get_style_context().add_class("log")
            self.buf = self.view.get_buffer()
            sw.add(self.view)
            root.pack_start(sw, True, True, 0)

            self.connect("delete-event", self.on_close)
            self.update_hint()

        # ----- helpers -----
        def mode(self) -> str:
            return next(k for k, b in self.mode_buttons.items() if b.get_active())

        def update_hint(self):
            d = self.dst.get_text().strip()
            if not d:
                self.dst_hint.set_text("")
                return
            p = Path(os.path.expanduser(d))
            if p.exists():
                try:
                    n = len(os.listdir(p))
                except OSError:
                    n = -1
                state = ("exists and is empty — OK for a new copy" if n == 0 else
                         f"exists with {n} items — only Resume / Verify can use it" if n > 0 else
                         "exists but cannot be read")
            else:
                state = ("will be created" if p.parent.is_dir()
                         else "parent folder does not exist — create it first")
            self.dst_hint.set_text(f"→ {p}  ({state})")

        def on_src_changed(self, *_):
            if self.dst_auto and self.cfg.get("dst_parent"):
                name = Path(self.src.get_text().strip().rstrip("/")).name
                if name:
                    self.dst.handler_block_by_func(self.on_dst_edited)
                    self.dst.set_text(str(Path(self.cfg["dst_parent"]) / name))
                    self.dst.handler_unblock_by_func(self.on_dst_edited)
            self.update_hint()

        def on_dst_edited(self, *_):
            self.dst_auto = False
            self.update_hint()

        def chooser(self, title, action=Gtk.FileChooserAction.SELECT_FOLDER, start=None):
            dlg = Gtk.FileChooserDialog(title=title, transient_for=self, action=action)
            dlg.add_buttons("Cancel", Gtk.ResponseType.CANCEL, "Select", Gtk.ResponseType.OK)
            if start and Path(start).is_dir():
                dlg.set_current_folder(start)
            path = dlg.get_filename() if dlg.run() == Gtk.ResponseType.OK else None
            dlg.destroy()
            return path

        def pick_source(self, *_):
            p = self.chooser("Choose the folder to copy (it will not be changed)",
                             start=self.cfg.get("src_parent") or str(Path.home()))
            if p:
                self.cfg["src_parent"] = str(Path(p).parent)
                self.src.set_text(p)

        def pick_dest(self, *_):
            p = self.chooser("Choose WHERE the copy goes (a folder on the destination disk)",
                             start=self.cfg.get("dst_parent") or "/media")
            if p:
                self.cfg["dst_parent"] = p
                name = Path(self.src.get_text().strip().rstrip("/")).name or "copy"
                self.dst_auto = True
                self.dst.handler_block_by_func(self.on_dst_edited)
                self.dst.set_text(str(Path(p) / name))
                self.dst.handler_unblock_by_func(self.on_dst_edited)
                self.update_hint()

        def pick_into(self, entry, title):
            p = self.chooser(title)
            if p:
                entry.set_text(p)

        def append(self, text):
            end = self.buf.get_end_iter()
            self.buf.insert(end, text)
            mark = self.buf.create_mark(None, self.buf.get_end_iter(), False)
            self.view.scroll_mark_onscreen(mark)
            return False

        def set_result(self, style, text):
            ctx = self.result.get_style_context()
            for s in ("verified", "info", "warn", "bad", "idle"):
                ctx.remove_class(f"result-{s}")
            ctx.add_class(f"result-{style}")
            self.result.set_text(text)

        def message(self, kind, title, body, buttons=Gtk.ButtonsType.OK):
            dlg = Gtk.MessageDialog(transient_for=self, modal=True, message_type=kind,
                                    buttons=buttons, text=title)
            dlg.format_secondary_markup(body)
            r = dlg.run()
            dlg.destroy()
            return r

        def show_acceptance(self, *_):
            self.get_clipboard(Gdk.SELECTION_CLIPBOARD).set_text(ACCEPTANCE_CMD, -1)
            self.message(Gtk.MessageType.INFO, "Run the machine-local acceptance",
                         "Open a terminal and run (already copied to your clipboard):\n\n"
                         f"<tt>{GLib.markup_escape_text(ACCEPTANCE_CMD)}</tt>\n\n"
                         "Replace &lt;HDD&gt; with your HDD's name. It asks for your sudo password once, "
                         "works only in new disposable folders, and tags V1 only if every check passes. "
                         "This window turns green once the tag exists.")

        def copy_command(self, *_):
            cmd = build_command(self.src.get_text().strip(), self.dst.get_text().strip(), self.mode(),
                                self.records.get_text(), self.bw.get_text())
            text = shlex.join(["cyclops-safe-copy", *cmd[2:]])
            self.get_clipboard(Gdk.SELECTION_CLIPBOARD).set_text(text, -1)
            self.set_result("idle", f"Command copied: {text}")

        # ----- running -----
        def on_run(self, *_):
            src = os.path.expanduser(self.src.get_text().strip())
            dst = os.path.expanduser(self.dst.get_text().strip())
            mode = self.mode()
            if not src or not dst:
                self.set_result("warn", "Choose a source and a destination first.")
                return
            if mode == "copy" or mode == "resume":
                warn = "" if self.accepted else (
                    "\n\n<b>This machine has not passed acceptance yet.</b> Only use disposable test data.")
                r = self.message(Gtk.MessageType.QUESTION, "Start copying?",
                                 f"<b>From</b>  {GLib.markup_escape_text(src)}\n"
                                 f"<b>To</b>      {GLib.markup_escape_text(dst)}\n\n"
                                 "The source is never changed. The copy is verified independently afterwards. "
                                 "Nothing is deleted, moved or symlinked." + warn,
                                 Gtk.ButtonsType.OK_CANCEL)
                if r != Gtk.ResponseType.OK:
                    return
            self.cfg.update(src=self.src.get_text().strip(), dst=self.dst.get_text().strip(),
                            records=self.records.get_text().strip())
            save_config(self.cfg)
            cmd = build_command(src, dst, mode, self.records.get_text(), self.bw.get_text())
            self.buf.set_text("$ " + shlex.join(["cyclops-safe-copy", *cmd[2:]]) + "\n\n")
            self.set_result("info", "Running… (safety checks, then " +
                            {"dry-run": "nothing else", "copy": "copy and verification",
                             "resume": "resume and verification", "verify-only": "verification"}[mode] + ")")
            self.run_btn.set_sensitive(False)
            self.stop_btn.set_sensitive(mode in ("copy", "resume", "verify-only"))
            self.rec_btn.set_sensitive(False)
            env = dict(os.environ, PYTHONUNBUFFERED="1")
            try:
                self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                             stdin=subprocess.DEVNULL, env=env, bufsize=1, text=True,
                                             encoding="utf-8", errors="replace")
            except OSError as e:
                self.set_result("bad", f"Could not start the tool: {e}")
                self.run_btn.set_sensitive(True)
                return
            threading.Thread(target=self.reader, args=(self.proc,), daemon=True).start()

        def reader(self, proc):
            lines = []
            for line in proc.stdout:
                lines.append(line)
                GLib.idle_add(self.append, line)
            rc = proc.wait()
            GLib.idle_add(self.finished, rc, "".join(lines))

        def finished(self, rc, out):
            self.proc = None
            self.run_btn.set_sensitive(True)
            self.stop_btn.set_sensitive(False)
            m = re.search(r"Record: (.+record\.json)", out)
            self.last_record = m.group(1).strip() if m else None
            self.rec_btn.set_sensitive(bool(self.last_record))
            nonempty = [l for l in out.splitlines() if l.strip()]
            last = nonempty[-1] if nonempty else ""
            if last.startswith("COPY VERIFIED — runtime"):
                last = nonempty[-2] if len(nonempty) > 1 else last
            style, text = classify(last)
            self.set_result(style, f"{text}   (exit {rc})")
            self.update_hint()
            return False

        def on_stop(self, *_):
            if not self.proc:
                return
            r = self.message(Gtk.MessageType.WARNING, "Stop safely?",
                             "The tool stops rsync and keeps the partial copy exactly as it is. "
                             "Nothing is deleted. You can continue later with “Resume an interrupted copy”.",
                             Gtk.ButtonsType.OK_CANCEL)
            if r == Gtk.ResponseType.OK and self.proc:
                self.proc.send_signal(signal.SIGINT)
                self.stop_btn.set_sensitive(False)
                self.set_result("warn", "Stopping safely…")

        def open_record(self, *_):
            if self.last_record:
                subprocess.Popen(["xdg-open", str(Path(self.last_record).parent)],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        def on_close(self, *_):
            if self.proc:
                r = self.message(Gtk.MessageType.WARNING, "A run is still in progress",
                                 "Close anyway? The tool will be stopped safely first (partial copy kept, "
                                 "nothing deleted).", Gtk.ButtonsType.OK_CANCEL)
                if r != Gtk.ResponseType.OK:
                    return True
                self.proc.send_signal(signal.SIGINT)
                try:
                    self.proc.wait(timeout=60)
                except subprocess.TimeoutExpired:
                    pass
            save_config(self.cfg)
            return False

    class App(Gtk.Application):
        def __init__(self):
            super().__init__(application_id="org.cyclops.SafeCopier")

        def do_activate(self):
            win = self.props.active_window or Win(self)
            win.show_all()
            win.present()

    return App().run([sys.argv[0]])


# --------------------------------------------------------------------------- #
# Terminal fallback
# --------------------------------------------------------------------------- #
def ask(prompt: str) -> str:
    v = input(prompt).strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":   # dragged-in paths arrive quoted
        v = v[1:-1]
    return os.path.expanduser(v)


def run_text() -> int:
    print("\n════ Cyclops Safe Copier ════")
    tag = acceptance_tag()
    print(f"Accepted on this machine: {tag}" if tag else
          "NOT yet accepted on this machine — disposable test folders only.\n"
          f"Acceptance: {ACCEPTANCE_CMD}")
    print("(For the window version: sudo apt install python3-gi gir1.2-gtk-3.0)\n")
    try:
        src = ask("Source folder (drag it here, then Enter): ")
        dst = ask("Copy to (new or empty folder): ")
        print("\nAction:")
        for i, (_, title, hint) in enumerate(MODES, 1):
            print(f"  {i}. {title} — {hint}")
        choice = input("Choose 1-4 [1]: ").strip() or "1"
        mode = MODES[int(choice) - 1][0] if choice in "1234" and choice else "dry-run"
        cmd = build_command(src, dst, mode)
        print("\n$ " + shlex.join(["cyclops-safe-copy", *cmd[2:]]))
        if mode in ("copy", "resume") and input("Start? [y/N] ").strip().lower() != "y":
            return 1
        rc = subprocess.call(cmd)
    except (KeyboardInterrupt, EOFError):
        rc = 130
    input("\nPress Enter to close…")
    return rc


def relaunch_in_terminal() -> bool:
    me = [sys.executable, str(Path(__file__).resolve()), "--text"]
    for term, args in (("x-terminal-emulator", ["-e"]), ("gnome-terminal", ["--"]), ("konsole", ["-e"]),
                       ("xfce4-terminal", ["-x"]), ("tilix", ["-e"]), ("kitty", []), ("alacritty", ["-e"]),
                       ("xterm", ["-e"])):
        if shutil.which(term):
            subprocess.Popen([term, *args, *me])
            return True
    return False


def main() -> int:
    if "--text" in sys.argv:
        return run_text()
    try:
        return run_gtk()
    except (ImportError, ValueError) as e:
        if sys.stdin and sys.stdin.isatty():
            print(f"(GTK window unavailable: {e})")
            return run_text()
        return 0 if relaunch_in_terminal() else 1


if __name__ == "__main__":
    sys.exit(main())
