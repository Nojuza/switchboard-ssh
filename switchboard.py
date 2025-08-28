#!/usr/bin/env python3
# sshpad.py — Terminal UI SSH profile manager that launches the native `ssh`.
# Noah-friendly: minimal deps (prompt_toolkit), JSON config, crisp keybindings.

import argparse
import json
import os
import shlex
import subprocess
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Optional

from prompt_toolkit.application import Application, run_in_terminal
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import Layout, HSplit, VSplit, Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.widgets import Box, Frame
from prompt_toolkit.styles import Style
from prompt_toolkit.shortcuts.dialogs import input_dialog, message_dialog, yes_no_dialog


APP_NAME = "sshpad"

def default_config_path() -> Path:
    xdg = os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))
    cfg_dir = Path(xdg) / APP_NAME
    cfg_dir.mkdir(parents=True, exist_ok=True)
    return cfg_dir / "connections.json"

@dataclass
class Profile:
    name: str
    # If alias is set, we will pass alias directly to ssh (ignores host/user unless you also want them).
    alias: str = ""
    host: str = ""
    user: str = ""
    port: Optional[int] = None
    identity_file: str = ""   # -i
    proxyjump: str = ""       # -J
    extra_args: str = ""      # freeform, space-separated (parsed with shlex)

    def build_ssh_cmd(self) -> List[str]:
        cmd = ["ssh"]
        if self.identity_file.strip():
            id_path = os.path.expanduser(self.identity_file.strip())
            cmd += ["-i", id_path]
        if self.proxyjump.strip():
            cmd += ["-J", self.proxyjump.strip()]
        if self.port:
            cmd += ["-p", str(self.port)]
        if self.extra_args.strip():
            cmd += shlex.split(self.extra_args.strip())

        if self.alias.strip():
            cmd += [self.alias.strip()]
        else:
            if not (self.host.strip() or self.user.strip()):
                raise ValueError("Profile has neither alias nor host/user.")
            target = (f"{self.user.strip()}@" if self.user.strip() else "") + self.host.strip()
            cmd += [target]
        return cmd

    def display_target(self) -> str:
        if self.alias.strip():
            return f"{self.alias.strip()} (alias)"
        parts = []
        u = self.user.strip()
        h = self.host.strip()
        p = f":{self.port}" if self.port else ""
        core = (f"{u}@{h}{p}" if u else f"{h}{p}") if h else "(incomplete)"
        if self.proxyjump.strip():
            core += f"  ⤴ via {self.proxyjump.strip()}"
        return core

def load_profiles(path: Path) -> List[Profile]:
    if not path.exists():
        # Seed example file
        seed = [
            asdict(Profile(name="Example alias (uses ~/.ssh/config)", alias="myhost")),
            asdict(Profile(name="Example full", host="server.example.com", user="noah", port=22,
                           identity_file="~/.ssh/id_ed25519", proxyjump="", extra_args="-o ServerAliveInterval=30")),
        ]
        path.write_text(json.dumps(seed, indent=2))
        return [Profile(**p) for p in seed]
    data = json.loads(path.read_text() or "[]")
    profiles: List[Profile] = []
    for item in data:
        # Backward/forward compatible field loading
        profiles.append(Profile(
            name=item.get("name",""),
            alias=item.get("alias",""),
            host=item.get("host",""),
            user=item.get("user",""),
            port=item.get("port",None),
            identity_file=item.get("identity_file",""),
            proxyjump=item.get("proxyjump",""),
            extra_args=item.get("extra_args",""),
        ))
    return profiles

def save_profiles(path: Path, profiles: List[Profile]) -> None:
    data = [asdict(p) for p in profiles]
    path.write_text(json.dumps(data, indent=2))

class SshPadApp:
    def __init__(self, config_path: Path):
        self.config_path = config_path
        self.profiles: List[Profile] = load_profiles(self.config_path)
        self.filtered_indices: List[int] = list(range(len(self.profiles)))
        self.cursor = 0
        self.search_query = ""

        self.kb = KeyBindings()
        self.style = Style.from_dict({
            "title": "bold",
            "header": "reverse",
            "item": "",
            "selected": "reverse",
            "dim": "ansiwhite",
            "help": "ansibrightblack",
            "error": "ansired bold",
        })

        self._build_ui()
        self._bind_keys()

        self.app = Application(
            layout=self.layout,
            key_bindings=self.kb,
            style=self.style,
            mouse_support=False,
            full_screen=True
        )

    # ---------- UI ----------
    def _build_ui(self):
        self.title = Window(FormattedTextControl(lambda: [("class:title", f" {APP_NAME} — SSH Profiles ")]), height=1)
        self.header = Window(FormattedTextControl(lambda: [
            ("class:header", "  ↑/↓ Move  Enter Connect   / Search   a Add   e Edit   d Delete   r Reload   s Save   ? Help   q Quit")
        ]), height=1)

        self.list_ctrl = FormattedTextControl(self._render_list)
        self.list_win = Window(self.list_ctrl, wrap_lines=False, always_hide_cursor=True)

        self.status = Window(FormattedTextControl(self._render_status), height=1)

        root = HSplit([
            Box(self.title, padding=0),
            self.header,
            Frame(self.list_win, title="Profiles"),
            self.status,
        ])

        self.layout = Layout(root)

    def _render_list(self):
        lines = []
        if not self.filtered_indices:
            lines.append(("class:dim", "  (no profiles match your filter)"))
            return lines

        for row, idx in enumerate(self.filtered_indices):
            p = self.profiles[idx]
            prefix = "➤ " if row == self.cursor else "  "
            style = "class:selected" if row == self.cursor else "class:item"
            lines.append((style, f"{prefix}{p.name}\n"))
            lines.append(("class:dim" if row != self.cursor else style, f"     {p.display_target()}\n"))
        return lines

    def _render_status(self):
        total = len(self.profiles)
        filt = len(self.filtered_indices)
        q = self.search_query or "(none)"
        return [
            ("class:help", f"  Profiles: {filt}/{total}   Filter: {q}   File: {self.config_path}  ")
        ]

    # ---------- Helpers ----------
    def _refresh_filter(self):
        q = (self.search_query or "").lower().strip()
        self.filtered_indices = []
        for i, p in enumerate(self.profiles):
            haystack = " ".join([
                p.name, p.alias, p.host, p.user,
                str(p.port) if p.port else "",
                p.identity_file, p.proxyjump, p.extra_args
            ]).lower()
            if q in haystack:
                self.filtered_indices.append(i)
        if not self.filtered_indices:
            self.cursor = 0
        else:
            self.cursor = max(0, min(self.cursor, len(self.filtered_indices) - 1))

    def _get_selected_profile(self) -> Optional[Profile]:
        if not self.filtered_indices:
            return None
        idx = self.filtered_indices[self.cursor]
        return self.profiles[idx]

    def _get_selected_index(self) -> Optional[int]:
        if not self.filtered_indices:
            return None
        return self.filtered_indices[self.cursor]

    # ---------- Actions ----------
    async def action_connect_selected(self):
        p = self._get_selected_profile()
        if not p:
            await message_dialog(title="No selection", text="No profile selected.").run_async()
            return
        try:
            cmd = p.build_ssh_cmd()
        except Exception as e:
            await message_dialog(title="Invalid profile", text=str(e)).run_async()
            return

        def runner():
            print(f"\nLaunching: {' '.join(shlex.quote(c) for c in cmd)}\n", flush=True)
            try:
                subprocess.call(cmd)
            except FileNotFoundError:
                print("Error: `ssh` not found in PATH.", file=sys.stderr)
            input("\nPress Enter to return to the manager…")

        # Safe to call inside the PTK app:
        run_in_terminal(runner)

    async def action_add(self):
        name = await input_dialog(title="New profile", text="Name (display):").run_async()
        if not name:
            return
        alias = await input_dialog(title="New profile", text="OpenSSH alias (optional):").run_async() or ""
        host = await input_dialog(title="New profile", text="Host (leave empty if using alias):").run_async() or ""
        user = await input_dialog(title="New profile", text="User (optional):").run_async() or ""
        port_s = await input_dialog(title="New profile", text="Port (optional, integer):").run_async() or ""
        identity = await input_dialog(title="New profile", text="Identity file -i (optional):").run_async() or ""
        proxyjump = await input_dialog(title="New profile", text="ProxyJump -J (optional):").run_async() or ""
        extra = await input_dialog(title="New profile", text="Extra args (optional, space-separated):").run_async() or ""

        port = None
        if port_s.strip():
            try:
                port = int(port_s.strip())
            except ValueError:
                await message_dialog(title="Invalid port", text="Port must be an integer.").run_async()
                return

        self.profiles.append(Profile(
            name=name.strip(), alias=alias.strip(), host=host.strip(), user=user.strip(),
            port=port, identity_file=identity.strip(), proxyjump=proxyjump.strip(), extra_args=extra.strip()
        ))
        self._refresh_filter()

    async def action_edit(self):
        idx = self._get_selected_index()
        if idx is None:
            return
        p = self.profiles[idx]

        async def ask(title, current):
            return await input_dialog(title=title, text=f"(current: {current})\nNew value (blank = keep):").run_async()

        name = await ask("Edit: Name", p.name)
        alias = await ask("Edit: OpenSSH alias", p.alias)
        host = await ask("Edit: Host", p.host)
        user = await ask("Edit: User", p.user)
        port_s = await ask("Edit: Port", p.port if p.port else "")
        identity = await ask("Edit: Identity file -i", p.identity_file)
        proxyjump = await ask("Edit: ProxyJump -J", p.proxyjump)
        extra = await ask("Edit: Extra args", p.extra_args)

        if name: p.name = name.strip()
        if alias is not None and alias != "": p.alias = alias.strip()
        if host is not None and host != "": p.host = host.strip()
        if user is not None and user != "": p.user = user.strip()
        if port_s is not None and port_s.strip() != "":
            try:
                p.port = int(port_s.strip())
            except ValueError:
                await message_dialog(title="Invalid port", text="Port must be an integer.").run_async()
        if identity is not None and identity != "": p.identity_file = identity.strip()
        if proxyjump is not None and proxyjump != "": p.proxyjump = proxyjump.strip()
        if extra is not None and extra != "": p.extra_args = extra.strip()

        self._refresh_filter()

    async def action_delete(self):
        idx = self._get_selected_index()
        if idx is None:
            return
        p = self.profiles[idx]
        if await yes_no_dialog(title="Delete profile?", text=f"Delete '{p.name}'?").run_async():
            del self.profiles[idx]
            self._refresh_filter()

    async def action_search(self):
        q = await input_dialog(title="Search/filter", text="Type to filter (blank clears):").run_async()
        self.search_query = (q or "").strip()
        self._refresh_filter()

    def action_reload(self):
        self.profiles = load_profiles(self.config_path)
        self._refresh_filter()

    async def action_save(self):
        save_profiles(self.config_path, self.profiles)
        await message_dialog(title="Saved", text=f"Saved {len(self.profiles)} profiles to:\n{self.config_path}").run_async()

    async def action_help(self):
        await message_dialog(
            title="Help",
            text=(
                "Keys:\n"
                "  ↑/↓, PgUp/PgDn  Move selection\n"
                "  Enter           Connect (launches native ssh)\n"
                "  /               Search/filter\n"
                "  a               Add profile\n"
                "  e               Edit selected\n"
                "  d               Delete selected\n"
                "  r               Reload from disk\n"
                "  s               Save to disk\n"
                "  q               Quit\n\n"
                "Tips:\n"
                "• Put OpenSSH alias from ~/.ssh/config in 'alias' and leave host/user blank.\n"
                "• 'Extra args' accepts ssh flags, e.g. '-o ServerAliveInterval=30 -A'.\n"
                "• Profiles live at the path in the status bar."
            ),
        ).run_async()
    # ---------- Keybindings ----------
    def _bind_keys(self):
        kb = self.kb

        @kb.add("q")
        def _(event): event.app.exit()

        @kb.add("up")
        def _(event):
            if self.filtered_indices:
                self.cursor = max(0, self.cursor - 1)

        @kb.add("down")
        def _(event):
            if self.filtered_indices:
                self.cursor = min(len(self.filtered_indices) - 1, self.cursor + 1)

        @kb.add("pageup")
        def _(event):
            if self.filtered_indices:
                self.cursor = max(0, self.cursor - 10)

        @kb.add("pagedown")
        def _(event):
            if self.filtered_indices:
                self.cursor = min(len(self.filtered_indices) - 1, self.cursor + 10)

        @kb.add("enter")
        def _(event):
            event.app.create_background_task(self.action_connect_selected())

        @kb.add("/")
        def _(event):
            event.app.create_background_task(self.action_search())

        @kb.add("a")
        def _(event):
            event.app.create_background_task(self.action_add())

        @kb.add("e")
        def _(event):
            event.app.create_background_task(self.action_edit())

        @kb.add("d")
        def _(event):
            event.app.create_background_task(self.action_delete())

        @kb.add("r")
        def _(event):
            self.action_reload()

        @kb.add("s")
        def _(event):
            event.app.create_background_task(self.action_save())

        @kb.add("?")
        def _(event):
            event.app.create_background_task(self.action_help())
    # ---------- Run ----------
    def run(self):
        self._refresh_filter()
        self.app.run()

def main():
    parser = argparse.ArgumentParser(description="Terminal UI SSH profile manager that launches native `ssh`.")
    parser.add_argument("--config", type=str, default=None, help="Path to connections.json (default: ~/.config/sshpad/connections.json)")
    args = parser.parse_args()

    cfg = Path(args.config) if args.config else default_config_path()
    app = SshPadApp(cfg)
    app.run()

if __name__ == "__main__":
    main()

