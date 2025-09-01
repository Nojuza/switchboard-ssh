#!/usr/bin/env python3
# sshpad.py — Terminal UI SSH profile manager that launches the native `ssh`.
# Noah-friendly: minimal deps (prompt_toolkit), JSON config, crisp keybindings.

import argparse
import os
import shlex
import subprocess
import sys
import base64
import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Optional
from hashlib import sha256
from cryptography.fernet import Fernet
try:
    import pexpect  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    pexpect = None

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
class CredentialProfile:
    name: str
    user: str = ""
    password: str = ""
    identity_file: str = ""

@dataclass
class DeviceProfile:
    name: str
    alias: str = ""
    host: str = ""
    port: Optional[int] = None
    proxyjump: str = ""
    extra_args: str = ""
    credential: str = ""

    def validate(self) -> None:
        if not self.alias.strip() and not self.host.strip():
            raise ValueError(f"Profile '{self.name}' must define either an alias or a host.")

    def build_ssh_cmd(self, cred: CredentialProfile) -> List[str]:
        self.validate()
        cmd = ["ssh"]
        if cred.identity_file.strip():
            id_path = os.path.expanduser(cred.identity_file.strip())
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
            target = (f"{cred.user.strip()}@" if cred.user.strip() else "") + self.host.strip()
            cmd += [target]
        return cmd

    def display_target(self, cred: Optional[CredentialProfile] = None) -> str:
        if self.alias.strip():
            return f"{self.alias.strip()} (alias)"
        h = self.host.strip()
        u = cred.user.strip() if cred else ""
        p = f":{self.port}" if self.port else ""
        core = (f"{u}@{h}{p}" if u else f"{h}{p}") if h else "(incomplete)"
        if self.proxyjump.strip():
            core += f"  ⤴ via {self.proxyjump.strip()}"
        return core

def load_devices(path: Path) -> List[DeviceProfile]:
    if not path.exists():
        seed = [
            asdict(DeviceProfile(name="Example alias", alias="myhost")),
            asdict(DeviceProfile(name="Example full", host="server.example.com", port=22,
                                proxyjump="", extra_args="-o ServerAliveInterval=30", credential="")),
        ]
        path.write_text(json.dumps(seed, indent=2))
        return [DeviceProfile(**p) for p in seed]
    data = json.loads(path.read_text() or "[]")
    return [DeviceProfile(**item) for item in data]

def save_devices(path: Path, devices: List[DeviceProfile]) -> None:
    path.write_text(json.dumps([asdict(d) for d in devices], indent=2))

def default_credentials_path() -> Path:
    xdg = os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))
    cfg_dir = Path(xdg) / APP_NAME
    cfg_dir.mkdir(parents=True, exist_ok=True)
    return cfg_dir / "credentials.enc"

def _derive_key(password: str) -> bytes:
    return base64.urlsafe_b64encode(sha256(password.encode()).digest())

def load_credentials(path: Path, password: str) -> List[CredentialProfile]:
    if not path.exists():
        return []
    raw = path.read_text() or ""
    if not raw:
        return []
    f = Fernet(_derive_key(password))
    data = json.loads(f.decrypt(raw.encode()).decode())
    return [CredentialProfile(**c) for c in data]

def save_credentials(path: Path, creds: List[CredentialProfile], password: str) -> None:
    f = Fernet(_derive_key(password))
    enc = f.encrypt(json.dumps([asdict(c) for c in creds]).encode())
    path.write_text(enc.decode())

class SshPadApp:
    def __init__(self, config_path: Path):
        self.config_path = config_path
        self.cred_path = default_credentials_path()

        self.devices = load_devices(self.config_path)
        self.device_filtered = list(range(len(self.devices)))
        self.device_cursor = 0
        self.device_search = ""

        self.credentials: List[CredentialProfile] = []
        self.credentials_unlocked = False
        self.cred_password: Optional[str] = None
        self.cred_cursor = 0

        self.active_pane = "devices"

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
            full_screen=True,
        )

    # ---------- UI ----------
    def _build_ui(self):
        self.title = Window(FormattedTextControl(self._render_title), height=1)
        self.header = Window(FormattedTextControl(lambda: [
            ("class:header", "  h/l Switch Pane  k/j Up/Down  Enter Select  a Add  e Edit  d Delete  r Reload  s Save  q Quit")
        ]), height=1)

        self.device_ctrl = FormattedTextControl(self._render_device_list)
        self.cred_ctrl = FormattedTextControl(self._render_cred_list)
        self.device_win = Window(self.device_ctrl, wrap_lines=False, always_hide_cursor=True)
        self.cred_win = Window(self.cred_ctrl, wrap_lines=False, always_hide_cursor=True)

        panes = VSplit([
            Frame(self.device_win, title="Devices"),
            Frame(self.cred_win, title="Credentials"),
        ])

        self.status = Window(FormattedTextControl(self._render_status), height=1)

        root = HSplit([
            Box(self.title, padding=0),
            self.header,
            panes,
            self.status,
        ])

        self.layout = Layout(root)
        self.layout.focus(self.device_win)

    def _render_title(self):
        pane = "Devices" if self.active_pane == "devices" else "Credentials"
        return [("class:title", f" {APP_NAME} — {pane} ")]

    def _render_device_list(self):
        lines = []
        if not self.device_filtered:
            lines.append(("class:dim", "  (no devices)"))
            return lines
        for row, idx in enumerate(self.device_filtered):
            d = self.devices[idx]
            cred = self._get_credential_by_name(d.credential)
            prefix = "➤ " if row == self.device_cursor else "  "
            style = "class:selected" if row == self.device_cursor and self.active_pane == "devices" else "class:item"
            lines.append((style, f"{prefix}{d.name}\n"))
            lines.append(("class:dim" if row != self.device_cursor or self.active_pane != "devices" else style,
                          f"     {d.display_target(cred)}\n"))
        return lines

    def _render_cred_list(self):
        lines = []
        if not self.credentials_unlocked:
            msg = "No credential store. Press Enter to create." if not self.cred_path.exists() else "Credentials locked. Press Enter to unlock."
            lines.append(("class:dim", f"  {msg}"))
            return lines
        if not self.credentials:
            lines.append(("class:dim", "  (no credentials)"))
            return lines
        for row, c in enumerate(self.credentials):
            prefix = "➤ " if row == self.cred_cursor else "  "
            style = "class:selected" if row == self.cred_cursor and self.active_pane == "credentials" else "class:item"
            lines.append((style, f"{prefix}{c.name}\n"))
            lines.append(("class:dim" if row != self.cred_cursor or self.active_pane != "credentials" else style,
                          f"     user: {c.user}\n"))
        return lines

    def _render_status(self):
        total = len(self.devices)
        filt = len(self.device_filtered)
        q = self.device_search or "(none)"
        return [("class:help", f"  Devices: {filt}/{total}   Filter: {q}   File: {self.config_path}  ")]

    # ---------- Helpers ----------
    def _refresh_device_filter(self):
        q = (self.device_search or "").lower().strip()
        self.device_filtered = []
        for i, d in enumerate(self.devices):
            haystack = " ".join([d.name, d.alias, d.host, d.extra_args]).lower()
            if q in haystack:
                self.device_filtered.append(i)
        if not self.device_filtered:
            self.device_cursor = 0
        else:
            self.device_cursor = max(0, min(self.device_cursor, len(self.device_filtered) - 1))

    def _get_selected_device(self) -> Optional[DeviceProfile]:
        if not self.device_filtered:
            return None
        return self.devices[self.device_filtered[self.device_cursor]]

    def _get_selected_credential(self) -> Optional[CredentialProfile]:
        if not self.credentials_unlocked or not self.credentials:
            return None
        return self.credentials[self.cred_cursor]

    def _get_credential_by_name(self, name: str) -> Optional[CredentialProfile]:
        for c in self.credentials:
            if c.name == name:
                return c
        return None

    def _select_default_credential(self, device: DeviceProfile):
        if not self.credentials_unlocked or not self.credentials:
            self.cred_cursor = 0
            return
        for i, c in enumerate(self.credentials):
            if c.name == device.credential:
                self.cred_cursor = i
                return
        self.cred_cursor = 0

    def _clear_key_buffer(self) -> None:
        self.app.key_processor.reset()
        self.app.renderer.clear()
        self.app.invalidate()

    # ---------- Actions ----------
    async def action_unlock_credentials(self):
        if self.cred_path.exists():
            pw = await input_dialog(title="Unlock", text="Password:").run_async()
            if not pw:
                self._clear_key_buffer()
                return
            try:
                self.credentials = load_credentials(self.cred_path, pw)
            except Exception:
                await message_dialog(title="Error", text="Incorrect password or corrupt store.").run_async()
                self._clear_key_buffer()
                return
            self.credentials_unlocked = True
            self.cred_password = pw
        else:
            pw = await input_dialog(title="Create store", text="New password:").run_async()
            if not pw:
                self._clear_key_buffer()
                return
            save_credentials(self.cred_path, [], pw)
            self.credentials_unlocked = True
            self.credentials = []
            self.cred_password = pw
        self._clear_key_buffer()

    async def action_connect(self):
        device = self._get_selected_device()
        cred = self._get_selected_credential()
        if not device or not cred:
            await message_dialog(title="No selection", text="Select a device and credential.").run_async()
            self._clear_key_buffer()
            return
        try:
            cmd = device.build_ssh_cmd(cred)
        except Exception as e:
            await message_dialog(title="Invalid", text=str(e)).run_async()
            self._clear_key_buffer()
            return

        pw = cred.password.strip()
        ssh_cmd = list(cmd)  # Preserve for display

        def runner():
            print(f"\nLaunching: {' '.join(shlex.quote(c) for c in ssh_cmd)}\n", flush=True)
            if pw:
                if pexpect is None:
                    print("Error: Python package `pexpect` is required for password-based credentials.", file=sys.stderr)
                else:
                    try:
                        child = pexpect.spawn(ssh_cmd[0], ssh_cmd[1:], env=os.environ)
                        child.expect("(?i)password:")
                        child.sendline(pw)
                        child.interact()
                        child.close()
                    except pexpect.exceptions.ExceptionPexpect as e:
                        if "not found" in str(e):
                            print("Error: `ssh` not found in PATH.", file=sys.stderr)
                        else:
                            print(f"SSH failed: {e}", file=sys.stderr)
            else:
                try:
                    subprocess.call(ssh_cmd)
                except FileNotFoundError:
                    print("Error: `ssh` not found in PATH.", file=sys.stderr)
            input("\nPress Enter to return to the manager…")

        run_in_terminal(runner)
        self._clear_key_buffer()

    async def action_add(self):
        if self.active_pane == "devices":
            name = await input_dialog(title="New device", text="Name:").run_async()
            if not name:
                self._clear_key_buffer()
                return
            alias = await input_dialog(title="New device", text="OpenSSH alias (optional):").run_async() or ""
            host = await input_dialog(title="New device", text="Host (leave blank if alias):").run_async() or ""
            port_s = await input_dialog(title="New device", text="Port (optional):").run_async() or ""
            proxyjump = await input_dialog(title="New device", text="ProxyJump -J (optional):").run_async() or ""
            extra = await input_dialog(title="New device", text="Extra args:").run_async() or ""
            cred = await input_dialog(title="New device", text="Default credential name:").run_async() or ""
            port = None
            if port_s.strip():
                try:
                    port = int(port_s.strip())
                except ValueError:
                    await message_dialog(title="Invalid", text="Port must be int").run_async()
                    self._clear_key_buffer()
                    return
            d = DeviceProfile(name=name.strip(), alias=alias.strip(), host=host.strip(), port=port,
                              proxyjump=proxyjump.strip(), extra_args=extra.strip(), credential=cred.strip())
            try:
                d.validate()
            except ValueError as e:
                await message_dialog(title="Invalid", text=str(e)).run_async()
                self._clear_key_buffer()
                return
            self.devices.append(d)
            self._refresh_device_filter()
        else:
            if not self.credentials_unlocked:
                await message_dialog(title="Locked", text="Unlock credentials first.").run_async()
                self._clear_key_buffer()
                return
            name = await input_dialog(title="New credential", text="Name:").run_async()
            if not name:
                self._clear_key_buffer()
                return
            user = await input_dialog(title="New credential", text="User:").run_async() or ""
            password = await input_dialog(title="New credential", text="Password (optional):").run_async() or ""
            identity = await input_dialog(title="New credential", text="Identity file path:").run_async() or ""
            c = CredentialProfile(name=name.strip(), user=user.strip(), password=password.strip(), identity_file=identity.strip())
            self.credentials.append(c)
        self._clear_key_buffer()

    async def action_edit(self):
        if self.active_pane == "devices":
            device = self._get_selected_device()
            if not device:
                return
            original = DeviceProfile(**asdict(device))
            async def ask(title, current):
                return await input_dialog(title=title, text=f"(current: {current})\nNew value (blank keeps)").run_async()
            name = await ask("Edit device name", device.name)
            alias = await ask("Edit alias", device.alias)
            host = await ask("Edit host", device.host)
            port_s = await ask("Edit port", device.port if device.port else "")
            proxyjump = await ask("Edit proxyjump", device.proxyjump)
            extra = await ask("Edit extra args", device.extra_args)
            cred = await ask("Edit default credential", device.credential)
            if name: device.name = name.strip()
            if alias is not None and alias != "": device.alias = alias.strip()
            if host is not None and host != "": device.host = host.strip()
            if port_s is not None and port_s.strip():
                try:
                    device.port = int(port_s.strip())
                except ValueError:
                    await message_dialog(title="Invalid", text="Port must be int").run_async()
                    device.port = original.port
            if proxyjump is not None and proxyjump != "": device.proxyjump = proxyjump.strip()
            if extra is not None and extra != "": device.extra_args = extra.strip()
            if cred is not None and cred != "": device.credential = cred.strip()
            try:
                device.validate()
            except ValueError as e:
                self.devices[self.device_filtered[self.device_cursor]] = original
                await message_dialog(title="Invalid", text=str(e)).run_async()
        else:
            if not self.credentials_unlocked or not self.credentials:
                return
            cred = self.credentials[self.cred_cursor]
            name = await input_dialog(title="Edit credential", text=f"Name ({cred.name}):").run_async()
            user = await input_dialog(title="Edit credential", text=f"User ({cred.user}):").run_async()
            password = await input_dialog(title="Edit credential", text="Password (leave blank keep):").run_async()
            identity = await input_dialog(title="Edit credential", text=f"Identity ({cred.identity_file}):").run_async()
            if name: cred.name = name.strip()
            if user: cred.user = user.strip()
            if password: cred.password = password.strip()
            if identity: cred.identity_file = identity.strip()
        self._clear_key_buffer()

    async def action_delete(self):
        if self.active_pane == "devices":
            device = self._get_selected_device()
            if device and await yes_no_dialog(title="Delete device", text=f"Delete '{device.name}'?").run_async():
                del self.devices[self.device_filtered[self.device_cursor]]
                self._refresh_device_filter()
        else:
            if not self.credentials_unlocked or not self.credentials:
                return
            cred = self.credentials[self.cred_cursor]
            if await yes_no_dialog(title="Delete credential", text=f"Delete '{cred.name}'?").run_async():
                del self.credentials[self.cred_cursor]
                self.cred_cursor = max(0, self.cred_cursor - 1)
        self._clear_key_buffer()

    async def action_search(self):
        q = await input_dialog(title="Search devices", text="Filter (blank clears)").run_async()
        self.device_search = (q or "").strip()
        self._refresh_device_filter()
        self._clear_key_buffer()

    def action_reload(self):
        self.devices = load_devices(self.config_path)
        self._refresh_device_filter()
        if self.credentials_unlocked and self.cred_password:
            self.credentials = load_credentials(self.cred_path, self.cred_password)

    async def action_save(self):
        save_devices(self.config_path, self.devices)
        if self.credentials_unlocked and self.cred_password:
            save_credentials(self.cred_path, self.credentials, self.cred_password)
        await message_dialog(title="Saved", text="Profiles saved.").run_async()
        self._clear_key_buffer()

    async def action_help(self):
        await message_dialog(title="Help", text=(
            "h/l or ←/→ switch panes\n"
            "k/j or ↑/↓ move\n"
            "Enter in device pane → choose credential\n"
            "Enter in credential pane → connect\n"
            "a/e/d add/edit/delete based on pane\n"
            "r reload  s save  q quit"
        )).run_async()
        self._clear_key_buffer()

    # ---------- Keybindings ----------
    def _bind_keys(self):
        kb = self.kb

        @kb.add("q")
        def _(event):
            event.app.exit()

        @kb.add("left")
        @kb.add("h")
        def _(event):
            self.active_pane = "devices"
            self.layout.focus(self.device_win)

        @kb.add("right")
        @kb.add("l")
        def _(event):
            self.active_pane = "credentials"
            self.layout.focus(self.cred_win)

        @kb.add("up")
        @kb.add("k")
        def _(event):
            if self.active_pane == "devices" and self.device_filtered:
                self.device_cursor = max(0, self.device_cursor - 1)
            elif self.active_pane == "credentials" and self.credentials_unlocked and self.credentials:
                self.cred_cursor = max(0, self.cred_cursor - 1)

        @kb.add("down")
        @kb.add("j")
        def _(event):
            if self.active_pane == "devices" and self.device_filtered:
                self.device_cursor = min(len(self.device_filtered) - 1, self.device_cursor + 1)
            elif self.active_pane == "credentials" and self.credentials_unlocked and self.credentials:
                self.cred_cursor = min(len(self.credentials) - 1, self.cred_cursor + 1)

        @kb.add("enter")
        def _(event):
            if self.active_pane == "devices":
                device = self._get_selected_device()
                if device:
                    if not self.credentials_unlocked:
                        event.app.create_background_task(self.action_unlock_credentials())
                    self.active_pane = "credentials"
                    self._select_default_credential(device)
                    self.layout.focus(self.cred_win)
            else:
                if not self.credentials_unlocked:
                    event.app.create_background_task(self.action_unlock_credentials())
                else:
                    event.app.create_background_task(self.action_connect())

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
        self._refresh_device_filter()
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
