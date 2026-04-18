from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import time
import webbrowser
from pathlib import Path
from typing import Any

import psutil


STATE_FILENAME = ".archivebox_tray_state.json"


def _default_command_prefix() -> list[str]:
    custom_cmd = os.environ.get("ARCHIVEBOX_TRAY_COMMAND", "").strip()
    if custom_cmd:
        return shlex.split(custom_cmd)
    return [sys.executable, "-m", "archivebox"]


def _creation_flags() -> int:
    if sys.platform.startswith("win"):
        return getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(subprocess, "DETACHED_PROCESS", 0)
    return 0


class TrayProcessController:
    """Small cross-platform process manager for ArchiveBox tray actions."""

    def __init__(
        self,
        *,
        data_dir: Path,
        host: str,
        port: int,
        command_prefix: list[str] | None = None,
        server_command: list[str] | None = None,
        runner_command: list[str] | None = None,
    ) -> None:
        self.data_dir = data_dir.expanduser().resolve()
        self.host = host.strip() or "127.0.0.1"
        self.port = int(port)
        self.command_prefix = command_prefix or _default_command_prefix()
        self.server_command = server_command
        self.runner_command = runner_command
        self.logs_dir = self.data_dir / "logs"
        self.state_file = self.data_dir / STATE_FILENAME

    # ------------------------------------------------------------------
    # State
    # ------------------------------------------------------------------
    def _ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.logs_dir.mkdir(parents=True, exist_ok=True)

    def _load_state(self) -> dict[str, dict[str, Any]]:
        if not self.state_file.exists():
            return {}
        try:
            raw = json.loads(self.state_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}
        if not isinstance(raw, dict):
            return {}
        state: dict[str, dict[str, Any]] = {}
        for key in ("server", "runner"):
            row = raw.get(key)
            if isinstance(row, dict):
                state[key] = row
        return state

    def _save_state(self, state: dict[str, dict[str, Any]]) -> None:
        self._ensure_dirs()
        self.state_file.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")

    def _clear_state_key(self, key: str) -> None:
        state = self._load_state()
        if key in state:
            del state[key]
            self._save_state(state)

    # ------------------------------------------------------------------
    # Process helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _is_process_alive(pid: int, started_at: float | None = None) -> bool:
        if pid <= 0:
            return False
        try:
            proc = psutil.Process(pid)
            if not proc.is_running() or proc.status() == psutil.STATUS_ZOMBIE:
                return False
            if started_at:
                # Guard against PID reuse.
                return abs(proc.create_time() - float(started_at)) < 2.0
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return False

    def _archivebox_cmd(self, *args: str) -> list[str]:
        return [*self.command_prefix, *args]

    def _spawn(self, key: str, command: list[str], log_name: str) -> dict[str, Any]:
        self._ensure_dirs()
        log_file = self.logs_dir / log_name
        env = os.environ.copy()
        env.setdefault("DATA_DIR", str(self.data_dir))
        env.setdefault("PYTHONUNBUFFERED", "1")

        with log_file.open("ab") as out_stream:
            proc = subprocess.Popen(
                command,
                cwd=str(self.data_dir),
                stdout=out_stream,
                stderr=out_stream,
                stdin=subprocess.DEVNULL,
                env=env,
                start_new_session=not sys.platform.startswith("win"),
                creationflags=_creation_flags(),
            )

        process_state = {"pid": int(proc.pid), "started_at": float(time.time()), "command": command}
        state = self._load_state()
        state[key] = process_state
        self._save_state(state)
        return process_state

    @staticmethod
    def _terminate_pid(pid: int) -> None:
        try:
            proc = psutil.Process(pid)
        except psutil.NoSuchProcess:
            return

        children = proc.children(recursive=True)
        for child in children:
            try:
                child.terminate()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        try:
            proc.terminate()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        gone, alive = psutil.wait_procs([*children, proc], timeout=8)
        if alive:
            for stubborn in alive:
                try:
                    stubborn.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

    def _ensure_initialized(self) -> None:
        db_file = self.data_dir / "index.sqlite3"
        if db_file.exists():
            return
        subprocess.run(
            self._archivebox_cmd("init", "--quick"),
            cwd=str(self.data_dir),
            env={**os.environ, "DATA_DIR": str(self.data_dir)},
            check=True,
            stdin=subprocess.DEVNULL,
        )

    # ------------------------------------------------------------------
    # Public operations
    # ------------------------------------------------------------------
    def start_server(self) -> dict[str, Any]:
        status = self.status()
        if status["server"]["running"]:
            return status["server"]
        command = self.server_command or self._archivebox_cmd("server", f"{self.host}:{self.port}")
        return self._spawn("server", command, "tray_server.log")

    def start_runner(self) -> dict[str, Any]:
        status = self.status()
        if status["runner"]["running"]:
            return status["runner"]
        command = self.runner_command or self._archivebox_cmd("run", "--daemon")
        return self._spawn("runner", command, "tray_runner.log")

    def stop_server(self) -> bool:
        state = self._load_state()
        row = state.get("server") or {}
        pid = int(row.get("pid") or 0)
        if pid:
            self._terminate_pid(pid)
        self._clear_state_key("server")
        return True

    def stop_runner(self) -> bool:
        state = self._load_state()
        row = state.get("runner") or {}
        pid = int(row.get("pid") or 0)
        if pid:
            self._terminate_pid(pid)
        self._clear_state_key("runner")
        return True

    def start_services(self, *, start_server: bool = True, start_runner: bool = True, ensure_initialized: bool = True) -> None:
        if not start_server and not start_runner:
            return
        if ensure_initialized:
            self._ensure_initialized()
        if start_server:
            self.start_server()
        if start_runner:
            self.start_runner()

    def stop_services(self, *, stop_server: bool = True, stop_runner: bool = True) -> None:
        if stop_runner:
            self.stop_runner()
        if stop_server:
            self.stop_server()

    def status(self) -> dict[str, Any]:
        state = self._load_state()
        result: dict[str, Any] = {
            "data_dir": str(self.data_dir),
            "web_url": f"http://{self.host}:{self.port}",
            "server": {"running": False, "pid": None},
            "runner": {"running": False, "pid": None},
        }

        changed = False
        for key in ("server", "runner"):
            row = state.get(key) or {}
            pid = int(row.get("pid") or 0)
            started_at = row.get("started_at")
            running = self._is_process_alive(pid, started_at)
            if running:
                result[key] = {"running": True, "pid": pid}
            else:
                result[key] = {"running": False, "pid": None}
                if key in state:
                    del state[key]
                    changed = True
        if changed:
            self._save_state(state)
        return result

    def open_web_ui(self) -> str:
        url = f"http://{self.host}:{self.port}"
        webbrowser.open(url)
        return url
