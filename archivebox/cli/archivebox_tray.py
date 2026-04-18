#!/usr/bin/env python3
from __future__ import annotations

__package__ = "archivebox.cli"
__command__ = "archivebox tray"

import io
import sys
import threading
import webbrowser

import rich_click as click
from rich import print

from archivebox.misc.util import docstring
from archivebox.tray.controller import TrayProcessController


def _make_icon_image():
    from PIL import Image, ImageDraw

    size = 64
    image = Image.new("RGBA", (size, size), (11, 20, 39, 255))
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle((6, 6, 58, 58), radius=12, fill=(24, 49, 95, 255), outline=(126, 249, 214, 255), width=2)
    draw.polygon(((16, 24), (32, 16), (48, 24), (32, 32)), fill=(126, 249, 214, 230))
    draw.rectangle((16, 24, 32, 44), fill=(24, 49, 95, 255))
    draw.rectangle((32, 24, 48, 44), fill=(40, 74, 133, 255))
    return image


def _render_status(controller: TrayProcessController) -> str:
    status = controller.status()
    server_state = "running" if status.get("server", {}).get("running") else "stopped"
    runner_state = "running" if status.get("runner", {}).get("running") else "stopped"
    return (
        f"Server: {server_state} ({status['web_url']}) | "
        f"Runner: {runner_state}"
    )


def _create_menu(icon, controller: TrayProcessController):
    import pystray

    def _refresh_display():
        icon.title = _render_status(controller)
        icon.update_menu()

    def _start_server(_icon, _item):
        controller.start_server()
        _refresh_display()

    def _stop_server(_icon, _item):
        controller.stop_server()
        _refresh_display()

    def _start_runner(_icon, _item):
        controller.start_runner()
        _refresh_display()

    def _stop_runner(_icon, _item):
        controller.stop_runner()
        _refresh_display()

    def _open_web(_icon, _item):
        webbrowser.open(controller.server_url())

    def _open_admin(_icon, _item):
        webbrowser.open(f"{controller.server_url()}/admin")

    def _quit(_icon, _item):
        controller.stop_runner()
        controller.stop_server()
        icon.stop()

    return pystray.Menu(
        pystray.MenuItem("Status", lambda _icon, _item: None, enabled=False),
        pystray.MenuItem(
            lambda _item: _render_status(controller),
            lambda _icon, _item: None,
            enabled=False,
        ),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem(
            "Start Server",
            _start_server,
            enabled=lambda _item: not controller.status().get("server", {}).get("running"),
        ),
        pystray.MenuItem(
            "Stop Server",
            _stop_server,
            enabled=lambda _item: controller.status().get("server", {}).get("running", False),
        ),
        pystray.MenuItem(
            "Start Worker Runner",
            _start_runner,
            enabled=lambda _item: not controller.status().get("runner", {}).get("running"),
        ),
        pystray.MenuItem(
            "Stop Worker Runner",
            _stop_runner,
            enabled=lambda _item: controller.status().get("runner", {}).get("running", False),
        ),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Open Web UI", _open_web),
        pystray.MenuItem("Open Admin", _open_admin),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Quit Tray App", _quit),
    )


def _run_headless(controller: TrayProcessController) -> None:
    print("[yellow][*] Running in headless tray fallback mode.[/yellow]")
    print(f"[green][+] Status:[/green] {_render_status(controller)}")
    print("Commands: status, start-server, stop-server, start-runner, stop-runner, open, admin, quit")
    while True:
        try:
            command = input("archivebox-tray> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            command = "quit"

        if command in {"quit", "exit"}:
            controller.stop_runner()
            controller.stop_server()
            break
        if command == "status":
            print(_render_status(controller))
        elif command == "start-server":
            controller.start_server()
            print(_render_status(controller))
        elif command == "stop-server":
            controller.stop_server()
            print(_render_status(controller))
        elif command == "start-runner":
            controller.start_runner()
            print(_render_status(controller))
        elif command == "stop-runner":
            controller.stop_runner()
            print(_render_status(controller))
        elif command == "open":
            webbrowser.open(controller.server_url())
        elif command == "admin":
            webbrowser.open(f"{controller.server_url()}/admin")
        else:
            print("[yellow]Unknown command.[/yellow]")


@click.command()
@click.option("--host", default="127.0.0.1", show_default=True, help="Host for ArchiveBox web server.")
@click.option("--port", default=8000, show_default=True, type=int, help="Port for ArchiveBox web server.")
@click.option("--auto-start", is_flag=True, help="Automatically start web server and runner when tray launches.")
@click.option("--headless", is_flag=True, help="Run tray controller in terminal mode without desktop UI.")
@docstring("Run ArchiveBox as a cross-platform system tray app.")
def main(host: str, port: int, auto_start: bool, headless: bool) -> None:
    from archivebox.config import DATA_DIR
    controller = TrayProcessController(data_dir=DATA_DIR, host=host, port=port)
    if auto_start:
        controller.start_server()
        controller.start_runner()

    if headless:
        _run_headless(controller)
        return

    try:
        import pystray
        from PIL import Image  # noqa: F401
    except Exception as exc:
        print(f"[yellow][!] Tray dependencies unavailable: {exc}[/yellow]")
        print("[yellow][*] Falling back to headless mode.[/yellow]")
        _run_headless(controller)
        return

    icon = pystray.Icon(
        "archivebox-tray",
        _make_icon_image(),
        "ArchiveBox Tray",
    )
    icon.menu = _create_menu(icon, controller)
    icon.title = _render_status(controller)

    def _status_updater():
        import time

        while icon.visible:
            icon.title = _render_status(controller)
            time.sleep(2)

    updater = threading.Thread(target=_status_updater, daemon=True)
    updater.start()
    icon.run()


if __name__ == "__main__":
    main()
