from __future__ import annotations

from pathlib import Path

from archivebox.tray.controller import TrayProcessController


def test_tray_controller_tracks_server_runner_and_process_state(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    controller = TrayProcessController(
        data_dir=data_dir,
        host="127.0.0.1",
        port=8000,
        command_prefix=["python", "-m", "archivebox"],
        server_command=["python", "-c", "import time; time.sleep(120)"],
        runner_command=["python", "-c", "import time; time.sleep(120)"],
    )

    state = controller.status()
    assert state["server"]["running"] is False
    assert state["runner"]["running"] is False

    server_state = controller.start_server()
    assert server_state["pid"] is not None

    runner_state = controller.start_runner()
    assert runner_state["pid"] is not None

    status = controller.status()
    assert status["server"]["running"] is True
    assert status["runner"]["running"] is True

    controller.stop_server()
    controller.stop_runner()

    status_after_stop = controller.status()
    assert status_after_stop["server"]["running"] is False
    assert status_after_stop["runner"]["running"] is False
