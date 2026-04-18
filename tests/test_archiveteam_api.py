from __future__ import annotations

import json
import os
from pathlib import Path

from django.test import Client

from archivebox.config import setup_django


def _json(response):
    return json.loads(response.content.decode("utf-8"))


def test_archiveteam_api_end_to_end(tmp_path, monkeypatch):
    out_dir = tmp_path / "api-data"
    out_dir.mkdir(parents=True, exist_ok=True)

    state_file = out_dir / "archiveteam_state.json"
    monkeypatch.setenv("ARCHIVETEAM_STATE_FILE", str(state_file))
    setup_django(out_dir=Path(out_dir), check_db=False, in_memory_db=True)

    client = Client()

    # Register two users
    register_owner = client.post(
        "/api/archiveteam/register",
        data=json.dumps({"username": "owner", "country": "US", "is_worker": True}),
        content_type="application/json",
    )
    assert register_owner.status_code == 201
    owner_payload = _json(register_owner)
    owner_key = owner_payload["user"]["display_public_key"]

    register_worker = client.post(
        "/api/archiveteam/register",
        data=json.dumps({"username": "worker", "country": "US", "is_worker": True}),
        content_type="application/json",
    )
    assert register_worker.status_code == 201
    worker_payload = _json(register_worker)
    worker_key = worker_payload["user"]["display_public_key"]

    # Mark both online
    owner_headers = {"HTTP_X_AT_SESSION": owner_payload["keys"]["private_key"]}  # intentionally wrong token first
    bad_heartbeat = client.post("/api/archiveteam/heartbeat", data="{}", content_type="application/json", **owner_headers)
    assert bad_heartbeat.status_code == 400

    # Login flow for owner
    owner_challenge = client.post(
        "/api/archiveteam/login/challenge",
        data=json.dumps({"public_key": owner_key}),
        content_type="application/json",
    )
    assert owner_challenge.status_code == 200
    challenge_value = _json(owner_challenge)["challenge"]

    from archivebox.archiveteam import ArchiveTeamNode, ArchiveTeamNetwork

    temp_network = ArchiveTeamNetwork(storage_path=str(state_file))
    owner_node = ArchiveTeamNode(
        network=temp_network,
        private_key=owner_payload["keys"]["private_key"],
        public_key=owner_payload["keys"]["public_key"],
    )
    owner_sig = owner_node.sign_login_challenge(challenge_value)

    owner_login = client.post(
        "/api/archiveteam/login/complete",
        data=json.dumps({"public_key": owner_key, "signature": owner_sig}),
        content_type="application/json",
    )
    assert owner_login.status_code == 200
    owner_session = _json(owner_login)["session_token"]

    # Login flow for worker
    worker_challenge = client.post(
        "/api/archiveteam/login/challenge",
        data=json.dumps({"public_key": worker_key}),
        content_type="application/json",
    )
    challenge_value_worker = _json(worker_challenge)["challenge"]
    worker_node = ArchiveTeamNode(
        network=temp_network,
        private_key=worker_payload["keys"]["private_key"],
        public_key=worker_payload["keys"]["public_key"],
    )
    worker_sig = worker_node.sign_login_challenge(challenge_value_worker)
    worker_login = client.post(
        "/api/archiveteam/login/complete",
        data=json.dumps({"public_key": worker_key, "signature": worker_sig}),
        content_type="application/json",
    )
    worker_session = _json(worker_login)["session_token"]

    # Heartbeats
    owner_heartbeat = client.post(
        "/api/archiveteam/heartbeat",
        data=json.dumps({"country_code": "US"}),
        content_type="application/json",
        HTTP_X_AT_SESSION=owner_session,
    )
    assert owner_heartbeat.status_code == 200
    worker_heartbeat = client.post(
        "/api/archiveteam/heartbeat",
        data=json.dumps({"country_code": "US"}),
        content_type="application/json",
        HTTP_X_AT_SESSION=worker_session,
    )
    assert worker_heartbeat.status_code == 200

    # Owner submits request, worker claims + fulfills
    submitted = client.post(
        "/api/archiveteam/requests",
        data=json.dumps({"url": "https://example.com", "archive_mode": "FULL_WARC"}),
        content_type="application/json",
        HTTP_X_AT_SESSION=owner_session,
    )
    assert submitted.status_code == 201
    request_id = _json(submitted)["request_id"]

    claimed = client.post(
        "/api/archiveteam/requests/claim",
        data=json.dumps({"request_id": request_id}),
        content_type="application/json",
        HTTP_X_AT_SESSION=worker_session,
    )
    assert claimed.status_code == 200

    fulfilled = client.post(
        "/api/archiveteam/requests/fulfill",
        data=json.dumps(
            {
                "request_id": request_id,
                "content_hash": "a" * 64,
                "storage_uri": "ipfs://abc123",
            }
        ),
        content_type="application/json",
        HTTP_X_AT_SESSION=worker_session,
    )
    assert fulfilled.status_code == 200
    archive_id = _json(fulfilled)["archive_id"]

    # Collection create + submit + review + fork
    created_collection = client.post(
        "/api/archiveteam/collections",
        data=json.dumps(
            {
                "name": "Main Collection",
                "description": "desc",
                "allow_submissions": True,
            }
        ),
        content_type="application/json",
        HTTP_X_AT_SESSION=owner_session,
    )
    assert created_collection.status_code == 201
    collection_id = _json(created_collection)["collection_id"]

    submitted_to_collection = client.post(
        f"/api/archiveteam/collections/{collection_id}/submit",
        data=json.dumps({"archive_id": archive_id, "note": "please add"}),
        content_type="application/json",
        HTTP_X_AT_SESSION=worker_session,
    )
    assert submitted_to_collection.status_code == 201
    submission_id = _json(submitted_to_collection)["submission_id"]

    reviewed = client.post(
        f"/api/archiveteam/submissions/{submission_id}/review",
        data=json.dumps({"approve": True}),
        content_type="application/json",
        HTTP_X_AT_SESSION=owner_session,
    )
    assert reviewed.status_code == 200
    assert _json(reviewed)["status"] == "APPROVED"

    forked = client.post(
        f"/api/archiveteam/collections/{collection_id}/fork",
        data=json.dumps({"name": "Forked"}),
        content_type="application/json",
        HTTP_X_AT_SESSION=worker_session,
    )
    assert forked.status_code == 201
    assert _json(forked)["forked_from"] == collection_id

    # Safety filter (default blocked term)
    blocked = client.post(
        "/api/archiveteam/requests",
        data=json.dumps({"url": "https://example.com/csam"}),
        content_type="application/json",
        HTTP_X_AT_SESSION=owner_session,
    )
    assert blocked.status_code == 400

    # Search + ratio endpoint should work
    search = client.get("/api/archiveteam/archives/search?query=example.com")
    assert search.status_code == 200
    assert len(_json(search)) >= 1

    ratio = client.get("/api/archiveteam/ratio", HTTP_X_AT_SESSION=worker_session)
    assert ratio.status_code == 200
    assert "ratio_score" in _json(ratio)

    # Ensure state file persisted to expected location
    assert state_file.exists()
