from __future__ import annotations

import json
import os
from django.test import Client

from archivebox.config.django import setup_django


def _json(response):
    return json.loads(response.content.decode("utf-8"))


def _post_json(client: Client, url: str, payload: dict, **kwargs):
    return client.post(url, data=json.dumps(payload), content_type="application/json", follow=False, **kwargs)


def test_archiveteam_api_end_to_end(tmp_path, monkeypatch):
    out_dir = tmp_path / "api-data"
    out_dir.mkdir(parents=True, exist_ok=True)

    state_file = out_dir / "archiveteam_state.json"
    monkeypatch.setenv("ARCHIVETEAM_STATE_FILE", str(state_file))
    monkeypatch.setenv("DATA_DIR", str(out_dir))
    setup_django(check_db=False, in_memory_db=False)

    client = Client(HTTP_HOST="api.archivebox.localhost:8000")

    # Register two users
    register_owner = _post_json(
        client,
        "/api/archiveteam/register",
        {"username": "owner", "country": "US", "is_worker": True},
    )
    assert register_owner.status_code == 201
    owner_payload = _json(register_owner)
    owner_key = owner_payload["user"]["display_public_key"]

    register_worker = _post_json(
        client,
        "/api/archiveteam/register",
        {"username": "worker", "country": "US", "is_worker": True},
    )
    assert register_worker.status_code == 201
    worker_payload = _json(register_worker)
    worker_key = worker_payload["user"]["display_public_key"]

    # Mark both online
    owner_headers = {"HTTP_X_AT_SESSION": owner_payload["keys"]["private_key"]}  # intentionally wrong token first
    bad_heartbeat = client.post("/api/archiveteam/heartbeat", data="{}", content_type="application/json", follow=True, **owner_headers)
    assert bad_heartbeat.status_code == 400

    # Login flow for owner
    owner_challenge = _post_json(
        client,
        "/api/archiveteam/login/challenge",
        {"public_key": owner_key},
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

    owner_login = _post_json(
        client,
        "/api/archiveteam/login/complete",
        {"public_key": owner_key, "signature": owner_sig},
    )
    assert owner_login.status_code == 200
    owner_session = _json(owner_login)["session_token"]

    # Login flow for worker
    worker_challenge = _post_json(
        client,
        "/api/archiveteam/login/challenge",
        {"public_key": worker_key},
    )
    challenge_value_worker = _json(worker_challenge)["challenge"]
    worker_node = ArchiveTeamNode(
        network=temp_network,
        private_key=worker_payload["keys"]["private_key"],
        public_key=worker_payload["keys"]["public_key"],
    )
    worker_sig = worker_node.sign_login_challenge(challenge_value_worker)
    worker_login = _post_json(
        client,
        "/api/archiveteam/login/complete",
        {"public_key": worker_key, "signature": worker_sig},
    )
    worker_session = _json(worker_login)["session_token"]

    # Heartbeats
    owner_heartbeat = _post_json(
        client,
        "/api/archiveteam/heartbeat",
        {"country_code": "US"},
        HTTP_X_AT_SESSION=owner_session,
    )
    assert owner_heartbeat.status_code == 200
    worker_heartbeat = _post_json(
        client,
        "/api/archiveteam/heartbeat",
        {"country_code": "US"},
        HTTP_X_AT_SESSION=worker_session,
    )
    assert worker_heartbeat.status_code == 200

    # Owner submits request, worker claims + fulfills
    submitted = _post_json(
        client,
        "/api/archiveteam/requests",
        {"url": "https://example.com", "archive_mode": "FULL_WARC"},
        HTTP_X_AT_SESSION=owner_session,
    )
    assert submitted.status_code == 201
    request_id = _json(submitted)["request_id"]

    claimed = _post_json(
        client,
        "/api/archiveteam/requests/claim",
        {"request_id": request_id},
        HTTP_X_AT_SESSION=worker_session,
    )
    assert claimed.status_code == 200

    fulfilled = _post_json(
        client,
        "/api/archiveteam/requests/fulfill",
        {
            "request_id": request_id,
            "content_hash": "a" * 64,
            "storage_uri": "ipfs://abc123",
        },
        HTTP_X_AT_SESSION=worker_session,
    )
    assert fulfilled.status_code == 200
    archive_id = _json(fulfilled)["archive_id"]

    # Collection create + submit + review + fork
    created_collection = _post_json(
        client,
        "/api/archiveteam/collections",
        {
            "name": "Main Collection",
            "description": "desc",
            "allow_submissions": True,
        },
        HTTP_X_AT_SESSION=owner_session,
    )
    assert created_collection.status_code == 201
    collection_id = _json(created_collection)["collection_id"]

    submitted_to_collection = _post_json(
        client,
        f"/api/archiveteam/collections/{collection_id}/submit",
        {"archive_id": archive_id, "note": "please add"},
        HTTP_X_AT_SESSION=worker_session,
    )
    assert submitted_to_collection.status_code == 201
    submission_id = _json(submitted_to_collection)["submission_id"]

    reviewed = _post_json(
        client,
        f"/api/archiveteam/submissions/{submission_id}/review",
        {"approve": True},
        HTTP_X_AT_SESSION=owner_session,
    )
    assert reviewed.status_code == 200
    assert _json(reviewed)["status"] == "APPROVED"

    forked = _post_json(
        client,
        f"/api/archiveteam/collections/{collection_id}/fork",
        {"name": "Forked"},
        HTTP_X_AT_SESSION=worker_session,
    )
    assert forked.status_code == 201
    assert _json(forked)["forked_from"] == collection_id

    # Safety filter (default blocked term)
    blocked = _post_json(
        client,
        "/api/archiveteam/requests",
        {"url": "https://example.com/csam"},
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


def test_archiveteam_api_governance_proposal_flow(tmp_path, monkeypatch):
    out_dir = tmp_path / "api-gov-data"
    out_dir.mkdir(parents=True, exist_ok=True)

    state_file = out_dir / "archiveteam_state.json"
    monkeypatch.setenv("ARCHIVETEAM_STATE_FILE", str(state_file))
    monkeypatch.setenv("DATA_DIR", str(out_dir))
    setup_django(check_db=False, in_memory_db=False)
    client = Client(HTTP_HOST="api.archivebox.localhost:8000")

    # register author + voters
    author_payload = _json(_post_json(client, "/api/archiveteam/register", {"username": "author", "country": "US", "is_worker": True}))
    voter1_payload = _json(_post_json(client, "/api/archiveteam/register", {"username": "voter1", "country": "US", "is_worker": True}))
    voter2_payload = _json(_post_json(client, "/api/archiveteam/register", {"username": "voter2", "country": "US", "is_worker": True}))

    from archivebox.archiveteam import ArchiveTeamNode, ArchiveTeamNetwork

    temp_network = ArchiveTeamNetwork(storage_path=str(state_file))
    author_node = ArchiveTeamNode(
        network=temp_network,
        private_key=author_payload["keys"]["private_key"],
        public_key=author_payload["keys"]["public_key"],
    )
    voter1_node = ArchiveTeamNode(
        network=temp_network,
        private_key=voter1_payload["keys"]["private_key"],
        public_key=voter1_payload["keys"]["public_key"],
    )
    voter2_node = ArchiveTeamNode(
        network=temp_network,
        private_key=voter2_payload["keys"]["private_key"],
        public_key=voter2_payload["keys"]["public_key"],
    )

    def login(display_public_key, node):
        challenge = _json(_post_json(client, "/api/archiveteam/login/challenge", {"public_key": display_public_key}))["challenge"]
        signature = node.sign_login_challenge(challenge)
        login_resp = _post_json(client, "/api/archiveteam/login/complete", {"public_key": display_public_key, "signature": signature})
        assert login_resp.status_code == 200
        return _json(login_resp)["session_token"]

    author_session = login(author_payload["user"]["display_public_key"], author_node)
    voter1_session = login(voter1_payload["user"]["display_public_key"], voter1_node)
    voter2_session = login(voter2_payload["user"]["display_public_key"], voter2_node)

    proposal_resp = _post_json(
        client,
        "/api/archiveteam/proposals",
        {
            "title": "Add richer moderation tools",
            "description": "Enable community votes on changes before rollout.",
            "change_type": "FEATURE",
            "target": "governance",
            "quorum": 2,
            "yes_threshold": 0.5,
        },
        HTTP_X_AT_SESSION=author_session,
    )
    assert proposal_resp.status_code == 201
    proposal = _json(proposal_resp)

    vote1 = _post_json(
        client,
        f"/api/archiveteam/proposals/{proposal['proposal_id']}/vote",
        {"vote": "YES"},
        HTTP_X_AT_SESSION=voter1_session,
    )
    assert vote1.status_code == 200
    vote2 = _post_json(
        client,
        f"/api/archiveteam/proposals/{proposal['proposal_id']}/vote",
        {"vote": "NO"},
        HTTP_X_AT_SESSION=voter2_session,
    )
    assert vote2.status_code == 200

    finalized = _post_json(
        client,
        f"/api/archiveteam/proposals/{proposal['proposal_id']}/finalize",
        {},
        HTTP_X_AT_SESSION=author_session,
    )
    assert finalized.status_code == 200
    finalized_payload = _json(finalized)
    assert finalized_payload["status"] in {"APPROVED", "REJECTED"}

    listed = client.get("/api/archiveteam/proposals")
    assert listed.status_code == 200
    rows = _json(listed)
    assert any(row["proposal_id"] == proposal["proposal_id"] for row in rows)


def test_archiveteam_api_site_pinning_flow(tmp_path, monkeypatch):
    out_dir = tmp_path / "api-site-data"
    out_dir.mkdir(parents=True, exist_ok=True)

    state_file = out_dir / "archiveteam_state.json"
    monkeypatch.setenv("ARCHIVETEAM_STATE_FILE", str(state_file))
    monkeypatch.setenv("DATA_DIR", str(out_dir))
    setup_django(check_db=False, in_memory_db=False)
    client = Client(HTTP_HOST="api.archivebox.localhost:8000")

    owner_payload = _json(_post_json(client, "/api/archiveteam/register", {"username": "owner", "country": "US", "is_worker": True}))
    node1_payload = _json(_post_json(client, "/api/archiveteam/register", {"username": "node1", "country": "US", "is_worker": True}))
    node2_payload = _json(_post_json(client, "/api/archiveteam/register", {"username": "node2", "country": "US", "is_worker": True}))

    from archivebox.archiveteam import ArchiveTeamNode, ArchiveTeamNetwork

    temp_network = ArchiveTeamNetwork(storage_path=str(state_file))
    owner_node = ArchiveTeamNode(
        network=temp_network,
        private_key=owner_payload["keys"]["private_key"],
        public_key=owner_payload["keys"]["public_key"],
    )
    node1 = ArchiveTeamNode(
        network=temp_network,
        private_key=node1_payload["keys"]["private_key"],
        public_key=node1_payload["keys"]["public_key"],
    )
    node2 = ArchiveTeamNode(
        network=temp_network,
        private_key=node2_payload["keys"]["private_key"],
        public_key=node2_payload["keys"]["public_key"],
    )

    def login(display_public_key, node):
        challenge = _json(_post_json(client, "/api/archiveteam/login/challenge", {"public_key": display_public_key}))["challenge"]
        signature = node.sign_login_challenge(challenge)
        login_resp = _post_json(client, "/api/archiveteam/login/complete", {"public_key": display_public_key, "signature": signature})
        assert login_resp.status_code == 200
        return _json(login_resp)["session_token"]

    owner_session = login(owner_payload["user"]["display_public_key"], owner_node)
    node1_session = login(node1_payload["user"]["display_public_key"], node1)
    node2_session = login(node2_payload["user"]["display_public_key"], node2)

    # mark nodes online before pin attestations so health can count them
    for session in (node1_session, node2_session):
        hb = _post_json(
            client,
            "/api/archiveteam/heartbeat",
            {"country_code": "US"},
            HTTP_X_AT_SESSION=session,
        )
        assert hb.status_code == 200

    cid = "bafybeigdyrztw4b4k6z6l5y5vci4c3p6k2wrg7u2v5uqf5h3i3b7v5r5pu"
    release = _post_json(
        client,
        "/api/archiveteam/site/release",
        {"cid": cid, "version": "1.0.0", "notes": "Initial release"},
        HTTP_X_AT_SESSION=owner_session,
    )
    assert release.status_code == 200
    assert _json(release)["current_cid"] == cid

    for session in (node1_session, node2_session):
        attest = _post_json(
            client,
            "/api/archiveteam/site/pin-attest",
            {"pin_provider": "local-ipfs", "pinned": True},
            HTTP_X_AT_SESSION=session,
        )
        assert attest.status_code == 200
        assert _json(attest)["cid"] == cid

    pinners = client.get("/api/archiveteam/site/pinners")
    assert pinners.status_code == 200
    assert len(_json(pinners)) == 2

    health = client.get("/api/archiveteam/site/health?min_online_pinners=2")
    assert health.status_code == 200
    health_payload = _json(health)
    assert health_payload["healthy"] is True
    assert health_payload["online_pinners"] == 2


def test_archiveteam_api_request_options_and_media_profiles(tmp_path, monkeypatch):
    out_dir = tmp_path / "api-request-options"
    out_dir.mkdir(parents=True, exist_ok=True)

    state_file = out_dir / "archiveteam_state.json"
    monkeypatch.setenv("ARCHIVETEAM_STATE_FILE", str(state_file))
    monkeypatch.setenv("DATA_DIR", str(out_dir))
    setup_django(check_db=False, in_memory_db=False)
    client = Client(HTTP_HOST="api.archivebox.localhost:8000")

    register = _post_json(
        client,
        "/api/archiveteam/register",
        {"username": "media", "country": "US", "is_worker": True},
    )
    assert register.status_code == 201
    payload = _json(register)

    from archivebox.archiveteam import ArchiveTeamNode, ArchiveTeamNetwork

    temp_network = ArchiveTeamNetwork(storage_path=str(state_file))
    node = ArchiveTeamNode(
        network=temp_network,
        private_key=payload["keys"]["private_key"],
        public_key=payload["keys"]["public_key"],
    )

    challenge = _json(
        _post_json(client, "/api/archiveteam/login/challenge", {"public_key": payload["user"]["display_public_key"]})
    )["challenge"]
    signature = node.sign_login_challenge(challenge)
    session = _json(
        _post_json(
            client,
            "/api/archiveteam/login/complete",
            {"public_key": payload["user"]["display_public_key"], "signature": signature},
        )
    )["session_token"]

    options = client.get("/api/archiveteam/request-options")
    assert options.status_code == 200
    options_payload = _json(options)
    assert "MEDIA_YTDLP" in options_payload["archive_modes"]
    assert "GALLERY_DL" in options_payload["archive_modes"]
    assert "media_fast" in options_payload["download_profiles"]
    assert "gallery_deep" in options_payload["download_profiles"]
    assert options_payload["default_worker_controls"]["max_retries"] == 3

    media_req = _post_json(
        client,
        "/api/archiveteam/requests",
        {
            "url": "https://youtube.com/watch?v=abc",
            "archive_mode": "MEDIA_YTDLP",
            "download_profile": "media_fast",
            "profile_options": {"video_quality": "720p", "audio_only": False},
            "worker_controls": {"max_retries": 4, "sleep_interval_seconds": 2},
        },
        HTTP_X_AT_SESSION=session,
    )
    assert media_req.status_code == 201
    media_payload = _json(media_req)
    assert media_payload["archive_mode"] == "MEDIA_YTDLP"
    assert media_payload["profile_options"]["video_quality"] == "720p"
    assert media_payload["worker_controls"]["max_retries"] == 4

    gallery_req = _post_json(
        client,
        "/api/archiveteam/requests",
        {
            "url": "https://instagram.com/p/test",
            "archive_mode": "GALLERY_DL",
            "download_profile": "gallery_deep",
            "profile_options": {"gallery_max_items": 123},
        },
        HTTP_X_AT_SESSION=session,
    )
    assert gallery_req.status_code == 201
    gallery_payload = _json(gallery_req)
    assert gallery_payload["archive_mode"] == "GALLERY_DL"
    assert gallery_payload["profile_options"]["gallery_max_items"] == 123

    coursera_req = _post_json(
        client,
        "/api/archiveteam/requests",
        {
            "url": "https://coursera.org/learn/crypto",
            "archive_mode": "FULL_WARC",
            "download_profile": "forensic",
        },
        HTTP_X_AT_SESSION=session,
    )
    assert coursera_req.status_code == 201
    assert "auth_gated_source" in _json(coursera_req)["policy_flags"]

    invalid_profile = _post_json(
        client,
        "/api/archiveteam/requests",
        {
            "url": "https://youtube.com/watch?v=abc",
            "archive_mode": "MEDIA_YTDLP",
            "download_profile": "forensic",
        },
        HTTP_X_AT_SESSION=session,
    )
    assert invalid_profile.status_code == 400

    blocked_drm = _post_json(
        client,
        "/api/archiveteam/requests",
        {
            "url": "https://www.netflix.com/title/1234",
            "archive_mode": "MEDIA_YTDLP",
        },
        HTTP_X_AT_SESSION=session,
    )
    assert blocked_drm.status_code == 400


def test_archiveteam_api_network_settings_rules_and_candidates(tmp_path, monkeypatch):
    out_dir = tmp_path / "api-network-rules-data"
    out_dir.mkdir(parents=True, exist_ok=True)

    state_file = out_dir / "archiveteam_state.json"
    monkeypatch.setenv("ARCHIVETEAM_STATE_FILE", str(state_file))
    monkeypatch.setenv("DATA_DIR", str(out_dir))
    setup_django(check_db=False, in_memory_db=False)
    client = Client(HTTP_HOST="api.archivebox.localhost:8000")

    requester_payload = _json(
        _post_json(client, "/api/archiveteam/register", {"username": "requester", "country": "US", "is_worker": True})
    )
    worker_payload = _json(
        _post_json(client, "/api/archiveteam/register", {"username": "worker", "country": "US", "is_worker": True})
    )

    from archivebox.archiveteam import ArchiveTeamNode, ArchiveTeamNetwork

    temp_network = ArchiveTeamNetwork(storage_path=str(state_file))
    requester_node = ArchiveTeamNode(
        network=temp_network,
        private_key=requester_payload["keys"]["private_key"],
        public_key=requester_payload["keys"]["public_key"],
    )
    worker_node = ArchiveTeamNode(
        network=temp_network,
        private_key=worker_payload["keys"]["private_key"],
        public_key=worker_payload["keys"]["public_key"],
    )

    def login(display_public_key, node):
        challenge = _json(_post_json(client, "/api/archiveteam/login/challenge", {"public_key": display_public_key}))["challenge"]
        signature = node.sign_login_challenge(challenge)
        login_resp = _post_json(client, "/api/archiveteam/login/complete", {"public_key": display_public_key, "signature": signature})
        assert login_resp.status_code == 200
        return _json(login_resp)["session_token"]

    requester_session = login(requester_payload["user"]["display_public_key"], requester_node)
    worker_session = login(worker_payload["user"]["display_public_key"], worker_node)

    # Mark nodes online so claims can succeed.
    assert _post_json(
        client,
        "/api/archiveteam/heartbeat",
        {"country_code": "US"},
        HTTP_X_AT_SESSION=requester_session,
    ).status_code == 200
    assert _post_json(
        client,
        "/api/archiveteam/heartbeat",
        {"country_code": "US"},
        HTTP_X_AT_SESSION=worker_session,
    ).status_code == 200

    # Worker configures job/storage/day and serving rules.
    network_update = _post_json(
        client,
        "/api/archiveteam/settings/network",
        {
            "max_jobs_per_day": 1,
            "max_storage_gb_per_day": 1.25,
            "max_upload_gb_per_day": 1.5,
            "max_download_gb_per_day": 2.0,
            "daily_upload_speed_mbps": 12,
            "daily_download_speed_mbps": 25,
        },
        HTTP_X_AT_SESSION=worker_session,
    )
    assert network_update.status_code == 200
    assert _json(network_update)["max_jobs_per_day"] == 1

    rules_update = _post_json(
        client,
        "/api/archiveteam/settings/serving-rules",
        {
            "block_porn_links": True,
                "min_ratio_to_serve": 0.0,
            "prioritize_high_ratio_first": False,
            "prioritize_followed_first": True,
            "followed_public_keys": [requester_payload["user"]["display_public_key"]],
            "site_blacklist": ["blocked.example"],
            "rules_md": "deny: forbidden.example",
        },
        HTTP_X_AT_SESSION=worker_session,
    )
    assert rules_update.status_code == 200
    assert _json(rules_update)["block_porn_links"] is True

    network_get = client.get("/api/archiveteam/settings/network", HTTP_X_AT_SESSION=worker_session)
    assert network_get.status_code == 200
    assert _json(network_get)["daily_download_speed_mbps"] == 25

    rules_get = client.get("/api/archiveteam/settings/serving-rules", HTTP_X_AT_SESSION=worker_session)
    assert rules_get.status_code == 200
    rules_payload = _json(rules_get)
    assert rules_payload["min_ratio_to_serve"] == 0.0
    assert requester_payload["user"]["public_key"] in rules_payload["followed_public_keys"]

    porn_request = _post_json(
        client,
        "/api/archiveteam/requests",
        {"url": "https://example.com/porn-feed", "archive_mode": "FULL_WARC"},
        HTTP_X_AT_SESSION=requester_session,
    )
    assert porn_request.status_code == 201

    valid_request = _post_json(
        client,
        "/api/archiveteam/requests",
        {"url": "https://example.com/clean", "archive_mode": "FULL_WARC"},
        HTTP_X_AT_SESSION=requester_session,
    )
    assert valid_request.status_code == 201
    request_id = _json(valid_request)["request_id"]

    # Candidate list should include this request before claiming.
    candidates = client.get("/api/archiveteam/requests/candidates?limit=5", HTTP_X_AT_SESSION=worker_session)
    assert candidates.status_code == 200
    candidate_rows = _json(candidates)
    candidate_ids = {row["request_id"] for row in candidate_rows}
    assert request_id in candidate_ids
    assert _json(porn_request)["request_id"] not in candidate_ids

    claimed = _post_json(
        client,
        "/api/archiveteam/requests/claim",
        {"request_id": request_id},
        HTTP_X_AT_SESSION=worker_session,
    )
    assert claimed.status_code == 200

    # max_jobs_per_day=1 should prevent claiming another request today.
    second_request = _post_json(
        client,
        "/api/archiveteam/requests",
        {"url": "https://example.com/second-clean", "archive_mode": "FULL_WARC"},
        HTTP_X_AT_SESSION=requester_session,
    )
    assert second_request.status_code == 201
    claim_again = _post_json(
        client,
        "/api/archiveteam/requests/claim",
        {"request_id": _json(second_request)["request_id"]},
        HTTP_X_AT_SESSION=worker_session,
    )
    assert claim_again.status_code == 400
    assert "daily capacity reached" in _json(claim_again)["error"].lower()
