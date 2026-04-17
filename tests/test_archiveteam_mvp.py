from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from archivebox.archiveteam import (
    ArchiveMode,
    ArchiveTeamError,
    ArchiveTeamNetwork,
    ArchiveTeamNode,
    RatioBand,
)


class FixedClock:
    def __init__(self, start: datetime) -> None:
        self.current = start

    def now(self) -> datetime:
        return self.current

    def advance(self, delta: timedelta) -> None:
        self.current += delta


def _new_user(network: ArchiveTeamNetwork, username: str, country: str, is_worker: bool = True):
    keypair = network.create_keypair()
    user = network.register_user(
        public_key=keypair["display_public_key"],
        username=username,
        country_code=country,
        is_worker=is_worker,
    )
    return keypair, user


def test_key_prefix_and_profile_validation(tmp_path):
    network = ArchiveTeamNetwork(storage_path=str(tmp_path / "state.json"))
    keypair, user = _new_user(network, "alice", "us")

    assert user["display_public_key"].startswith("AT")
    assert network.normalize_public_key(user["display_public_key"]) == keypair["public_key"]

    with pytest.raises(ArchiveTeamError):
        network.update_profile(
            public_key=user["display_public_key"],
            pfp_url="https://example.com/pfp.png",
            bio="x" * 501,
            website_url="https://example.com",
        )

    profile = network.update_profile(
        public_key=user["display_public_key"],
        pfp_url="https://example.com/pfp.png",
        bio="hello world",
        website_url="https://example.com",
    )
    assert profile["pfp_size"] == "200x200"
    assert profile["bio"] == "hello world"


def test_login_challenge_signature_roundtrip():
    network = ArchiveTeamNetwork()
    keypair, user = _new_user(network, "alice", "us")
    node = ArchiveTeamNode(network=network, private_key=keypair["private_key"], public_key=keypair["public_key"])

    challenge = network.issue_login_challenge(user["display_public_key"])
    signature = node.sign_login_challenge(challenge)
    token = network.complete_login(user["display_public_key"], signature)

    assert token
    assert token in network.sessions


def test_request_claim_fulfill_and_online_search():
    clock = FixedClock(datetime(2026, 1, 1, tzinfo=timezone.utc))
    network = ArchiveTeamNetwork(now_fn=clock.now)

    requester_keys, requester = _new_user(network, "requester", "US", is_worker=True)
    worker_keys, worker = _new_user(network, "worker", "CA", is_worker=True)

    requester_node = ArchiveTeamNode(network, requester_keys["private_key"], requester_keys["public_key"])
    worker_node = ArchiveTeamNode(network, worker_keys["private_key"], worker_keys["public_key"])

    requester_node.heartbeat(country_code="US")
    worker_node.heartbeat(country_code="CA")

    request = requester_node.submit_request(
        url="https://example.com",
        archive_mode=ArchiveMode.ZIP_WARC.value,
        country_preference="CA",
    )
    assert request["archive_mode"] == ArchiveMode.ZIP_WARC.value

    claimed = worker_node.poll_and_claim()
    assert claimed is not None
    assert claimed["request_id"] == request["request_id"]

    archive = worker_node.fulfill_claimed_request(
        request_id=request["request_id"],
        archive_bytes=b"fake warc payload",
        storage_uri=worker_node.generate_storage_uri(),
    )
    assert archive["archive_mode"] == ArchiveMode.ZIP_WARC.value
    assert len(network.ledger) == 1
    assert network.ledger[0]["payload"]["event"] == "ArchiveFulfilled"

    available = network.search_available_archives("example.com")
    assert len(available) == 1
    assert available[0]["archive_id"] == archive["archive_id"]

    worker_node.go_offline()
    assert network.search_available_archives("example.com") == []


def test_pin_window_expiry_and_requester_self_hosting():
    clock = FixedClock(datetime(2026, 1, 1, tzinfo=timezone.utc))
    network = ArchiveTeamNetwork(now_fn=clock.now)
    requester_keys, requester = _new_user(network, "requester", "US", is_worker=True)
    worker_keys, worker = _new_user(network, "worker", "US", is_worker=True)

    requester_node = ArchiveTeamNode(network, requester_keys["private_key"], requester_keys["public_key"])
    worker_node = ArchiveTeamNode(network, worker_keys["private_key"], worker_keys["public_key"])

    requester_node.heartbeat(country_code="US")
    worker_node.heartbeat(country_code="US")

    request = requester_node.submit_request("https://archive.org", ArchiveMode.FULL_WARC.value)
    worker_node.poll_and_claim()
    archive = worker_node.fulfill_claimed_request(
        request_id=request["request_id"],
        archive_bytes=b"payload",
        storage_uri="ipfs://cid",
    )

    assert len(network.search_available_archives()) == 1

    clock.advance(timedelta(hours=24, seconds=1))
    assert network.search_available_archives() == []

    requester_node.heartbeat(country_code="US")
    requester_node.self_host_archive(archive["archive_id"])
    assert len(network.search_available_archives()) == 1


def test_ratio_scoring_and_serve_events():
    clock = FixedClock(datetime(2026, 1, 1, tzinfo=timezone.utc))
    network = ArchiveTeamNetwork(now_fn=clock.now)
    requester_keys, requester = _new_user(network, "requester", "US", is_worker=True)
    worker_keys, worker = _new_user(network, "worker", "US", is_worker=True)

    requester_node = ArchiveTeamNode(network, requester_keys["private_key"], requester_keys["public_key"])
    worker_node = ArchiveTeamNode(network, worker_keys["private_key"], worker_keys["public_key"])

    requester_node.heartbeat(country_code="US")
    worker_node.heartbeat(country_code="US")

    req = requester_node.submit_request("https://example.org", ArchiveMode.FULL_WARC.value)
    worker_node.poll_and_claim()
    archive = worker_node.fulfill_claimed_request(
        request_id=req["request_id"],
        archive_bytes=b"archive bytes",
        storage_uri="ipfs://abc",
    )

    worker_node.serve_archive_to(requester["display_public_key"], archive["archive_id"])
    worker_summary = network.get_user_summary(worker["display_public_key"])
    requester_summary = network.get_user_summary(requester["display_public_key"])

    assert worker_summary["stats"]["files_served"] == 1
    assert worker_summary["ratio_band"] == RatioBand.GREEN.value
    assert requester_summary["stats"]["files_requested"] >= 2
    assert len(network.ledger) == 2
    assert network.ledger[1]["payload"]["event"] == "ArchiveServed"


def test_non_worker_cannot_submit():
    network = ArchiveTeamNetwork()
    keypair = network.create_keypair()
    user = network.register_user(
        public_key=keypair["public_key"],
        username="reader",
        country_code="US",
        is_worker=False,
    )
    with pytest.raises(ArchiveTeamError):
        network.submit_request(
            requester_public_key=user["display_public_key"],
            url="https://example.com",
            archive_mode=ArchiveMode.FULL_WARC.value,
        )
