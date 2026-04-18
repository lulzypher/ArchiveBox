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


def test_collection_crud_submission_review_and_fork():
    network = ArchiveTeamNetwork()
    owner_keys, owner = _new_user(network, "owner", "US")
    submitter_keys, submitter = _new_user(network, "submitter", "US")
    forker_keys, forker = _new_user(network, "forker", "US")

    owner_node = ArchiveTeamNode(network, owner_keys["private_key"], owner_keys["public_key"])
    submitter_node = ArchiveTeamNode(network, submitter_keys["private_key"], submitter_keys["public_key"])
    owner_node.heartbeat("US")
    submitter_node.heartbeat("US")

    req = owner_node.submit_request("https://example.net", ArchiveMode.FULL_WARC.value)
    owner_node.poll_and_claim()
    archive = owner_node.fulfill_claimed_request(req["request_id"], b"bytes", "ipfs://collection-test")

    collection = network.create_collection(
        owner_public_key=owner["display_public_key"],
        name="Tech News",
        description="Interesting links",
        is_private=False,
        allow_submissions=True,
    )
    assert collection["name"] == "Tech News"
    assert collection["allow_submissions"] is True

    submission = network.submit_collection_entry(
        submitter_public_key=submitter["display_public_key"],
        collection_id=collection["collection_id"],
        archive_id=archive["archive_id"],
        note="Great fit for this collection",
    )
    assert submission["status"] == "PENDING"

    reviewed = network.review_collection_submission(
        owner_public_key=owner["display_public_key"],
        submission_id=submission["submission_id"],
        approve=True,
    )
    assert reviewed["status"] == "APPROVED"

    updated_collection = network.get_collection(
        collection_id=collection["collection_id"],
        viewer_public_key=owner["display_public_key"],
    )
    assert archive["archive_id"] in updated_collection["archives"]

    fork = network.fork_collection(
        forker_public_key=forker["display_public_key"],
        source_collection_id=collection["collection_id"],
        name="Forked Tech",
    )
    assert fork["forked_from"] == collection["collection_id"]
    assert fork["archives"] == updated_collection["archives"]

    network.update_collection(
        owner_public_key=owner["display_public_key"],
        collection_id=collection["collection_id"],
        is_private=True,
        allow_submissions=False,
    )
    with pytest.raises(ArchiveTeamError):
        network.get_collection(
            collection_id=collection["collection_id"],
            viewer_public_key=submitter["display_public_key"],
        )

    network.delete_collection(
        owner_public_key=owner["display_public_key"],
        collection_id=collection["collection_id"],
    )
    with pytest.raises(ArchiveTeamError):
        network.get_collection(collection_id=collection["collection_id"], viewer_public_key=owner["display_public_key"])


def test_safety_filter_blocks_obviously_flagged_urls():
    network = ArchiveTeamNetwork(
        blocked_url_terms=["forbidden-term"],
        blocked_hosts=["blocked.example"],
    )
    keys, user = _new_user(network, "safe-user", "US")

    with pytest.raises(ArchiveTeamError):
        network.submit_request(
            requester_public_key=user["display_public_key"],
            url="https://example.com/path/forbidden-term",
            archive_mode=ArchiveMode.FULL_WARC.value,
        )

    with pytest.raises(ArchiveTeamError):
        network.submit_request(
            requester_public_key=user["display_public_key"],
            url="https://blocked.example/safe",
            archive_mode=ArchiveMode.FULL_WARC.value,
        )


def test_governance_proposal_voting_and_finalization():
    network = ArchiveTeamNetwork()
    author_keys, author = _new_user(network, "author", "US")
    voter1_keys, voter1 = _new_user(network, "voter1", "US")
    voter2_keys, voter2 = _new_user(network, "voter2", "US")
    voter3_keys, voter3 = _new_user(network, "voter3", "US")

    proposal = network.create_proposal(
        author_public_key=author["display_public_key"],
        title="Add stricter URL policy checks",
        description="Propose expanding blocked host controls and review workflow.",
        change_type="POLICY",
        target="safety",
        proposed_patch="Add default blocked hosts list and escalation hooks.",
        quorum=3,
        yes_threshold=0.66,
    )
    assert proposal["status"] == "OPEN"
    assert proposal["yes_count"] == 0

    network.cast_proposal_vote(voter1["display_public_key"], proposal["proposal_id"], "YES")
    network.cast_proposal_vote(voter2["display_public_key"], proposal["proposal_id"], "YES")
    network.cast_proposal_vote(voter3["display_public_key"], proposal["proposal_id"], "NO")

    finalized = network.finalize_proposal(author["display_public_key"], proposal["proposal_id"])
    assert finalized["status"] == "APPROVED"
    assert finalized["result"] == "THRESHOLD_MET"
    assert finalized["yes_count"] == 2
    assert finalized["no_count"] == 1

    # votes can no longer be cast after finalization
    with pytest.raises(ArchiveTeamError):
        network.cast_proposal_vote(voter1["display_public_key"], proposal["proposal_id"], "YES")


def test_governance_proposal_author_close():
    network = ArchiveTeamNetwork()
    author_keys, author = _new_user(network, "author", "US")
    outsider_keys, outsider = _new_user(network, "outsider", "US")

    proposal = network.create_proposal(
        author_public_key=author["display_public_key"],
        title="Refactor network sync endpoint",
        description="Close this one manually as no longer needed.",
        change_type="FEATURE",
        target="sync",
        quorum=2,
    )

    with pytest.raises(ArchiveTeamError):
        network.close_proposal(outsider["display_public_key"], proposal["proposal_id"])

    closed = network.close_proposal(author["display_public_key"], proposal["proposal_id"])
    assert closed["status"] == "CLOSED"
    assert closed["result"] == "AUTHOR_CLOSED"
