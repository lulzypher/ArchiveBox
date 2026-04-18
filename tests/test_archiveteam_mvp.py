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


def test_governance_votes_are_weighted_by_ratio():
    network = ArchiveTeamNetwork()
    _, author = _new_user(network, "author", "US")
    _, high_ratio_voter = _new_user(network, "high", "US")
    _, low_ratio_voter = _new_user(network, "low", "US")

    high_stats = network.users[network.normalize_public_key(high_ratio_voter["display_public_key"])]["stats"]
    high_stats["files_served"] = 14
    high_stats["requests_processed"] = 4
    high_stats["files_requested"] = 1

    low_stats = network.users[network.normalize_public_key(low_ratio_voter["display_public_key"])]["stats"]
    low_stats["files_served"] = 0
    low_stats["requests_processed"] = 0
    low_stats["files_requested"] = 30

    proposal = network.create_proposal(
        author_public_key=author["display_public_key"],
        title="Weighted vote check",
        description="Ensure high-ratio contributors have more governance weight.",
        change_type="POLICY",
        quorum=2,
        yes_threshold=0.6,
    )
    network.cast_proposal_vote(high_ratio_voter["display_public_key"], proposal["proposal_id"], "YES")
    network.cast_proposal_vote(low_ratio_voter["display_public_key"], proposal["proposal_id"], "NO")

    finalized = network.finalize_proposal(author["display_public_key"], proposal["proposal_id"])
    assert finalized["status"] == "APPROVED"
    assert finalized["yes_count"] == 1
    assert finalized["no_count"] == 1
    assert finalized["weighted_yes"] > finalized["weighted_no"]
    assert finalized["votes"][network.normalize_public_key(high_ratio_voter["display_public_key"])]["vote_weight"] > 1.0
    assert finalized["votes"][network.normalize_public_key(low_ratio_voter["display_public_key"])]["vote_weight"] == 0.1

    high_summary = network.get_user_summary(high_ratio_voter["display_public_key"])
    low_summary = network.get_user_summary(low_ratio_voter["display_public_key"])
    assert high_summary["voting_power"] > low_summary["voting_power"]


def test_site_release_pinning_and_health_with_governance():
    network = ArchiveTeamNetwork()
    owner_keys, owner = _new_user(network, "owner", "US")
    node1_keys, node1 = _new_user(network, "node1", "US")
    node2_keys, node2 = _new_user(network, "node2", "US")
    node3_keys, node3 = _new_user(network, "node3", "US")

    # mark nodes online so health can count them
    network.set_node_online(node1["display_public_key"])
    network.set_node_online(node2["display_public_key"])
    network.set_node_online(node3["display_public_key"])

    proposal = network.create_proposal(
        author_public_key=owner["display_public_key"],
        title="Release site v1",
        description="Publish canonical frontend CID",
        change_type="SITE_RELEASE",
        target="bafybeigdyrztw4b4k6z6l5y5vci4c3p6k2wrg7u2v5uqf5h3i3b7v5r5pu",
        proposed_patch='{"cid":"bafybeigdyrztw4b4k6z6l5y5vci4c3p6k2wrg7u2v5uqf5h3i3b7v5r5pu","version":"1.0.0","notes":"Initial IPFS release"}',
        quorum=2,
        yes_threshold=0.5,
    )
    network.cast_proposal_vote(node1["display_public_key"], proposal["proposal_id"], "YES")
    network.cast_proposal_vote(node2["display_public_key"], proposal["proposal_id"], "YES")
    finalized = network.finalize_proposal(owner["display_public_key"], proposal["proposal_id"])
    assert finalized["status"] == "APPROVED"

    site = network.get_site_state()
    assert site["current_cid"] == "bafybeigdyrztw4b4k6z6l5y5vci4c3p6k2wrg7u2v5uqf5h3i3b7v5r5pu"
    assert site["version"] == "1.0.0"
    assert site["proposal_id"] == proposal["proposal_id"]

    # nodes attest they pin the site
    network.attest_site_pin(node1["display_public_key"], pin_provider="local-ipfs")
    network.attest_site_pin(node2["display_public_key"], pin_provider="local-ipfs")
    network.attest_site_pin(node3["display_public_key"], pin_provider="pinning-service")

    pinners = network.list_site_pinners()
    assert len(pinners) == 3
    assert all(row["cid"] == site["current_cid"] for row in pinners)

    health = network.get_site_health(min_online_pinners=3)
    assert health["healthy"] is True
    assert health["online_pinners"] == 3


def test_request_profiles_modes_worker_controls_and_policy_flags():
    network = ArchiveTeamNetwork()
    keypair, user = _new_user(network, "media-user", "US")
    node = ArchiveTeamNode(network, keypair["private_key"], keypair["public_key"])
    node.heartbeat("US")

    media_request = node.submit_request(
        url="https://youtube.com/watch?v=abc",
        archive_mode=ArchiveMode.MEDIA_YTDLP.value,
        download_profile="media_fast",
        profile_options={"audio_only": "false", "video_quality": "720p"},
        worker_controls={"max_retries": "4", "sleep_interval_seconds": 3},
    )
    assert media_request["archive_mode"] == ArchiveMode.MEDIA_YTDLP.value
    assert media_request["download_profile"] == "media_fast"
    assert media_request["profile_options"]["audio_only"] is False
    assert media_request["profile_options"]["video_quality"] == "720p"
    assert media_request["worker_controls"]["max_retries"] == 4
    assert media_request["worker_controls"]["sleep_interval_seconds"] == 3

    gallery_request = node.submit_request(
        url="https://instagram.com/p/test",
        archive_mode=ArchiveMode.GALLERY_DL.value,
        download_profile="gallery_deep",
        profile_options={"gallery_max_items": 200},
    )
    assert gallery_request["archive_mode"] == ArchiveMode.GALLERY_DL.value
    assert gallery_request["profile_options"]["gallery_max_items"] == 200

    auth_request = node.submit_request(
        url="https://www.coursera.org/learn/crypto",
        archive_mode=ArchiveMode.FULL_WARC.value,
        download_profile="forensic",
    )
    assert "auth_gated_source" in auth_request["policy_flags"]

    with pytest.raises(ArchiveTeamError):
        node.submit_request(
            url="https://youtube.com/watch?v=abc",
            archive_mode=ArchiveMode.MEDIA_YTDLP.value,
            download_profile="forensic",
        )

    with pytest.raises(ArchiveTeamError):
        node.submit_request(
            url="https://youtube.com/watch?v=abc",
            archive_mode=ArchiveMode.MEDIA_YTDLP.value,
            download_profile="media_fast",
            worker_controls={"max_retries": "abc"},
        )

    with pytest.raises(ArchiveTeamError):
        node.submit_request(
            url="https://youtube.com/watch?v=abc",
            archive_mode=ArchiveMode.GALLERY_DL.value,
            download_profile="gallery_deep",
            profile_options={"audio_only": True},
        )


def test_drm_hosts_are_blocked_by_content_policy():
    network = ArchiveTeamNetwork()
    keypair, user = _new_user(network, "policy-user", "US")
    with pytest.raises(ArchiveTeamError):
        network.submit_request(
            requester_public_key=user["display_public_key"],
            url="https://www.netflix.com/title/1234",
            archive_mode=ArchiveMode.MEDIA_YTDLP.value,
        )


def test_worker_serving_rules_and_capacity_are_enforced():
    network = ArchiveTeamNetwork()
    requester_keys, requester = _new_user(network, "requester", "US")
    high_keys, high_ratio_requester = _new_user(network, "trusted", "US")
    worker_keys, worker = _new_user(network, "worker", "US")

    requester_node = ArchiveTeamNode(network, requester_keys["private_key"], requester_keys["public_key"])
    high_node = ArchiveTeamNode(network, high_keys["private_key"], high_keys["public_key"])
    worker_node = ArchiveTeamNode(network, worker_keys["private_key"], worker_keys["public_key"])

    requester_node.heartbeat("US")
    high_node.heartbeat("US")
    worker_node.heartbeat("US")

    # Boost one requester above the ratio threshold to validate filtering logic.
    high_stats = network.users[network.normalize_public_key(high_ratio_requester["display_public_key"])]["stats"]
    high_stats["files_served"] = 3
    high_stats["requests_processed"] = 2
    high_stats["files_requested"] = 1

    rules = network.update_serving_rules(
        public_key=worker["display_public_key"],
        block_porn_links=True,
        min_ratio_to_serve=1.0,
        prioritize_followed_first=True,
        followed_public_keys=[high_ratio_requester["display_public_key"]],
        site_blacklist=["blocked.example"],
        rules_md="deny: banned.example",
    )
    assert rules["block_porn_links"] is True
    assert rules["min_ratio_to_serve"] == 1.0
    assert network.normalize_public_key(high_ratio_requester["display_public_key"]) in rules["followed_public_keys"]

    low_ratio_request = requester_node.submit_request("https://example.com/low", ArchiveMode.FULL_WARC.value)
    porn_request = high_node.submit_request("https://example.com/porn", ArchiveMode.FULL_WARC.value)
    blacklisted_request = high_node.submit_request("https://blocked.example/video", ArchiveMode.FULL_WARC.value)
    rules_md_request = high_node.submit_request("https://banned.example/page", ArchiveMode.FULL_WARC.value)
    eligible_request = high_node.submit_request("https://example.com/eligible", ArchiveMode.FULL_WARC.value)

    candidates = network.get_request_candidates(worker["display_public_key"], limit=10)
    candidate_ids = [candidate["request_id"] for candidate in candidates]
    assert eligible_request["request_id"] in candidate_ids
    assert low_ratio_request["request_id"] not in candidate_ids
    assert porn_request["request_id"] not in candidate_ids
    assert blacklisted_request["request_id"] not in candidate_ids
    assert rules_md_request["request_id"] not in candidate_ids

    settings = network.update_network_settings(
        public_key=worker["display_public_key"],
        max_jobs_per_day=1,
        max_storage_gb_per_day=0.0001,
    )
    assert settings["max_jobs_per_day"] == 1
    assert settings["max_storage_gb_per_day"] == 0.0001

    claimed = network.claim_request(worker["display_public_key"], eligible_request["request_id"])
    assert claimed["request_id"] == eligible_request["request_id"]

    with pytest.raises(ArchiveTeamError):
        network.claim_request(worker["display_public_key"], low_ratio_request["request_id"])

    with pytest.raises(ArchiveTeamError):
        network.fulfill_request(
            worker_public_key=worker["display_public_key"],
            request_id=eligible_request["request_id"],
            content_hash="a" * 64,
            storage_uri="ipfs://example?size_bytes=200000",
        )


def test_speed_limits_apply_as_daily_transfer_budgets():
    network = ArchiveTeamNetwork()
    requester_keys, requester = _new_user(network, "requester", "US")
    worker_keys, worker = _new_user(network, "worker", "US")
    requester_node = ArchiveTeamNode(network, requester_keys["private_key"], requester_keys["public_key"])
    worker_node = ArchiveTeamNode(network, worker_keys["private_key"], worker_keys["public_key"])

    requester_node.heartbeat("US")
    worker_node.heartbeat("US")

    request = requester_node.submit_request("https://example.com/large", ArchiveMode.FULL_WARC.value)
    worker_node.poll_and_claim()
    archive = worker_node.fulfill_claimed_request(
        request_id=request["request_id"],
        archive_bytes=b"archive bytes",
        storage_uri="ipfs://large",
    )
    network.archives[archive["archive_id"]]["estimated_size_bytes"] = 11 * 1024 ** 3

    network.update_network_settings(
        public_key=worker["display_public_key"],
        daily_upload_speed_mbps=1,
    )
    with pytest.raises(ArchiveTeamError):
        network.record_archive_serve(
            server_public_key=worker["display_public_key"],
            requester_public_key=requester["display_public_key"],
            archive_id=archive["archive_id"],
        )
