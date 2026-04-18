from __future__ import annotations

import hashlib
import json
import secrets
from urllib.parse import unquote, urlparse

from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey


class ArchiveTeamError(ValueError):
    """Raised when ArchiveTeam workflow validation fails."""


class ArchiveMode(str, Enum):
    FULL_WARC = "FULL_WARC"
    ZIP_WARC = "ZIP_WARC"


class RatioBand(str, Enum):
    GREEN = "green"
    YELLOW = "yellow"
    RED = "red"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ArchiveTeamNetwork:
    """In-memory + optional JSON-persisted MVP coordinator for ArchiveTeam."""

    KEY_PREFIX = "AT"
    DEFAULT_BLOCKED_URL_TERMS = (
        "csam",
        "child-abuse",
        "illegal-child-content",
        "minor-sex",
    )
    DEFAULT_BLOCKED_HOSTS = ()

    def __init__(
        self,
        storage_path: Optional[str] = None,
        pin_window_hours: int = 24,
        heartbeat_ttl_seconds: int = 90,
        now_fn: Optional[Callable[[], datetime]] = None,
        blocked_url_terms: Optional[List[str]] = None,
        blocked_hosts: Optional[List[str]] = None,
    ) -> None:
        self.storage_path = Path(storage_path) if storage_path else None
        self.pin_window = timedelta(hours=pin_window_hours)
        self.heartbeat_ttl_seconds = heartbeat_ttl_seconds
        self.now_fn = now_fn or utcnow
        self.blocked_url_terms = tuple(
            (term or "").strip().lower()
            for term in (blocked_url_terms or list(self.DEFAULT_BLOCKED_URL_TERMS))
            if (term or "").strip()
        )
        self.blocked_hosts = {
            (host or "").strip().lower()
            for host in (blocked_hosts or list(self.DEFAULT_BLOCKED_HOSTS))
            if (host or "").strip()
        }

        self.users: Dict[str, Dict[str, Any]] = {}
        self.requests: Dict[str, Dict[str, Any]] = {}
        self.archives: Dict[str, Dict[str, Any]] = {}
        self.collections: Dict[str, Dict[str, Any]] = {}
        self.collection_submissions: Dict[str, Dict[str, Any]] = {}
        self.proposals: Dict[str, Dict[str, Any]] = {}
        self.ledger: List[Dict[str, Any]] = []
        self.online_nodes: Dict[str, str] = {}
        self.login_challenges: Dict[str, Dict[str, str]] = {}
        self.sessions: Dict[str, Dict[str, str]] = {}

        if self.storage_path and self.storage_path.exists():
            self._load()

    # -------------------------------------------------------------------------
    # Identity & auth
    # -------------------------------------------------------------------------

    @classmethod
    def normalize_public_key(cls, public_key: str) -> str:
        normalized = (public_key or "").strip()
        if normalized.upper().startswith(cls.KEY_PREFIX):
            normalized = normalized[len(cls.KEY_PREFIX):]
        normalized = normalized.lower()
        if not normalized:
            raise ArchiveTeamError("Public key cannot be empty.")
        return normalized

    @classmethod
    def display_public_key(cls, public_key: str) -> str:
        return f"{cls.KEY_PREFIX}{cls.normalize_public_key(public_key)}"

    @staticmethod
    def create_keypair() -> Dict[str, str]:
        signing_key = SigningKey.generate()
        private_key = signing_key.encode().hex()
        public_key = signing_key.verify_key.encode().hex()
        return {
            "private_key": private_key,
            "public_key": public_key,
            "display_public_key": ArchiveTeamNetwork.display_public_key(public_key),
        }

    def register_user(
        self,
        public_key: str,
        username: str,
        country_code: str,
        is_worker: bool = True,
    ) -> Dict[str, Any]:
        canonical_key = self.normalize_public_key(public_key)
        if canonical_key in self.users:
            raise ArchiveTeamError(f"User already exists for key: {canonical_key}")
        if not username.strip():
            raise ArchiveTeamError("Username is required.")
        if not country_code.strip():
            raise ArchiveTeamError("Country code is required.")

        user = {
            "public_key": canonical_key,
            "display_public_key": self.display_public_key(canonical_key),
            "username": username.strip(),
            "country_code": country_code.strip().upper(),
            "is_worker": is_worker,
            "profile": {
                "pfp_url": "",
                "pfp_size": "200x200",
                "bio": "",
                "website_url": "",
            },
            "stats": {
                "requests_made": 0,
                "requests_processed": 0,
                "files_served": 0,
                "files_requested": 0,
                "archives_pinned": 0,
            },
            "created_at": self._now().isoformat(),
        }
        self.users[canonical_key] = user
        self._save()
        return self._clone(user)

    def update_profile(
        self,
        public_key: str,
        pfp_url: str,
        bio: str,
        website_url: str,
    ) -> Dict[str, Any]:
        canonical_key = self.normalize_public_key(public_key)
        user = self._require_user(canonical_key)
        if len(bio) > 500:
            raise ArchiveTeamError("Bio must be 500 characters or less.")
        user["profile"] = {
            "pfp_url": pfp_url.strip(),
            "pfp_size": "200x200",
            "bio": bio,
            "website_url": website_url.strip(),
        }
        self._save()
        return self._clone(user["profile"])

    def issue_login_challenge(self, public_key: str) -> str:
        canonical_key = self.normalize_public_key(public_key)
        self._require_user(canonical_key)

        nonce = secrets.token_hex(16)
        challenge = f"archiveteam-login:{nonce}"
        self.login_challenges[canonical_key] = {
            "challenge": challenge,
            "expires_at": (self._now() + timedelta(minutes=5)).isoformat(),
        }
        self._save()
        return challenge

    def complete_login(self, public_key: str, signature_hex: str) -> str:
        canonical_key = self.normalize_public_key(public_key)
        challenge_record = self.login_challenges.get(canonical_key)
        if not challenge_record:
            raise ArchiveTeamError("No login challenge found for this key.")

        expires_at = datetime.fromisoformat(challenge_record["expires_at"])
        if expires_at < self._now():
            raise ArchiveTeamError("Login challenge has expired.")

        challenge = challenge_record["challenge"]
        verify_key = VerifyKey(bytes.fromhex(canonical_key))
        try:
            verify_key.verify(challenge.encode("utf-8"), bytes.fromhex(signature_hex))
        except (BadSignatureError, ValueError) as exc:
            raise ArchiveTeamError("Invalid signature.") from exc

        token = secrets.token_hex(24)
        self.sessions[token] = {
            "public_key": canonical_key,
            "created_at": self._now().isoformat(),
        }
        del self.login_challenges[canonical_key]
        self._save()
        return token

    # -------------------------------------------------------------------------
    # Node state
    # -------------------------------------------------------------------------

    def set_node_online(self, public_key: str, country_code: Optional[str] = None) -> None:
        canonical_key = self.normalize_public_key(public_key)
        user = self._require_user(canonical_key)
        if country_code:
            user["country_code"] = country_code.strip().upper()
        self.online_nodes[canonical_key] = self._now().isoformat()
        self._save()

    def set_node_offline(self, public_key: str) -> None:
        canonical_key = self.normalize_public_key(public_key)
        self._require_user(canonical_key)
        self.online_nodes.pop(canonical_key, None)
        self._save()

    def is_node_online(self, public_key: str) -> bool:
        canonical_key = self.normalize_public_key(public_key)
        last_seen = self.online_nodes.get(canonical_key)
        if not last_seen:
            return False
        seen_dt = datetime.fromisoformat(last_seen)
        return (self._now() - seen_dt).total_seconds() <= self.heartbeat_ttl_seconds

    # -------------------------------------------------------------------------
    # Request lifecycle
    # -------------------------------------------------------------------------

    def submit_request(
        self,
        requester_public_key: str,
        url: str,
        archive_mode: str = ArchiveMode.FULL_WARC.value,
        country_preference: str = "",
    ) -> Dict[str, Any]:
        requester_key = self.normalize_public_key(requester_public_key)
        requester = self._require_user(requester_key)
        if not requester["is_worker"]:
            raise ArchiveTeamError("Only worker accounts can submit requests.")
        if not url.startswith(("http://", "https://")):
            raise ArchiveTeamError("URL must start with http:// or https://")
        self._assert_url_allowed(url)

        mode = ArchiveMode(archive_mode)
        request_id = secrets.token_hex(12)
        request_record = {
            "request_id": request_id,
            "requester_public_key": requester_key,
            "url": url.strip(),
            "archive_mode": mode.value,
            "country_preference": country_preference.strip().upper(),
            "status": "OPEN",
            "claimed_by": "",
            "archive_id": "",
            "created_at": self._now().isoformat(),
            "fulfilled_at": "",
        }
        self.requests[request_id] = request_record
        requester["stats"]["requests_made"] += 1
        requester["stats"]["files_requested"] += 1
        self._save()
        return self._clone(request_record)

    def list_open_requests(self, worker_public_key: Optional[str] = None) -> List[Dict[str, Any]]:
        worker_country = None
        if worker_public_key:
            worker = self._require_user(self.normalize_public_key(worker_public_key))
            worker_country = worker["country_code"]

        results: List[Dict[str, Any]] = []
        for record in self.requests.values():
            if record["status"] != "OPEN":
                continue
            if worker_country and record["country_preference"] and record["country_preference"] != worker_country:
                continue
            results.append(self._clone(record))
        results.sort(key=lambda req: req["created_at"])
        return results

    def poll_next_request(self, worker_public_key: str) -> Optional[Dict[str, Any]]:
        open_requests = self.list_open_requests(worker_public_key=worker_public_key)
        return open_requests[0] if open_requests else None

    def claim_request(self, worker_public_key: str, request_id: str) -> Dict[str, Any]:
        worker_key = self.normalize_public_key(worker_public_key)
        worker = self._require_user(worker_key)
        request_record = self._require_request(request_id)

        if not self.is_node_online(worker_key):
            raise ArchiveTeamError("Worker must be online to claim a request.")
        if request_record["status"] != "OPEN":
            raise ArchiveTeamError("Request is not open for claiming.")
        if request_record["country_preference"] and request_record["country_preference"] != worker["country_code"]:
            raise ArchiveTeamError("Worker country does not match request preference.")

        request_record["status"] = "CLAIMED"
        request_record["claimed_by"] = worker_key
        self._save()
        return self._clone(request_record)

    def fulfill_request(
        self,
        worker_public_key: str,
        request_id: str,
        content_hash: str,
        storage_uri: str,
    ) -> Dict[str, Any]:
        worker_key = self.normalize_public_key(worker_public_key)
        worker = self._require_user(worker_key)
        request_record = self._require_request(request_id)

        if request_record["status"] != "CLAIMED":
            raise ArchiveTeamError("Request must be claimed before fulfillment.")
        if request_record["claimed_by"] != worker_key:
            raise ArchiveTeamError("Only claiming worker can fulfill the request.")
        if not content_hash.strip():
            raise ArchiveTeamError("Content hash is required.")

        now = self._now()
        pinned_until = now + self.pin_window
        archive_id = hashlib.sha256(f"{request_id}:{content_hash}".encode("utf-8")).hexdigest()[:40]

        archive_record = {
            "archive_id": archive_id,
            "request_id": request_id,
            "source_url": request_record["url"],
            "archive_mode": request_record["archive_mode"],
            "content_hash": content_hash.lower(),
            "storage_uri": storage_uri.strip(),
            "pinned_until": pinned_until.isoformat(),
            "created_at": now.isoformat(),
            "hosts": [
                {
                    "public_key": worker_key,
                    "country_code": worker["country_code"],
                    "available_until": pinned_until.isoformat(),
                }
            ],
            "serve_count": 0,
            "chain_hash": "",
        }
        self.archives[archive_id] = archive_record

        request_record["status"] = "FULFILLED"
        request_record["archive_id"] = archive_id
        request_record["fulfilled_at"] = now.isoformat()

        worker["stats"]["requests_processed"] += 1
        worker["stats"]["archives_pinned"] += 1

        ledger_entry = self._append_ledger_entry(
            {
                "event": "ArchiveFulfilled",
                "request_id": request_id,
                "archive_id": archive_id,
                "worker_public_key": worker_key,
                "content_hash": content_hash.lower(),
                "storage_uri": storage_uri.strip(),
                "expires_at": pinned_until.isoformat(),
            }
        )
        archive_record["chain_hash"] = ledger_entry["tx_hash"]
        self._save()
        return self._clone(archive_record)

    def assume_archive_hosting(self, host_public_key: str, archive_id: str) -> Dict[str, Any]:
        host_key = self.normalize_public_key(host_public_key)
        host = self._require_user(host_key)
        archive = self._require_archive(archive_id)

        host_record = next((h for h in archive["hosts"] if h["public_key"] == host_key), None)
        if host_record:
            host_record["available_until"] = ""
            host_record["country_code"] = host["country_code"]
        else:
            archive["hosts"].append(
                {
                    "public_key": host_key,
                    "country_code": host["country_code"],
                    "available_until": "",
                }
            )
        self._save()
        return self._clone(archive)

    # -------------------------------------------------------------------------
    # Collections
    # -------------------------------------------------------------------------

    def create_collection(
        self,
        owner_public_key: str,
        name: str,
        description: str = "",
        is_private: bool = False,
        allow_submissions: bool = False,
        forked_from: str = "",
    ) -> Dict[str, Any]:
        owner_key = self.normalize_public_key(owner_public_key)
        self._require_user(owner_key)
        self._validate_collection_fields(name=name, description=description)

        collection_id = secrets.token_hex(12)
        collection = {
            "collection_id": collection_id,
            "owner_public_key": owner_key,
            "name": name.strip(),
            "description": description.strip(),
            "is_private": is_private,
            "allow_submissions": allow_submissions,
            "archives": [],
            "forked_from": forked_from.strip(),
            "created_at": self._now().isoformat(),
            "updated_at": self._now().isoformat(),
        }
        self.collections[collection_id] = collection
        self._save()
        return self._clone(collection)

    def get_collection(self, collection_id: str, viewer_public_key: Optional[str] = None) -> Dict[str, Any]:
        collection = self._require_collection(collection_id)
        viewer_key = self.normalize_public_key(viewer_public_key) if viewer_public_key else ""
        self._assert_collection_visible(collection, viewer_key)
        return self._clone(collection)

    def list_collections(
        self,
        viewer_public_key: Optional[str] = None,
        owner_public_key: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        viewer_key = self.normalize_public_key(viewer_public_key) if viewer_public_key else ""
        owner_key = self.normalize_public_key(owner_public_key) if owner_public_key else ""

        results: List[Dict[str, Any]] = []
        for collection in self.collections.values():
            if owner_key and collection["owner_public_key"] != owner_key:
                continue
            if collection["is_private"] and collection["owner_public_key"] != viewer_key:
                continue
            results.append(self._clone(collection))
        results.sort(key=lambda row: row["created_at"], reverse=True)
        return results

    def update_collection(
        self,
        owner_public_key: str,
        collection_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        is_private: Optional[bool] = None,
        allow_submissions: Optional[bool] = None,
    ) -> Dict[str, Any]:
        owner_key = self.normalize_public_key(owner_public_key)
        collection = self._require_collection(collection_id)
        self._assert_collection_owner(collection, owner_key)

        next_name = collection["name"] if name is None else name
        next_description = collection["description"] if description is None else description
        self._validate_collection_fields(name=next_name, description=next_description)

        if name is not None:
            collection["name"] = name.strip()
        if description is not None:
            collection["description"] = description.strip()
        if is_private is not None:
            collection["is_private"] = is_private
        if allow_submissions is not None:
            collection["allow_submissions"] = allow_submissions

        collection["updated_at"] = self._now().isoformat()
        self._save()
        return self._clone(collection)

    def delete_collection(self, owner_public_key: str, collection_id: str) -> None:
        owner_key = self.normalize_public_key(owner_public_key)
        collection = self._require_collection(collection_id)
        self._assert_collection_owner(collection, owner_key)

        submission_ids = [
            submission_id
            for submission_id, submission in self.collection_submissions.items()
            if submission["collection_id"] == collection_id
        ]
        for submission_id in submission_ids:
            del self.collection_submissions[submission_id]
        del self.collections[collection_id]
        self._save()

    def add_archive_to_collection(
        self,
        owner_public_key: str,
        collection_id: str,
        archive_id: str,
    ) -> Dict[str, Any]:
        owner_key = self.normalize_public_key(owner_public_key)
        collection = self._require_collection(collection_id)
        self._assert_collection_owner(collection, owner_key)
        self._require_archive(archive_id)

        if archive_id not in collection["archives"]:
            collection["archives"].append(archive_id)
            collection["updated_at"] = self._now().isoformat()
            self._save()
        return self._clone(collection)

    def fork_collection(
        self,
        forker_public_key: str,
        source_collection_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
    ) -> Dict[str, Any]:
        forker_key = self.normalize_public_key(forker_public_key)
        self._require_user(forker_key)
        source = self._require_collection(source_collection_id)
        self._assert_collection_visible(source, forker_key)

        clone_name = name or f"Fork of {source['name']}"
        clone_description = description if description is not None else source["description"]
        fork = self.create_collection(
            owner_public_key=forker_key,
            name=clone_name,
            description=clone_description,
            is_private=False,
            allow_submissions=False,
            forked_from=source_collection_id,
        )
        # Keep archives in insertion order.
        self.collections[fork["collection_id"]]["archives"] = list(source["archives"])
        self.collections[fork["collection_id"]]["updated_at"] = self._now().isoformat()
        self._save()
        return self._clone(self.collections[fork["collection_id"]])

    def submit_collection_entry(
        self,
        submitter_public_key: str,
        collection_id: str,
        archive_id: str,
        note: str = "",
    ) -> Dict[str, Any]:
        submitter_key = self.normalize_public_key(submitter_public_key)
        self._require_user(submitter_key)
        collection = self._require_collection(collection_id)
        self._require_archive(archive_id)

        if collection["owner_public_key"] == submitter_key:
            return self.add_archive_to_collection(
                owner_public_key=submitter_key,
                collection_id=collection_id,
                archive_id=archive_id,
            )

        if collection["is_private"]:
            raise ArchiveTeamError("Cannot submit to a private collection.")
        if not collection["allow_submissions"]:
            raise ArchiveTeamError("Collection owner has disabled submissions.")

        submission_id = secrets.token_hex(12)
        submission = {
            "submission_id": submission_id,
            "collection_id": collection_id,
            "archive_id": archive_id,
            "submitter_public_key": submitter_key,
            "note": note.strip(),
            "status": "PENDING",
            "reviewed_at": "",
            "reviewed_by": "",
            "created_at": self._now().isoformat(),
        }
        self.collection_submissions[submission_id] = submission
        self._save()
        return self._clone(submission)

    def review_collection_submission(
        self,
        owner_public_key: str,
        submission_id: str,
        approve: bool,
    ) -> Dict[str, Any]:
        owner_key = self.normalize_public_key(owner_public_key)
        submission = self._require_collection_submission(submission_id)
        collection = self._require_collection(submission["collection_id"])
        self._assert_collection_owner(collection, owner_key)

        if submission["status"] != "PENDING":
            raise ArchiveTeamError("Submission has already been reviewed.")

        submission["status"] = "APPROVED" if approve else "DENIED"
        submission["reviewed_by"] = owner_key
        submission["reviewed_at"] = self._now().isoformat()

        if approve and submission["archive_id"] not in collection["archives"]:
            collection["archives"].append(submission["archive_id"])
            collection["updated_at"] = self._now().isoformat()

        self._save()
        return self._clone(submission)

    # -------------------------------------------------------------------------
    # Governance proposals (GitHub-like change + voting flow)
    # -------------------------------------------------------------------------

    def create_proposal(
        self,
        author_public_key: str,
        title: str,
        description: str,
        change_type: str,
        target: str = "",
        proposed_patch: str = "",
        quorum: int = 3,
        yes_threshold: float = 0.6,
    ) -> Dict[str, Any]:
        author_key = self.normalize_public_key(author_public_key)
        self._require_user(author_key)

        if not (title or "").strip():
            raise ArchiveTeamError("Proposal title is required.")
        if len((title or "").strip()) > 160:
            raise ArchiveTeamError("Proposal title must be 160 characters or less.")
        if len(description or "") > 8000:
            raise ArchiveTeamError("Proposal description must be 8000 characters or less.")
        if quorum < 1:
            raise ArchiveTeamError("Proposal quorum must be at least 1.")
        if not (0.0 < yes_threshold <= 1.0):
            raise ArchiveTeamError("yes_threshold must be greater than 0 and less than or equal to 1.")

        proposal_id = secrets.token_hex(12)
        proposal = {
            "proposal_id": proposal_id,
            "author_public_key": author_key,
            "title": title.strip(),
            "description": description.strip(),
            "change_type": (change_type or "").strip(),
            "target": (target or "").strip(),
            "proposed_patch": proposed_patch or "",
            "status": "OPEN",
            "quorum": int(quorum),
            "yes_threshold": float(yes_threshold),
            "votes": {},
            "yes_count": 0,
            "no_count": 0,
            "abstain_count": 0,
            "finalized_at": "",
            "finalized_by": "",
            "result": "",
            "created_at": self._now().isoformat(),
            "updated_at": self._now().isoformat(),
        }
        self.proposals[proposal_id] = proposal
        self._append_ledger_entry(
            {
                "event": "ProposalCreated",
                "proposal_id": proposal_id,
                "author_public_key": author_key,
                "change_type": proposal["change_type"],
                "target": proposal["target"],
            }
        )
        self._save()
        return self._clone(proposal)

    def list_proposals(
        self,
        status: str = "",
        author_public_key: str = "",
    ) -> List[Dict[str, Any]]:
        author_key = self.normalize_public_key(author_public_key) if author_public_key else ""
        wanted_status = (status or "").strip().upper()
        if wanted_status and wanted_status not in {"OPEN", "APPROVED", "REJECTED", "CLOSED"}:
            raise ArchiveTeamError("Invalid proposal status filter.")

        rows: List[Dict[str, Any]] = []
        for proposal in self.proposals.values():
            if wanted_status and proposal["status"] != wanted_status:
                continue
            if author_key and proposal["author_public_key"] != author_key:
                continue
            rows.append(self._clone(proposal))
        rows.sort(key=lambda row: row["created_at"], reverse=True)
        return rows

    def get_proposal(self, proposal_id: str) -> Dict[str, Any]:
        return self._clone(self._require_proposal(proposal_id))

    def cast_proposal_vote(
        self,
        voter_public_key: str,
        proposal_id: str,
        vote: str,
        note: str = "",
    ) -> Dict[str, Any]:
        voter_key = self.normalize_public_key(voter_public_key)
        self._require_user(voter_key)
        proposal = self._require_proposal(proposal_id)
        if proposal["status"] != "OPEN":
            raise ArchiveTeamError("Votes can only be cast while proposal is OPEN.")

        vote_value = (vote or "").strip().upper()
        if vote_value not in {"YES", "NO", "ABSTAIN"}:
            raise ArchiveTeamError("Vote must be YES, NO, or ABSTAIN.")

        proposal["votes"][voter_key] = {
            "vote": vote_value,
            "note": (note or "").strip(),
            "voted_at": self._now().isoformat(),
        }
        self._recount_proposal_votes(proposal)
        self._append_ledger_entry(
            {
                "event": "ProposalVoteCast",
                "proposal_id": proposal_id,
                "voter_public_key": voter_key,
                "vote": vote_value,
            }
        )
        self._save()
        return self._clone(proposal)

    def finalize_proposal(self, actor_public_key: str, proposal_id: str) -> Dict[str, Any]:
        actor_key = self.normalize_public_key(actor_public_key)
        self._require_user(actor_key)
        proposal = self._require_proposal(proposal_id)
        if proposal["status"] != "OPEN":
            raise ArchiveTeamError("Only OPEN proposals can be finalized.")

        self._recount_proposal_votes(proposal)
        total_votes = proposal["yes_count"] + proposal["no_count"] + proposal["abstain_count"]
        decisive_votes = proposal["yes_count"] + proposal["no_count"]
        yes_ratio = (proposal["yes_count"] / decisive_votes) if decisive_votes else 0.0

        if total_votes < proposal["quorum"]:
            result = "REJECTED"
            reason = "QUORUM_NOT_MET"
        elif yes_ratio >= proposal["yes_threshold"]:
            result = "APPROVED"
            reason = "THRESHOLD_MET"
        else:
            result = "REJECTED"
            reason = "THRESHOLD_NOT_MET"

        proposal["status"] = result
        proposal["result"] = reason
        proposal["finalized_by"] = actor_key
        proposal["finalized_at"] = self._now().isoformat()
        proposal["updated_at"] = self._now().isoformat()

        self._append_ledger_entry(
            {
                "event": "ProposalFinalized",
                "proposal_id": proposal_id,
                "status": result,
                "result": reason,
                "yes_count": proposal["yes_count"],
                "no_count": proposal["no_count"],
                "abstain_count": proposal["abstain_count"],
                "finalized_by": actor_key,
            }
        )
        self._save()
        return self._clone(proposal)

    def close_proposal(self, actor_public_key: str, proposal_id: str) -> Dict[str, Any]:
        actor_key = self.normalize_public_key(actor_public_key)
        self._require_user(actor_key)
        proposal = self._require_proposal(proposal_id)
        if proposal["status"] != "OPEN":
            raise ArchiveTeamError("Only OPEN proposals can be closed.")
        if proposal["author_public_key"] != actor_key:
            raise ArchiveTeamError("Only the proposal author can close it while OPEN.")

        proposal["status"] = "CLOSED"
        proposal["result"] = "AUTHOR_CLOSED"
        proposal["finalized_by"] = actor_key
        proposal["finalized_at"] = self._now().isoformat()
        proposal["updated_at"] = self._now().isoformat()
        self._append_ledger_entry(
            {
                "event": "ProposalClosed",
                "proposal_id": proposal_id,
                "closed_by": actor_key,
            }
        )
        self._save()
        return self._clone(proposal)

    def record_archive_serve(
        self,
        server_public_key: str,
        requester_public_key: str,
        archive_id: str,
    ) -> Dict[str, Any]:
        server_key = self.normalize_public_key(server_public_key)
        requester_key = self.normalize_public_key(requester_public_key)
        server = self._require_user(server_key)
        requester = self._require_user(requester_key)
        archive = self._require_archive(archive_id)

        serving_hosts = {host["public_key"] for host in self._active_hosts(archive)}
        if server_key not in serving_hosts:
            raise ArchiveTeamError("Server is not currently available for this archive.")

        server["stats"]["files_served"] += 1
        requester["stats"]["files_requested"] += 1
        archive["serve_count"] += 1

        self._append_ledger_entry(
            {
                "event": "ArchiveServed",
                "archive_id": archive_id,
                "server_public_key": server_key,
                "requester_public_key": requester_key,
                "served_at": self._now().isoformat(),
            }
        )
        self._save()
        return self._clone(archive)

    # -------------------------------------------------------------------------
    # Search + scoring
    # -------------------------------------------------------------------------

    def search_available_archives(self, query: str = "") -> List[Dict[str, Any]]:
        lowered = query.strip().lower()
        results: List[Dict[str, Any]] = []

        for archive in self.archives.values():
            if lowered and lowered not in archive["source_url"].lower() and lowered not in archive["content_hash"]:
                continue
            active_hosts = self._active_hosts(archive)
            if not active_hosts:
                continue

            result = self._clone(archive)
            result["active_hosts"] = active_hosts
            results.append(result)

        results.sort(key=lambda item: item["created_at"], reverse=True)
        return results

    def get_ratio(self, public_key: str) -> Tuple[float, RatioBand]:
        canonical_key = self.normalize_public_key(public_key)
        user = self._require_user(canonical_key)
        stats = user["stats"]
        ratio = (stats["files_served"] + stats["requests_processed"]) / max(stats["files_requested"], 1)
        if ratio >= 1.0:
            band = RatioBand.GREEN
        elif ratio >= 0.7:
            band = RatioBand.YELLOW
        else:
            band = RatioBand.RED
        return ratio, band

    def get_user_summary(self, public_key: str) -> Dict[str, Any]:
        canonical_key = self.normalize_public_key(public_key)
        user = self._clone(self._require_user(canonical_key))
        ratio, band = self.get_ratio(canonical_key)
        user["ratio_score"] = round(ratio, 3)
        user["ratio_band"] = band.value
        user["online"] = self.is_node_online(canonical_key)
        return user

    # -------------------------------------------------------------------------
    # Persistence helpers
    # -------------------------------------------------------------------------

    def _save(self) -> None:
        if not self.storage_path:
            return
        payload = {
            "users": self.users,
            "requests": self.requests,
            "archives": self.archives,
            "collections": self.collections,
            "collection_submissions": self.collection_submissions,
            "proposals": self.proposals,
            "ledger": self.ledger,
            "online_nodes": self.online_nodes,
            "login_challenges": self.login_challenges,
            "sessions": self.sessions,
        }
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        self.storage_path.write_text(json.dumps(payload, sort_keys=True, indent=2), encoding="utf-8")

    def _load(self) -> None:
        raw = json.loads(self.storage_path.read_text(encoding="utf-8"))
        self.users = raw.get("users", {})
        self.requests = raw.get("requests", {})
        self.archives = raw.get("archives", {})
        self.collections = raw.get("collections", {})
        self.collection_submissions = raw.get("collection_submissions", {})
        self.proposals = raw.get("proposals", {})
        self.ledger = raw.get("ledger", [])
        self.online_nodes = raw.get("online_nodes", {})
        self.login_challenges = raw.get("login_challenges", {})
        self.sessions = raw.get("sessions", {})

    def _append_ledger_entry(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        previous_hash = self.ledger[-1]["tx_hash"] if self.ledger else "GENESIS"
        entry_string = json.dumps(payload, sort_keys=True)
        tx_hash = hashlib.sha256(f"{previous_hash}:{entry_string}".encode("utf-8")).hexdigest()
        entry = {
            "tx_hash": tx_hash,
            "previous_hash": previous_hash,
            "payload": payload,
            "created_at": self._now().isoformat(),
        }
        self.ledger.append(entry)
        return entry

    def _active_hosts(self, archive: Dict[str, Any]) -> List[Dict[str, Any]]:
        now = self._now()
        active_hosts: List[Dict[str, Any]] = []
        for host in archive["hosts"]:
            until = host.get("available_until") or ""
            if until and datetime.fromisoformat(until) <= now:
                continue
            if not self.is_node_online(host["public_key"]):
                continue
            active_hosts.append(self._clone(host))
        return active_hosts

    def _now(self) -> datetime:
        now = self.now_fn()
        if now.tzinfo is None:
            return now.replace(tzinfo=timezone.utc)
        return now

    @staticmethod
    def _clone(data: Dict[str, Any]) -> Dict[str, Any]:
        return json.loads(json.dumps(data))

    def _require_user(self, public_key: str) -> Dict[str, Any]:
        user = self.users.get(public_key)
        if not user:
            raise ArchiveTeamError(f"Unknown user: {public_key}")
        return user

    def _require_request(self, request_id: str) -> Dict[str, Any]:
        request_record = self.requests.get(request_id)
        if not request_record:
            raise ArchiveTeamError(f"Unknown request: {request_id}")
        return request_record

    def _require_archive(self, archive_id: str) -> Dict[str, Any]:
        archive = self.archives.get(archive_id)
        if not archive:
            raise ArchiveTeamError(f"Unknown archive: {archive_id}")
        return archive

    def _require_collection(self, collection_id: str) -> Dict[str, Any]:
        collection = self.collections.get(collection_id)
        if not collection:
            raise ArchiveTeamError(f"Unknown collection: {collection_id}")
        return collection

    def _require_collection_submission(self, submission_id: str) -> Dict[str, Any]:
        submission = self.collection_submissions.get(submission_id)
        if not submission:
            raise ArchiveTeamError(f"Unknown collection submission: {submission_id}")
        return submission

    def _require_proposal(self, proposal_id: str) -> Dict[str, Any]:
        proposal = self.proposals.get(proposal_id)
        if not proposal:
            raise ArchiveTeamError(f"Unknown proposal: {proposal_id}")
        return proposal

    def _recount_proposal_votes(self, proposal: Dict[str, Any]) -> None:
        yes_count = 0
        no_count = 0
        abstain_count = 0
        for vote_row in proposal["votes"].values():
            vote = vote_row["vote"]
            if vote == "YES":
                yes_count += 1
            elif vote == "NO":
                no_count += 1
            elif vote == "ABSTAIN":
                abstain_count += 1
        proposal["yes_count"] = yes_count
        proposal["no_count"] = no_count
        proposal["abstain_count"] = abstain_count
        proposal["updated_at"] = self._now().isoformat()

    def _validate_collection_fields(self, name: str, description: str) -> None:
        if not (name or "").strip():
            raise ArchiveTeamError("Collection name is required.")
        if len((name or "").strip()) > 120:
            raise ArchiveTeamError("Collection name must be 120 characters or less.")
        if len(description or "") > 5000:
            raise ArchiveTeamError("Collection description must be 5000 characters or less.")

    def _assert_collection_owner(self, collection: Dict[str, Any], public_key: str) -> None:
        if collection["owner_public_key"] != public_key:
            raise ArchiveTeamError("Only the collection owner can perform this action.")

    def _assert_collection_visible(self, collection: Dict[str, Any], viewer_public_key: str) -> None:
        if collection["is_private"] and collection["owner_public_key"] != viewer_public_key:
            raise ArchiveTeamError("Collection is private.")

    def _assert_url_allowed(self, url: str) -> None:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        decoded_url = unquote(url).lower()

        if host and host in self.blocked_hosts:
            raise ArchiveTeamError("URL host is blocked by safety policy.")

        for term in self.blocked_url_terms:
            if term in decoded_url:
                raise ArchiveTeamError("URL blocked by safety policy.")
