from __future__ import annotations

import hashlib
import json
import secrets
import re
from urllib.parse import parse_qs, unquote, urlparse

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
    MEDIA_YTDLP = "MEDIA_YTDLP"
    GALLERY_DL = "GALLERY_DL"


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
    DEFAULT_PORN_KEYWORDS = (
        "porn",
        "xxx",
        "adult",
        "nsfw",
        "sexcam",
        "redtube",
        "xvideos",
        "pornhub",
        "onlyfans",
    )
    DEFAULT_RESTRICTED_DRM_HOSTS = (
        "netflix.com",
        "primevideo.com",
        "disneyplus.com",
        "hulu.com",
        "max.com",
        "hbomax.com",
        "tv.apple.com",
        "paramountplus.com",
        "peacocktv.com",
    )
    DEFAULT_AUTH_GATED_HOSTS = (
        "coursera.org",
        "edx.org",
        "udemy.com",
    )
    DEFAULT_WORKER_CONTROLS = {
        "max_retries": 3,
        "retry_backoff_seconds": 30,
        "sleep_interval_seconds": 0,
        "max_concurrent_downloads": 2,
    }
    DEFAULT_NETWORK_SETTINGS = {
        "max_jobs_per_day": 0,
        "max_storage_gb_per_day": 0.0,
        "max_upload_gb_per_day": 0.0,
        "max_download_gb_per_day": 0.0,
        "daily_upload_speed_mbps": 0,
        "daily_download_speed_mbps": 0,
    }
    DEFAULT_SERVING_RULES = {
        "block_porn_links": False,
        "min_ratio_to_serve": 0.0,
        "prioritize_high_ratio_first": True,
        "prioritize_followed_first": False,
        "followed_public_keys": [],
        "site_blacklist": [],
        "rules_md": "",
    }
    MAX_VOTE_WEIGHT = 20.0
    DOWNLOAD_PROFILES = {
        "balanced": {
            "allowed_modes": [
                ArchiveMode.FULL_WARC.value,
                ArchiveMode.ZIP_WARC.value,
                ArchiveMode.MEDIA_YTDLP.value,
                ArchiveMode.GALLERY_DL.value,
            ],
            "defaults": {
                "video_quality": "best",
                "audio_only": False,
                "include_subtitles": False,
                "include_thumbnail": True,
                "playlist": False,
                "format": "",
                "gallery_max_items": 0,
                "cookies_from_browser": "",
            },
        },
        "forensic": {
            "allowed_modes": [
                ArchiveMode.FULL_WARC.value,
                ArchiveMode.ZIP_WARC.value,
            ],
            "defaults": {
                "video_quality": "best",
                "audio_only": False,
                "include_subtitles": True,
                "include_thumbnail": True,
                "playlist": False,
                "format": "",
                "gallery_max_items": 0,
                "cookies_from_browser": "",
            },
        },
        "media_fast": {
            "allowed_modes": [ArchiveMode.MEDIA_YTDLP.value],
            "defaults": {
                "video_quality": "1080p",
                "audio_only": False,
                "include_subtitles": False,
                "include_thumbnail": True,
                "playlist": False,
                "format": "mp4",
                "gallery_max_items": 0,
                "cookies_from_browser": "",
            },
        },
        "audio_only": {
            "allowed_modes": [ArchiveMode.MEDIA_YTDLP.value],
            "defaults": {
                "video_quality": "best",
                "audio_only": True,
                "include_subtitles": False,
                "include_thumbnail": False,
                "playlist": False,
                "format": "mp3",
                "gallery_max_items": 0,
                "cookies_from_browser": "",
            },
        },
        "gallery_deep": {
            "allowed_modes": [ArchiveMode.GALLERY_DL.value],
            "defaults": {
                "video_quality": "best",
                "audio_only": False,
                "include_subtitles": False,
                "include_thumbnail": False,
                "playlist": True,
                "format": "",
                "gallery_max_items": 500,
                "cookies_from_browser": "",
            },
        },
    }
    ALLOWED_VIDEO_QUALITIES = {"best", "high", "medium", "low", "2160p", "1440p", "1080p", "720p", "480p", "360p"}
    ALLOWED_MEDIA_FORMATS = {"", "mp4", "mkv", "webm", "mp3", "m4a", "opus", "wav", "flac"}
    ALLOWED_COOKIE_BROWSERS = {"", "firefox", "chrome", "safari", "edge", "chromium", "brave", "opera", "vivaldi"}
    DEFAULT_SITE_STATE = {
        "current_cid": "",
        "version": "",
        "notes": "",
        "updated_at": "",
        "updated_by": "",
        "proposal_id": "",
    }

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
        self.site: Dict[str, Any] = self._clone(self.DEFAULT_SITE_STATE)
        self.site_pin_attestations: Dict[str, Dict[str, Any]] = {}
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
                "served_bytes_total": 0,
                "downloaded_bytes_total": 0,
                "stored_bytes_total": 0,
            },
            "network_settings": self._clone(self.DEFAULT_NETWORK_SETTINGS),
            "serving_rules": self._clone(self.DEFAULT_SERVING_RULES),
            "daily_usage": {
                "date": self._now().date().isoformat(),
                "jobs_claimed": 0,
                "storage_bytes_added": 0,
                "upload_bytes_served": 0,
                "download_bytes_received": 0,
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

    def get_network_settings(self, public_key: str) -> Dict[str, Any]:
        canonical_key = self.normalize_public_key(public_key)
        user = self._require_user(canonical_key)
        settings = self._normalize_network_settings(user.get("network_settings", {}))
        user["network_settings"] = self._clone(settings)
        self._save()
        return self._clone(settings)

    def update_network_settings(
        self,
        public_key: str,
        max_jobs_per_day: Optional[int] = None,
        max_storage_gb_per_day: Optional[float] = None,
        max_upload_gb_per_day: Optional[float] = None,
        max_download_gb_per_day: Optional[float] = None,
        daily_upload_speed_mbps: Optional[int] = None,
        daily_download_speed_mbps: Optional[int] = None,
    ) -> Dict[str, Any]:
        canonical_key = self.normalize_public_key(public_key)
        user = self._require_user(canonical_key)
        settings = self._clone(user.get("network_settings", self.DEFAULT_NETWORK_SETTINGS))

        if max_jobs_per_day is not None:
            settings["max_jobs_per_day"] = self._parse_int(max_jobs_per_day, "network_settings.max_jobs_per_day")
        if max_storage_gb_per_day is not None:
            settings["max_storage_gb_per_day"] = self._parse_float(max_storage_gb_per_day, "network_settings.max_storage_gb_per_day")
        if max_upload_gb_per_day is not None:
            settings["max_upload_gb_per_day"] = self._parse_float(max_upload_gb_per_day, "network_settings.max_upload_gb_per_day")
        if max_download_gb_per_day is not None:
            settings["max_download_gb_per_day"] = self._parse_float(max_download_gb_per_day, "network_settings.max_download_gb_per_day")
        if daily_upload_speed_mbps is not None:
            settings["daily_upload_speed_mbps"] = self._parse_int(daily_upload_speed_mbps, "network_settings.daily_upload_speed_mbps")
        if daily_download_speed_mbps is not None:
            settings["daily_download_speed_mbps"] = self._parse_int(daily_download_speed_mbps, "network_settings.daily_download_speed_mbps")

        normalized = self._normalize_network_settings(settings)
        user["network_settings"] = normalized
        self._save()
        return self._clone(normalized)

    def get_serving_rules(self, public_key: str) -> Dict[str, Any]:
        canonical_key = self.normalize_public_key(public_key)
        user = self._require_user(canonical_key)
        rules = self._normalize_serving_rules(user.get("serving_rules", {}))
        user["serving_rules"] = self._clone(rules)
        self._save()
        return self._clone(rules)

    def update_serving_rules(
        self,
        public_key: str,
        block_porn_links: Optional[bool] = None,
        min_ratio_to_serve: Optional[float] = None,
        prioritize_high_ratio_first: Optional[bool] = None,
        prioritize_followed_first: Optional[bool] = None,
        followed_public_keys: Optional[List[str]] = None,
        site_blacklist: Optional[List[str]] = None,
        rules_md: Optional[str] = None,
    ) -> Dict[str, Any]:
        canonical_key = self.normalize_public_key(public_key)
        user = self._require_user(canonical_key)
        rules = self._clone(user.get("serving_rules", self.DEFAULT_SERVING_RULES))

        if block_porn_links is not None:
            rules["block_porn_links"] = self._parse_bool(block_porn_links, "serving_rules.block_porn_links")
        if min_ratio_to_serve is not None:
            rules["min_ratio_to_serve"] = self._parse_float(min_ratio_to_serve, "serving_rules.min_ratio_to_serve")
        if prioritize_high_ratio_first is not None:
            rules["prioritize_high_ratio_first"] = self._parse_bool(
                prioritize_high_ratio_first,
                "serving_rules.prioritize_high_ratio_first",
            )
        if prioritize_followed_first is not None:
            rules["prioritize_followed_first"] = self._parse_bool(
                prioritize_followed_first,
                "serving_rules.prioritize_followed_first",
            )
        if followed_public_keys is not None:
            rules["followed_public_keys"] = followed_public_keys
        if site_blacklist is not None:
            rules["site_blacklist"] = site_blacklist
        if rules_md is not None:
            rules["rules_md"] = str(rules_md)

        normalized = self._normalize_serving_rules(rules)
        user["serving_rules"] = normalized
        self._save()
        return self._clone(normalized)

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
        download_profile: str = "",
        profile_options: Optional[Dict[str, Any]] = None,
        worker_controls: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        requester_key = self.normalize_public_key(requester_public_key)
        requester = self._require_user(requester_key)
        requester["serving_rules"] = self._normalize_serving_rules(requester.get("serving_rules", {}))
        self._reset_daily_usage_if_needed(requester)
        if not requester["is_worker"]:
            raise ArchiveTeamError("Only worker accounts can submit requests.")
        if not url.startswith(("http://", "https://")):
            raise ArchiveTeamError("URL must start with http:// or https://")
        self._assert_url_allowed(url, rules=requester["serving_rules"])

        mode = ArchiveMode(archive_mode)
        normalized_profile = self._normalize_download_profile(mode, download_profile)
        normalized_profile_options = self._normalize_profile_options(
            mode=mode,
            download_profile=normalized_profile,
            profile_options=profile_options or {},
        )
        normalized_worker_controls = self._normalize_worker_controls(worker_controls or {})
        policy_flags = self._build_policy_flags(url)
        request_id = secrets.token_hex(12)
        request_record = {
            "request_id": request_id,
            "requester_public_key": requester_key,
            "url": url.strip(),
            "archive_mode": mode.value,
            "download_profile": normalized_profile,
            "profile_options": normalized_profile_options,
            "worker_controls": normalized_worker_controls,
            "policy_flags": policy_flags,
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

    def get_request_candidates(
        self,
        worker_public_key: str,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        worker_key = self.normalize_public_key(worker_public_key)
        worker = self._require_user(worker_key)
        worker["serving_rules"] = self._normalize_serving_rules(worker.get("serving_rules", {}))
        worker["network_settings"] = self._normalize_network_settings(worker.get("network_settings", {}))
        self._reset_daily_usage_if_needed(worker)

        candidates: List[Dict[str, Any]] = []
        for record in self.list_open_requests(worker_public_key=worker_key):
            allowed, reason = self._request_allowed_by_rules(worker_key, record, worker["serving_rules"])
            if not allowed:
                continue
            ok, cap_reason = self._worker_has_capacity_for_request(worker, record)
            if not ok:
                continue
            candidate = self._clone(record)
            requester_ratio, _ = self.get_ratio(candidate["requester_public_key"])
            candidate["requester_ratio"] = round(requester_ratio, 3)
            candidate["rule_reason"] = reason
            candidate["capacity_reason"] = cap_reason
            candidates.append(candidate)
            if len(candidates) >= max(limit, 1):
                break
        return candidates

    def list_open_requests(self, worker_public_key: Optional[str] = None) -> List[Dict[str, Any]]:
        worker_country = None
        worker_key = ""
        worker_rules = self._clone(self.DEFAULT_SERVING_RULES)
        if worker_public_key:
            worker_key = self.normalize_public_key(worker_public_key)
            worker = self._require_user(worker_key)
            worker["serving_rules"] = self._normalize_serving_rules(worker.get("serving_rules", {}))
            self._reset_daily_usage_if_needed(worker)
            worker_country = worker["country_code"]
            worker_rules = worker["serving_rules"]

        results: List[Dict[str, Any]] = []
        for record in self.requests.values():
            if record["status"] != "OPEN":
                continue
            if worker_country and record["country_preference"] and record["country_preference"] != worker_country:
                continue
            if worker_key:
                allowed, _ = self._request_allowed_by_rules(worker_key, record, worker_rules)
                if not allowed:
                    continue
            results.append(self._clone(record))
        if worker_key:
            followed = set(worker_rules.get("followed_public_keys", []))

            def _worker_priority(req: Dict[str, Any]) -> Tuple[int, float, str]:
                requester = req["requester_public_key"]
                requester_ratio, _ = self.get_ratio(requester)
                follow_rank = 0 if worker_rules.get("prioritize_followed_first", False) and requester in followed else 1
                ratio_rank = -requester_ratio if worker_rules.get("prioritize_high_ratio_first", True) else 0.0
                return (follow_rank, ratio_rank, req["created_at"])

            results.sort(key=_worker_priority)
        else:
            results.sort(key=lambda req: req["created_at"])
        return results

    def poll_next_request(self, worker_public_key: str) -> Optional[Dict[str, Any]]:
        open_requests = self.list_open_requests(worker_public_key=worker_public_key)
        return open_requests[0] if open_requests else None

    def claim_request(self, worker_public_key: str, request_id: str) -> Dict[str, Any]:
        worker_key = self.normalize_public_key(worker_public_key)
        worker = self._require_user(worker_key)
        worker["serving_rules"] = self._normalize_serving_rules(worker.get("serving_rules", {}))
        worker["network_settings"] = self._normalize_network_settings(worker.get("network_settings", {}))
        self._reset_daily_usage_if_needed(worker)
        request_record = self._require_request(request_id)

        if not self.is_node_online(worker_key):
            raise ArchiveTeamError("Worker must be online to claim a request.")
        if request_record["status"] != "OPEN":
            raise ArchiveTeamError("Request is not open for claiming.")
        if request_record["country_preference"] and request_record["country_preference"] != worker["country_code"]:
            raise ArchiveTeamError("Worker country does not match request preference.")
        allowed, reason = self._request_allowed_by_rules(worker_key, request_record, worker["serving_rules"])
        if not allowed:
            raise ArchiveTeamError(f"Request blocked by worker rules: {reason}.")
        capacity_ok, capacity_reason = self._worker_has_capacity_for_request(worker, request_record)
        if not capacity_ok:
            raise ArchiveTeamError(f"Worker daily capacity reached: {capacity_reason}.")

        request_record["status"] = "CLAIMED"
        request_record["claimed_by"] = worker_key
        self._increment_worker_capacity_usage(worker, request_record, claim_job=True)
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
        worker["network_settings"] = self._normalize_network_settings(worker.get("network_settings", {}))
        self._reset_daily_usage_if_needed(worker)
        request_record = self._require_request(request_id)

        if request_record["status"] != "CLAIMED":
            raise ArchiveTeamError("Request must be claimed before fulfillment.")
        if request_record["claimed_by"] != worker_key:
            raise ArchiveTeamError("Only claiming worker can fulfill the request.")
        if not content_hash.strip():
            raise ArchiveTeamError("Content hash is required.")

        estimated_size_bytes = self._extract_bytes_from_storage_uri(storage_uri)
        if estimated_size_bytes <= 0:
            estimated_size_bytes = self._estimate_request_size_bytes(request_record)
        capacity_ok, capacity_reason = self._worker_has_capacity_for_request(
            worker,
            request_record,
            extra_storage_bytes=estimated_size_bytes,
            check_jobs=False,
        )
        if not capacity_ok:
            raise ArchiveTeamError(f"Worker daily capacity reached: {capacity_reason}.")

        now = self._now()
        pinned_until = now + self.pin_window
        archive_id = hashlib.sha256(f"{request_id}:{content_hash}".encode("utf-8")).hexdigest()[:40]

        archive_record = {
            "archive_id": archive_id,
            "request_id": request_id,
            "source_url": request_record["url"],
            "archive_mode": request_record["archive_mode"],
            "download_profile": request_record.get("download_profile", "balanced"),
            "profile_options": self._clone(request_record.get("profile_options", {})),
            "worker_controls": self._clone(request_record.get("worker_controls", self.DEFAULT_WORKER_CONTROLS)),
            "policy_flags": self._clone(request_record.get("policy_flags", [])),
            "content_hash": content_hash.lower(),
            "storage_uri": storage_uri.strip(),
            "estimated_size_bytes": int(estimated_size_bytes),
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
        worker["stats"]["stored_bytes_total"] += int(estimated_size_bytes)
        self._increment_worker_capacity_usage(
            worker,
            request_record,
            claim_job=False,
            storage_bytes=int(estimated_size_bytes),
        )

        ledger_entry = self._append_ledger_entry(
            {
                "event": "ArchiveFulfilled",
                "request_id": request_id,
                "archive_id": archive_id,
                "worker_public_key": worker_key,
                "content_hash": content_hash.lower(),
                "storage_uri": storage_uri.strip(),
                "archive_mode": request_record["archive_mode"],
                "download_profile": request_record.get("download_profile", "balanced"),
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

        change_type_value = (change_type or "").strip().upper()
        proposal_id = secrets.token_hex(12)
        proposal = {
            "proposal_id": proposal_id,
            "author_public_key": author_key,
            "title": title.strip(),
            "description": description.strip(),
            "change_type": change_type_value,
            "target": (target or "").strip(),
            "proposed_patch": proposed_patch or "",
            "status": "OPEN",
            "quorum": int(quorum),
            "yes_threshold": float(yes_threshold),
            "votes": {},
            "yes_count": 0,
            "no_count": 0,
            "abstain_count": 0,
            "weighted_yes": 0.0,
            "weighted_no": 0.0,
            "weighted_abstain": 0.0,
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
        decisive_votes = proposal["weighted_yes"] + proposal["weighted_no"]
        yes_ratio = (proposal["weighted_yes"] / decisive_votes) if decisive_votes else 0.0

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
                "weighted_yes": proposal["weighted_yes"],
                "weighted_no": proposal["weighted_no"],
                "weighted_abstain": proposal["weighted_abstain"],
                "finalized_by": actor_key,
            }
        )
        if result == "APPROVED":
            self._apply_approved_proposal(actor_key, proposal)
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

    # -------------------------------------------------------------------------
    # Distributed site pinning state (Phase 3b)
    # -------------------------------------------------------------------------

    def get_site_state(self) -> Dict[str, Any]:
        return self._clone(self.site)

    def set_site_release(
        self,
        actor_public_key: str,
        cid: str,
        version: str = "",
        notes: str = "",
        proposal_id: str = "",
    ) -> Dict[str, Any]:
        actor_key = self.normalize_public_key(actor_public_key)
        self._require_user(actor_key)
        self._validate_site_cid(cid)

        self.site = {
            "current_cid": cid.strip(),
            "version": (version or "").strip(),
            "notes": (notes or "").strip(),
            "updated_at": self._now().isoformat(),
            "updated_by": actor_key,
            "proposal_id": (proposal_id or "").strip(),
        }
        self._append_ledger_entry(
            {
                "event": "SiteReleaseUpdated",
                "current_cid": self.site["current_cid"],
                "version": self.site["version"],
                "updated_by": actor_key,
                "proposal_id": self.site["proposal_id"],
            }
        )
        self._save()
        return self._clone(self.site)

    def attest_site_pin(
        self,
        node_public_key: str,
        cid: str = "",
        pinned: bool = True,
        pin_provider: str = "",
        signature: str = "",
    ) -> Dict[str, Any]:
        node_key = self.normalize_public_key(node_public_key)
        self._require_user(node_key)
        attested_cid = (cid or self.site.get("current_cid", "")).strip()
        self._validate_site_cid(attested_cid)

        attestation = {
            "public_key": node_key,
            "cid": attested_cid,
            "pinned": bool(pinned),
            "pin_provider": (pin_provider or "").strip(),
            "signature": (signature or "").strip(),
            "last_attested_at": self._now().isoformat(),
        }
        self.site_pin_attestations[node_key] = attestation
        self._save()
        return self._clone(attestation)

    def list_site_pinners(
        self,
        cid: str = "",
        online_only: bool = True,
        pinned_only: bool = True,
    ) -> List[Dict[str, Any]]:
        wanted_cid = (cid or self.site.get("current_cid", "")).strip()
        if wanted_cid:
            self._validate_site_cid(wanted_cid)

        rows: List[Dict[str, Any]] = []
        for row in self.site_pin_attestations.values():
            if wanted_cid and row["cid"] != wanted_cid:
                continue
            if pinned_only and not row["pinned"]:
                continue
            if online_only and not self.is_node_online(row["public_key"]):
                continue
            rows.append(self._clone(row))
        rows.sort(key=lambda item: item["last_attested_at"], reverse=True)
        return rows

    def get_site_health(
        self,
        cid: str = "",
        min_online_pinners: int = 3,
    ) -> Dict[str, Any]:
        if min_online_pinners < 0:
            raise ArchiveTeamError("min_online_pinners must be 0 or greater.")

        wanted_cid = (cid or self.site.get("current_cid", "")).strip()
        if wanted_cid:
            self._validate_site_cid(wanted_cid)

        all_rows = [
            self._clone(row)
            for row in self.site_pin_attestations.values()
            if (not wanted_cid or row["cid"] == wanted_cid)
        ]
        online_rows = [
            row
            for row in all_rows
            if row["pinned"] and self.is_node_online(row["public_key"])
        ]
        unique_online_keys = sorted({row["public_key"] for row in online_rows})
        return {
            "cid": wanted_cid,
            "current_cid": self.site.get("current_cid", ""),
            "total_attestations": len(all_rows),
            "online_pinners": len(unique_online_keys),
            "required_online_pinners": int(min_online_pinners),
            "healthy": len(unique_online_keys) >= int(min_online_pinners),
            "online_public_keys": unique_online_keys,
        }

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
        server["serving_rules"] = self._normalize_serving_rules(server.get("serving_rules", {}))
        server["network_settings"] = self._normalize_network_settings(server.get("network_settings", {}))
        requester["network_settings"] = self._normalize_network_settings(requester.get("network_settings", {}))
        self._reset_daily_usage_if_needed(server)
        self._reset_daily_usage_if_needed(requester)
        archive = self._require_archive(archive_id)

        serving_hosts = {host["public_key"] for host in self._active_hosts(archive)}
        if server_key not in serving_hosts:
            raise ArchiveTeamError("Server is not currently available for this archive.")
        requester_ratio, _ = self.get_ratio(requester_key)
        min_ratio = float(server["serving_rules"].get("min_ratio_to_serve", 0.0))
        if requester_ratio < min_ratio:
            raise ArchiveTeamError("Requester ratio is below server minimum serving requirement.")
        url_allowed, url_reason = self._request_allowed_by_rules(
            worker_public_key=server_key,
            request_record={"url": archive["source_url"], "requester_public_key": requester_key},
            rules=server["serving_rules"],
        )
        if not url_allowed:
            raise ArchiveTeamError(f"Archive blocked by server rules: {url_reason}.")

        transfer_bytes = int(archive.get("estimated_size_bytes") or self._estimate_request_size_bytes(archive))
        upload_cap = float(server["network_settings"].get("max_upload_gb_per_day", 0.0))
        download_cap = float(requester["network_settings"].get("max_download_gb_per_day", 0.0))
        upload_speed_limit = int(server["network_settings"].get("daily_upload_speed_mbps", 0))
        download_speed_limit = int(requester["network_settings"].get("daily_download_speed_mbps", 0))
        server_usage = self._ensure_daily_usage(server)
        requester_usage = self._ensure_daily_usage(requester)
        if upload_cap > 0 and server_usage["upload_bytes_served"] + transfer_bytes > int(upload_cap * 1024 ** 3):
            raise ArchiveTeamError("Server daily upload cap reached.")
        if download_cap > 0 and requester_usage["download_bytes_received"] + transfer_bytes > int(download_cap * 1024 ** 3):
            raise ArchiveTeamError("Requester daily download cap reached.")
        # Speed limits are applied as an approximate max transferable bytes/day.
        if upload_speed_limit > 0:
            upload_limit_bytes = self._daily_bytes_from_mbps(upload_speed_limit)
            if server_usage["upload_bytes_served"] + transfer_bytes > upload_limit_bytes:
                raise ArchiveTeamError("Server daily upload speed-derived cap reached.")
        if download_speed_limit > 0:
            download_limit_bytes = self._daily_bytes_from_mbps(download_speed_limit)
            if requester_usage["download_bytes_received"] + transfer_bytes > download_limit_bytes:
                raise ArchiveTeamError("Requester daily download speed-derived cap reached.")

        server["stats"]["files_served"] += 1
        server["stats"]["served_bytes_total"] += transfer_bytes
        requester["stats"]["files_requested"] += 1
        requester["stats"]["downloaded_bytes_total"] += transfer_bytes
        archive["serve_count"] += 1
        server_usage["upload_bytes_served"] += transfer_bytes
        requester_usage["download_bytes_received"] += transfer_bytes

        self._append_ledger_entry(
            {
                "event": "ArchiveServed",
                "archive_id": archive_id,
                "server_public_key": server_key,
                "requester_public_key": requester_key,
                "transfer_bytes": transfer_bytes,
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
        user["voting_power"] = round(self._vote_weight_for_user(canonical_key), 3)
        user["online"] = self.is_node_online(canonical_key)
        return user

    @classmethod
    def list_archive_modes(cls) -> List[str]:
        return [mode.value for mode in ArchiveMode]

    @classmethod
    def list_download_profiles(cls) -> Dict[str, Dict[str, Any]]:
        return cls._clone(cls.DOWNLOAD_PROFILES)

    @classmethod
    def default_worker_controls(cls) -> Dict[str, int]:
        return cls._clone(cls.DEFAULT_WORKER_CONTROLS)

    @classmethod
    def default_network_settings(cls) -> Dict[str, Any]:
        return cls._clone(cls.DEFAULT_NETWORK_SETTINGS)

    @classmethod
    def default_serving_rules(cls) -> Dict[str, Any]:
        return cls._clone(cls.DEFAULT_SERVING_RULES)

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
            "site": self.site,
            "site_pin_attestations": self.site_pin_attestations,
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
        self.site = raw.get("site", self._clone(self.DEFAULT_SITE_STATE))
        self.site_pin_attestations = raw.get("site_pin_attestations", {})
        self.ledger = raw.get("ledger", [])
        self.online_nodes = raw.get("online_nodes", {})
        self.login_challenges = raw.get("login_challenges", {})
        self.sessions = raw.get("sessions", {})
        for user in self.users.values():
            user["network_settings"] = self._normalize_network_settings(user.get("network_settings", {}))
            user["serving_rules"] = self._normalize_serving_rules(user.get("serving_rules", {}))
            self._reset_daily_usage_if_needed(user)
        for request_record in self.requests.values():
            self._hydrate_request_defaults(request_record)
        for archive_record in self.archives.values():
            request_record = self.requests.get(archive_record.get("request_id", ""))
            if request_record:
                archive_record.setdefault("download_profile", request_record.get("download_profile", "balanced"))
                archive_record.setdefault("profile_options", self._clone(request_record.get("profile_options", {})))
                archive_record.setdefault("worker_controls", self._clone(request_record.get("worker_controls", self.DEFAULT_WORKER_CONTROLS)))
                archive_record.setdefault("policy_flags", self._clone(request_record.get("policy_flags", [])))
            else:
                archive_record.setdefault("download_profile", "balanced")
                archive_record.setdefault("profile_options", {})
                archive_record.setdefault("worker_controls", self._clone(self.DEFAULT_WORKER_CONTROLS))
                archive_record.setdefault("policy_flags", [])

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
    def _clone(data: Any) -> Any:
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

    def _apply_approved_proposal(self, actor_key: str, proposal: Dict[str, Any]) -> None:
        if proposal["change_type"] != "SITE_RELEASE":
            return
        site_release = self._extract_site_release_payload(proposal)
        self.set_site_release(
            actor_public_key=actor_key,
            cid=site_release["cid"],
            version=site_release["version"],
            notes=site_release["notes"],
            proposal_id=proposal["proposal_id"],
        )

    def _extract_site_release_payload(self, proposal: Dict[str, Any]) -> Dict[str, str]:
        payload = {"cid": "", "version": "", "notes": ""}
        proposed_patch = (proposal.get("proposed_patch") or "").strip()
        if proposed_patch:
            try:
                patch_data = json.loads(proposed_patch)
                if isinstance(patch_data, dict):
                    payload["cid"] = str(patch_data.get("cid", "")).strip()
                    payload["version"] = str(patch_data.get("version", "")).strip()
                    payload["notes"] = str(patch_data.get("notes", "")).strip()
            except json.JSONDecodeError:
                # Backward-compatible fallback for non-JSON patches.
                payload["notes"] = proposed_patch

        if not payload["cid"]:
            payload["cid"] = str(proposal.get("target", "")).strip()
        self._validate_site_cid(payload["cid"])
        return payload

    def _recount_proposal_votes(self, proposal: Dict[str, Any]) -> None:
        yes_count = 0
        no_count = 0
        abstain_count = 0
        weighted_yes = 0.0
        weighted_no = 0.0
        weighted_abstain = 0.0
        for voter_key, vote_row in proposal["votes"].items():
            vote = vote_row["vote"]
            vote_weight = self._vote_weight_for_user(voter_key)
            vote_row["vote_weight"] = round(vote_weight, 3)
            if vote == "YES":
                yes_count += 1
                weighted_yes += vote_weight
            elif vote == "NO":
                no_count += 1
                weighted_no += vote_weight
            elif vote == "ABSTAIN":
                abstain_count += 1
                weighted_abstain += vote_weight
        proposal["yes_count"] = yes_count
        proposal["no_count"] = no_count
        proposal["abstain_count"] = abstain_count
        proposal["weighted_yes"] = round(weighted_yes, 3)
        proposal["weighted_no"] = round(weighted_no, 3)
        proposal["weighted_abstain"] = round(weighted_abstain, 3)
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

    def _assert_url_allowed(self, url: str, rules: Optional[Dict[str, Any]] = None) -> None:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        decoded_url = unquote(url).lower()

        if host and any(self._host_matches(host, blocked_host) for blocked_host in self.blocked_hosts):
            raise ArchiveTeamError("URL host is blocked by safety policy.")
        if host and any(self._host_matches(host, restricted_host) for restricted_host in self.DEFAULT_RESTRICTED_DRM_HOSTS):
            raise ArchiveTeamError("URL blocked by content policy (DRM/paywalled streaming host).")

        for term in self.blocked_url_terms:
            if term in decoded_url:
                raise ArchiveTeamError("URL blocked by safety policy.")

        if rules:
            normalized_rules = self._normalize_serving_rules(rules)
            for blocked_host in normalized_rules.get("site_blacklist", []):
                if host and self._host_matches(host, blocked_host):
                    raise ArchiveTeamError("URL host is blocked by user site blacklist.")
            if normalized_rules.get("block_porn_links", False):
                for keyword in self.DEFAULT_PORN_KEYWORDS:
                    if keyword in decoded_url:
                        raise ArchiveTeamError("URL blocked by user porn policy.")
            md_allowed, md_reason = self._apply_rules_md_hints(normalized_rules.get("rules_md", ""), url=url, host=host)
            if not md_allowed:
                raise ArchiveTeamError(f"URL blocked by user Rules.MD policy: {md_reason}.")

    def _build_policy_flags(self, url: str) -> List[str]:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        flags: List[str] = []
        if host and any(self._host_matches(host, auth_host) for auth_host in self.DEFAULT_AUTH_GATED_HOSTS):
            flags.append("auth_gated_source")
        return flags

    @staticmethod
    def _host_matches(host: str, candidate: str) -> bool:
        return host == candidate or host.endswith(f".{candidate}")

    @classmethod
    def _default_profile_for_mode(cls, mode: ArchiveMode) -> str:
        if mode == ArchiveMode.MEDIA_YTDLP:
            return "media_fast"
        if mode == ArchiveMode.GALLERY_DL:
            return "gallery_deep"
        if mode in (ArchiveMode.FULL_WARC, ArchiveMode.ZIP_WARC):
            return "forensic"
        return "balanced"

    @classmethod
    def _normalize_download_profile(cls, mode: ArchiveMode, download_profile: str) -> str:
        profile = (download_profile or "").strip().lower() or cls._default_profile_for_mode(mode)
        profile_row = cls.DOWNLOAD_PROFILES.get(profile)
        if not profile_row:
            raise ArchiveTeamError(f"Unsupported download_profile: {download_profile}")
        if mode.value not in profile_row["allowed_modes"]:
            raise ArchiveTeamError(f"download_profile '{profile}' is not supported for archive mode '{mode.value}'.")
        return profile

    @classmethod
    def _normalize_profile_options(
        cls,
        mode: ArchiveMode,
        download_profile: str,
        profile_options: Dict[str, Any],
    ) -> Dict[str, Any]:
        if not isinstance(profile_options, dict):
            raise ArchiveTeamError("profile_options must be a JSON object.")

        defaults = cls._clone(cls.DOWNLOAD_PROFILES[download_profile]["defaults"])
        for key, value in profile_options.items():
            if key not in defaults:
                raise ArchiveTeamError(f"Unsupported profile option: {key}")
            defaults[key] = value

        quality = str(defaults.get("video_quality", "best")).strip().lower()
        if quality not in cls.ALLOWED_VIDEO_QUALITIES:
            raise ArchiveTeamError("profile_options.video_quality is invalid.")
        defaults["video_quality"] = quality

        defaults["audio_only"] = cls._parse_bool(defaults.get("audio_only", False), "profile_options.audio_only")
        defaults["include_subtitles"] = cls._parse_bool(
            defaults.get("include_subtitles", False),
            "profile_options.include_subtitles",
        )
        defaults["include_thumbnail"] = cls._parse_bool(
            defaults.get("include_thumbnail", False),
            "profile_options.include_thumbnail",
        )
        defaults["playlist"] = cls._parse_bool(defaults.get("playlist", False), "profile_options.playlist")

        media_format = str(defaults.get("format", "")).strip().lower()
        if media_format not in cls.ALLOWED_MEDIA_FORMATS:
            raise ArchiveTeamError("profile_options.format is invalid.")
        defaults["format"] = media_format

        gallery_max_items = cls._parse_int(defaults.get("gallery_max_items", 0), "profile_options.gallery_max_items")
        if gallery_max_items < 0 or gallery_max_items > 5000:
            raise ArchiveTeamError("profile_options.gallery_max_items must be between 0 and 5000.")
        defaults["gallery_max_items"] = gallery_max_items

        cookies_source = str(defaults.get("cookies_from_browser", "")).strip().lower()
        if cookies_source not in cls.ALLOWED_COOKIE_BROWSERS:
            raise ArchiveTeamError("profile_options.cookies_from_browser is invalid.")
        defaults["cookies_from_browser"] = cookies_source

        if mode != ArchiveMode.MEDIA_YTDLP and defaults["audio_only"]:
            raise ArchiveTeamError("audio_only option is only supported for MEDIA_YTDLP mode.")
        if mode == ArchiveMode.GALLERY_DL and defaults["audio_only"]:
            raise ArchiveTeamError("audio_only cannot be used with GALLERY_DL mode.")

        return defaults

    @classmethod
    def _normalize_worker_controls(cls, worker_controls: Dict[str, Any]) -> Dict[str, int]:
        if not isinstance(worker_controls, dict):
            raise ArchiveTeamError("worker_controls must be a JSON object.")

        normalized = cls._clone(cls.DEFAULT_WORKER_CONTROLS)
        for key in worker_controls.keys():
            if key not in normalized:
                raise ArchiveTeamError(f"Unsupported worker control: {key}")

        if "max_retries" in worker_controls:
            normalized["max_retries"] = cls._parse_int(worker_controls["max_retries"], "worker_controls.max_retries")
        if "retry_backoff_seconds" in worker_controls:
            normalized["retry_backoff_seconds"] = cls._parse_int(
                worker_controls["retry_backoff_seconds"],
                "worker_controls.retry_backoff_seconds",
            )
        if "sleep_interval_seconds" in worker_controls:
            normalized["sleep_interval_seconds"] = cls._parse_int(
                worker_controls["sleep_interval_seconds"],
                "worker_controls.sleep_interval_seconds",
            )
        if "max_concurrent_downloads" in worker_controls:
            normalized["max_concurrent_downloads"] = cls._parse_int(
                worker_controls["max_concurrent_downloads"],
                "worker_controls.max_concurrent_downloads",
            )

        if normalized["max_retries"] < 0 or normalized["max_retries"] > 8:
            raise ArchiveTeamError("worker_controls.max_retries must be between 0 and 8.")
        if normalized["retry_backoff_seconds"] < 0 or normalized["retry_backoff_seconds"] > 300:
            raise ArchiveTeamError("worker_controls.retry_backoff_seconds must be between 0 and 300.")
        if normalized["sleep_interval_seconds"] < 0 or normalized["sleep_interval_seconds"] > 120:
            raise ArchiveTeamError("worker_controls.sleep_interval_seconds must be between 0 and 120.")
        if normalized["max_concurrent_downloads"] < 1 or normalized["max_concurrent_downloads"] > 8:
            raise ArchiveTeamError("worker_controls.max_concurrent_downloads must be between 1 and 8.")

        return normalized

    def _hydrate_request_defaults(self, request_record: Dict[str, Any]) -> None:
        try:
            mode = ArchiveMode(request_record.get("archive_mode", ArchiveMode.FULL_WARC.value))
        except ValueError:
            mode = ArchiveMode.FULL_WARC
            request_record["archive_mode"] = mode.value

        desired_profile = str(request_record.get("download_profile", "")).strip().lower()
        try:
            normalized_profile = self._normalize_download_profile(mode, desired_profile)
        except ArchiveTeamError:
            normalized_profile = self._default_profile_for_mode(mode)
        request_record["download_profile"] = normalized_profile

        try:
            request_record["profile_options"] = self._normalize_profile_options(
                mode=mode,
                download_profile=normalized_profile,
                profile_options=request_record.get("profile_options", {}) or {},
            )
        except ArchiveTeamError:
            request_record["profile_options"] = self._normalize_profile_options(
                mode=mode,
                download_profile=normalized_profile,
                profile_options={},
            )

        try:
            request_record["worker_controls"] = self._normalize_worker_controls(request_record.get("worker_controls", {}) or {})
        except ArchiveTeamError:
            request_record["worker_controls"] = self._clone(self.DEFAULT_WORKER_CONTROLS)

        request_record["policy_flags"] = self._clone(request_record.get("policy_flags", self._build_policy_flags(request_record.get("url", ""))))

    @staticmethod
    def _parse_int(value: Any, field_name: str) -> int:
        try:
            return int(value)
        except (TypeError, ValueError) as exc:
            raise ArchiveTeamError(f"{field_name} must be an integer.") from exc

    @staticmethod
    def _parse_bool(value: Any, field_name: str) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"true", "1", "yes", "y", "on"}:
                return True
            if normalized in {"false", "0", "no", "n", "off"}:
                return False
        if isinstance(value, (int, float)) and value in (0, 1):
            return bool(value)
        raise ArchiveTeamError(f"{field_name} must be a boolean.")

    @staticmethod
    def _validate_site_cid(cid: str) -> None:
        cid_value = (cid or "").strip()
        if not cid_value:
            raise ArchiveTeamError("Site CID is required.")
        # Basic CID sanity checks (supporting common CIDv0/CIDv1 forms).
        if cid_value.startswith("Qm") and len(cid_value) >= 46:
            return
        if cid_value.startswith("bafy") and len(cid_value) >= 20:
            return
        raise ArchiveTeamError("Invalid IPFS CID format.")

    def _normalize_network_settings(self, settings: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(settings, dict):
            settings = {}
        normalized = self._clone(self.DEFAULT_NETWORK_SETTINGS)
        normalized.update(settings)
        normalized["max_jobs_per_day"] = self._parse_int(normalized.get("max_jobs_per_day", 0), "network_settings.max_jobs_per_day")
        normalized["max_storage_gb_per_day"] = self._parse_float(
            normalized.get("max_storage_gb_per_day", 0.0),
            "network_settings.max_storage_gb_per_day",
        )
        normalized["max_upload_gb_per_day"] = self._parse_float(
            normalized.get("max_upload_gb_per_day", 0.0),
            "network_settings.max_upload_gb_per_day",
        )
        normalized["max_download_gb_per_day"] = self._parse_float(
            normalized.get("max_download_gb_per_day", 0.0),
            "network_settings.max_download_gb_per_day",
        )
        normalized["daily_upload_speed_mbps"] = self._parse_int(
            normalized.get("daily_upload_speed_mbps", 0),
            "network_settings.daily_upload_speed_mbps",
        )
        normalized["daily_download_speed_mbps"] = self._parse_int(
            normalized.get("daily_download_speed_mbps", 0),
            "network_settings.daily_download_speed_mbps",
        )
        for key in ("max_jobs_per_day", "daily_upload_speed_mbps", "daily_download_speed_mbps"):
            if normalized[key] < 0:
                raise ArchiveTeamError(f"{key} must be 0 or greater.")
        for key in ("max_storage_gb_per_day", "max_upload_gb_per_day", "max_download_gb_per_day"):
            if normalized[key] < 0:
                raise ArchiveTeamError(f"{key} must be 0 or greater.")
        return normalized

    def _normalize_serving_rules(self, rules: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(rules, dict):
            rules = {}
        normalized = self._clone(self.DEFAULT_SERVING_RULES)
        normalized.update(rules)
        normalized["block_porn_links"] = self._parse_bool(
            normalized.get("block_porn_links", False),
            "serving_rules.block_porn_links",
        )
        normalized["min_ratio_to_serve"] = self._parse_float(
            normalized.get("min_ratio_to_serve", 0.0),
            "serving_rules.min_ratio_to_serve",
        )
        if normalized["min_ratio_to_serve"] < 0:
            raise ArchiveTeamError("serving_rules.min_ratio_to_serve must be 0 or greater.")
        normalized["prioritize_high_ratio_first"] = self._parse_bool(
            normalized.get("prioritize_high_ratio_first", True),
            "serving_rules.prioritize_high_ratio_first",
        )
        normalized["prioritize_followed_first"] = self._parse_bool(
            normalized.get("prioritize_followed_first", False),
            "serving_rules.prioritize_followed_first",
        )
        followed_keys: List[str] = []
        for key in normalized.get("followed_public_keys", []) or []:
            followed_keys.append(self.normalize_public_key(str(key)))
        normalized["followed_public_keys"] = sorted(set(followed_keys))
        blacklist_hosts: List[str] = []
        for host in normalized.get("site_blacklist", []) or []:
            clean = str(host or "").strip().lower()
            if clean:
                blacklist_hosts.append(clean)
        normalized["site_blacklist"] = sorted(set(blacklist_hosts))
        normalized["rules_md"] = str(normalized.get("rules_md", "") or "")
        return normalized

    def _reset_daily_usage_if_needed(self, user: Dict[str, Any]) -> None:
        today = self._now().date().isoformat()
        usage = user.setdefault(
            "daily_usage",
            {"date": today, "jobs_claimed": 0, "storage_bytes_added": 0, "upload_bytes_served": 0, "download_bytes_received": 0},
        )
        if usage.get("date") != today:
            usage["date"] = today
            usage["jobs_claimed"] = 0
            usage["storage_bytes_added"] = 0
            usage["upload_bytes_served"] = 0
            usage["download_bytes_received"] = 0

    def _ensure_daily_usage(self, user: Dict[str, Any]) -> Dict[str, Any]:
        self._reset_daily_usage_if_needed(user)
        usage = user.setdefault("daily_usage", {})
        usage.setdefault("jobs_claimed", 0)
        usage.setdefault("storage_bytes_added", 0)
        usage.setdefault("upload_bytes_served", 0)
        usage.setdefault("download_bytes_received", 0)
        return usage

    def _request_allowed_by_rules(
        self,
        worker_public_key: str,
        request_record: Dict[str, Any],
        rules: Dict[str, Any],
    ) -> Tuple[bool, str]:
        url = str(request_record.get("url", "")).strip()
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        decoded = unquote(url).lower()

        for blocked_host in rules.get("site_blacklist", []):
            if host and self._host_matches(host, blocked_host):
                return False, "site_blacklist"

        if rules.get("block_porn_links", False):
            for keyword in self.DEFAULT_PORN_KEYWORDS:
                if keyword in decoded:
                    return False, "porn_filtered"

        requester_raw = str(request_record.get("requester_public_key", "") or "").strip()
        requester_ratio = 0.0
        if requester_raw:
            requester_key = self.normalize_public_key(requester_raw)
            requester_ratio, _ = self.get_ratio(requester_key)
        if requester_ratio < float(rules.get("min_ratio_to_serve", 0.0)):
            return False, "not_enough_ratio_to_serve"

        rules_md = str(rules.get("rules_md", "") or "")
        if rules_md:
            md_allowed, md_reason = self._apply_rules_md_hints(rules_md, url=url, host=host)
            if not md_allowed:
                return False, md_reason

        return True, ""

    def _apply_rules_md_hints(self, rules_md: str, url: str, host: str) -> Tuple[bool, str]:
        text = rules_md.lower()
        if "do not archive porn" in text or "no porn" in text:
            decoded = unquote(url).lower()
            for keyword in self.DEFAULT_PORN_KEYWORDS:
                if keyword in decoded:
                    return False, "rules_md_porn_filtered"

        blocked_hosts: List[str] = []
        for line in rules_md.splitlines():
            stripped = line.strip().lower()
            if stripped.startswith(("block:", "blacklist:", "deny:")):
                _, _, value = stripped.partition(":")
                host_value = value.strip()
                if host_value:
                    blocked_hosts.append(host_value)

        for blocked_host in blocked_hosts:
            if host and self._host_matches(host, blocked_host):
                return False, "rules_md_blocked_host"

        return True, ""

    def _worker_has_capacity_for_request(
        self,
        worker: Dict[str, Any],
        request_record: Dict[str, Any],
        extra_storage_bytes: int = 0,
        check_jobs: bool = True,
    ) -> Tuple[bool, str]:
        settings = self._normalize_network_settings(worker.get("network_settings", {}))
        usage = self._ensure_daily_usage(worker)
        if check_jobs and settings["max_jobs_per_day"] > 0 and usage["jobs_claimed"] >= settings["max_jobs_per_day"]:
            return False, "daily_job_limit_reached"
        if settings["max_storage_gb_per_day"] > 0:
            storage_cap = int(settings["max_storage_gb_per_day"] * 1024 ** 3)
            if usage["storage_bytes_added"] + max(extra_storage_bytes, 0) > storage_cap:
                return False, "daily_storage_gb_limit_reached"
        return True, ""

    def _increment_worker_capacity_usage(
        self,
        worker: Dict[str, Any],
        request_record: Dict[str, Any],
        claim_job: bool = True,
        storage_bytes: int = 0,
    ) -> None:
        usage = self._ensure_daily_usage(worker)
        if claim_job:
            usage["jobs_claimed"] += 1
        if storage_bytes > 0:
            usage["storage_bytes_added"] += int(storage_bytes)

    @staticmethod
    def _extract_bytes_from_storage_uri(storage_uri: str) -> int:
        parsed = urlparse(storage_uri or "")
        query = parse_qs(parsed.query or "")
        for key in ("size_bytes", "bytes", "size"):
            value = query.get(key, [""])[0]
            if not value:
                continue
            try:
                return max(int(value), 0)
            except (TypeError, ValueError):
                continue
        return 0

    def _estimate_request_size_bytes(self, request_record: Dict[str, Any]) -> int:
        mode = str(request_record.get("archive_mode", ArchiveMode.FULL_WARC.value))
        if mode == ArchiveMode.ZIP_WARC.value:
            return 120 * 1024 * 1024
        if mode == ArchiveMode.MEDIA_YTDLP.value:
            return 800 * 1024 * 1024
        if mode == ArchiveMode.GALLERY_DL.value:
            return 250 * 1024 * 1024
        return 300 * 1024 * 1024

    def _vote_weight_for_user(self, public_key: str) -> float:
        canonical_key = self.normalize_public_key(public_key)
        ratio, _ = self.get_ratio(canonical_key)
        return min(max(ratio, 0.1), self.MAX_VOTE_WEIGHT)

    @staticmethod
    def _parse_float(value: Any, field_name: str) -> float:
        try:
            return float(value)
        except (TypeError, ValueError) as exc:
            raise ArchiveTeamError(f"{field_name} must be a number.") from exc

    @staticmethod
    def _daily_bytes_from_mbps(mbps: int) -> int:
        # Convert megabits/sec into approximate bytes/day.
        return int((max(mbps, 0) * 1_000_000 / 8) * 86400)
