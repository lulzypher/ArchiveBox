from __future__ import annotations

import hashlib
import secrets
from typing import Any, Dict, Optional

from .network import ArchiveTeamNetwork


class ArchiveTeamNode:
    """Lightweight worker client for the ArchiveTeam network MVP."""

    def __init__(
        self,
        network: ArchiveTeamNetwork,
        private_key: str,
        public_key: str,
    ) -> None:
        self.network = network
        self.private_key = private_key.strip().lower()
        self.public_key = self.network.normalize_public_key(public_key)

    @classmethod
    def create(cls, network: ArchiveTeamNetwork) -> Dict[str, str]:
        return network.create_keypair()

    def heartbeat(self, country_code: Optional[str] = None) -> None:
        self.network.set_node_online(self.public_key, country_code=country_code)

    def go_offline(self) -> None:
        self.network.set_node_offline(self.public_key)

    def submit_request(
        self,
        url: str,
        archive_mode: str,
        country_preference: str = "",
        download_profile: str = "balanced",
        profile_options: Optional[Dict[str, Any]] = None,
        worker_controls: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self.network.submit_request(
            requester_public_key=self.public_key,
            url=url,
            archive_mode=archive_mode,
            country_preference=country_preference,
            download_profile=download_profile,
            profile_options=profile_options,
            worker_controls=worker_controls,
        )

    def poll_and_claim(self) -> Optional[Dict[str, Any]]:
        request_record = self.network.poll_next_request(self.public_key)
        if not request_record:
            return None
        return self.network.claim_request(self.public_key, request_record["request_id"])

    def fulfill_claimed_request(
        self,
        request_id: str,
        archive_bytes: bytes,
        storage_uri: str,
    ) -> Dict[str, Any]:
        content_hash = hashlib.sha256(archive_bytes).hexdigest()
        return self.network.fulfill_request(
            worker_public_key=self.public_key,
            request_id=request_id,
            content_hash=content_hash,
            storage_uri=storage_uri,
        )

    def sign_login_challenge(self, challenge: str) -> str:
        # MVP signature helper to keep key handling in one place.
        # In production this should use hardware wallet or encrypted key storage.
        from nacl.signing import SigningKey

        signing_key = SigningKey(bytes.fromhex(self.private_key))
        signed = signing_key.sign(challenge.encode("utf-8"))
        return signed.signature.hex()

    def self_host_archive(self, archive_id: str) -> Dict[str, Any]:
        return self.network.assume_archive_hosting(self.public_key, archive_id)

    def serve_archive_to(self, requester_public_key: str, archive_id: str) -> Dict[str, Any]:
        return self.network.record_archive_serve(
            server_public_key=self.public_key,
            requester_public_key=requester_public_key,
            archive_id=archive_id,
        )

    @staticmethod
    def generate_storage_uri() -> str:
        return f"ipfs://{secrets.token_hex(24)}"
