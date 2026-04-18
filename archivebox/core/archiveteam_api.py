__package__ = "archivebox.core"

import json
import os

from pathlib import Path
from typing import Any, Dict, Optional

from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt

from ..archiveteam import ArchiveTeamError, ArchiveTeamNetwork
from ..config import OUTPUT_DIR


def _state_file_path() -> str:
    return os.environ.get("ARCHIVETEAM_STATE_FILE") or str(Path(OUTPUT_DIR) / "archiveteam_state.json")


@method_decorator(csrf_exempt, name="dispatch")
class ArchiveTeamAPIView(View):
    """HTTP JSON API for ArchiveTeam workflows."""

    def get(self, request: HttpRequest, endpoint: str = "") -> HttpResponse:
        return self._route(request, "GET", endpoint)

    def post(self, request: HttpRequest, endpoint: str = "") -> HttpResponse:
        return self._route(request, "POST", endpoint)

    def patch(self, request: HttpRequest, endpoint: str = "") -> HttpResponse:
        return self._route(request, "PATCH", endpoint)

    def delete(self, request: HttpRequest, endpoint: str = "") -> HttpResponse:
        return self._route(request, "DELETE", endpoint)

    def _route(self, request: HttpRequest, method: str, endpoint: str) -> HttpResponse:
        network = ArchiveTeamNetwork(storage_path=_state_file_path())
        endpoint = endpoint.strip("/")

        try:
            body = self._body(request)

            if method == "GET" and endpoint in ("", "health"):
                return self._ok(
                    {
                        "ok": True,
                        "name": "archiveteam-api",
                        "version": "v1",
                    }
                )

            if method == "POST" and endpoint == "register":
                keypair = network.create_keypair()
                user = network.register_user(
                    public_key=keypair["public_key"],
                    username=body["username"],
                    country_code=body["country"],
                    is_worker=bool(body.get("is_worker", True)),
                )
                return self._ok({"user": user, "keys": keypair}, status=201)

            if method == "POST" and endpoint == "login/challenge":
                challenge = network.issue_login_challenge(body["public_key"])
                return self._ok({"challenge": challenge})

            if method == "POST" and endpoint == "login/complete":
                token = network.complete_login(
                    public_key=body["public_key"],
                    signature_hex=body["signature"],
                )
                return self._ok({"session_token": token})

            if method == "GET" and endpoint == "me":
                session_key = self._require_session(network, request)
                return self._ok(network.get_user_summary(session_key))

            if method == "POST" and endpoint == "profile":
                session_key = self._require_session(network, request)
                profile = network.update_profile(
                    public_key=session_key,
                    pfp_url=str(body.get("pfp_url", "")),
                    bio=str(body.get("bio", "")),
                    website_url=str(body.get("website_url", "")),
                )
                return self._ok(profile)

            if method == "POST" and endpoint == "heartbeat":
                session_key = self._require_session(network, request)
                network.set_node_online(
                    public_key=session_key,
                    country_code=body.get("country_code"),
                )
                return self._ok({"ok": True})

            if method == "POST" and endpoint == "requests":
                session_key = self._require_session(network, request)
                request_row = network.submit_request(
                    requester_public_key=session_key,
                    url=body["url"],
                    archive_mode=body.get("archive_mode", "FULL_WARC"),
                    country_preference=body.get("country_preference", ""),
                )
                return self._ok(request_row, status=201)

            if method == "GET" and endpoint == "requests/open":
                session_key = self._optional_session(network, request)
                worker_public_key = request.GET.get("worker_public_key") or session_key
                requests = network.list_open_requests(worker_public_key=worker_public_key or None)
                return self._ok(requests)

            if method == "POST" and endpoint == "requests/claim":
                session_key = self._require_session(network, request)
                claimed = network.claim_request(
                    worker_public_key=session_key,
                    request_id=body["request_id"],
                )
                return self._ok(claimed)

            if method == "POST" and endpoint == "requests/fulfill":
                session_key = self._require_session(network, request)
                archive = network.fulfill_request(
                    worker_public_key=session_key,
                    request_id=body["request_id"],
                    content_hash=body["content_hash"],
                    storage_uri=body["storage_uri"],
                )
                return self._ok(archive)

            if method == "GET" and endpoint == "archives/search":
                query = request.GET.get("query", "")
                return self._ok(network.search_available_archives(query=query))

            if method == "GET" and endpoint == "ratio":
                public_key = request.GET.get("public_key") or self._optional_session(network, request)
                if not public_key:
                    raise ArchiveTeamError("public_key or session token is required.")
                return self._ok(network.get_user_summary(public_key))

            if method == "POST" and endpoint == "proposals":
                session_key = self._require_session(network, request)
                proposal = network.create_proposal(
                    author_public_key=session_key,
                    title=body["title"],
                    description=body.get("description", ""),
                    change_type=body.get("change_type", "GENERAL"),
                    target=body.get("target", ""),
                    proposed_patch=body.get("proposed_patch", ""),
                    quorum=int(body.get("quorum", 3)),
                    yes_threshold=float(body.get("yes_threshold", 0.6)),
                )
                return self._ok(proposal, status=201)

            if method == "GET" and endpoint == "proposals":
                status_filter = request.GET.get("status", "")
                author_public_key = request.GET.get("author_public_key", "")
                proposals = network.list_proposals(
                    status=status_filter,
                    author_public_key=author_public_key,
                )
                return self._ok(proposals)

            if endpoint.startswith("proposals/"):
                return self._proposal_subroute(network, request, method, endpoint, body)

            if method == "POST" and endpoint == "collections":
                session_key = self._require_session(network, request)
                collection = network.create_collection(
                    owner_public_key=session_key,
                    name=body["name"],
                    description=body.get("description", ""),
                    is_private=bool(body.get("is_private", False)),
                    allow_submissions=bool(body.get("allow_submissions", False)),
                )
                return self._ok(collection, status=201)

            if method == "GET" and endpoint == "collections":
                viewer_public_key = request.GET.get("viewer_public_key") or self._optional_session(network, request)
                owner_public_key = request.GET.get("owner_public_key")
                collections = network.list_collections(
                    viewer_public_key=viewer_public_key or None,
                    owner_public_key=owner_public_key or None,
                )
                return self._ok(collections)

            if endpoint.startswith("collections/"):
                return self._collection_subroute(network, request, method, endpoint, body)

            if endpoint.startswith("submissions/"):
                return self._submission_subroute(network, request, method, endpoint, body)

            return self._error("Unknown endpoint.", status=404)
        except KeyError as exc:
            return self._error(f"Missing required field: {exc.args[0]}")
        except ArchiveTeamError as exc:
            return self._error(str(exc), status=400)
        except json.JSONDecodeError:
            return self._error("Invalid JSON body.", status=400)

    def _collection_subroute(
        self,
        network: ArchiveTeamNetwork,
        request: HttpRequest,
        method: str,
        endpoint: str,
        body: Dict[str, Any],
    ) -> HttpResponse:
        # collections/<id>, collections/<id>/archives, collections/<id>/submit, collections/<id>/fork
        parts = endpoint.split("/")
        if len(parts) < 2:
            return self._error("Invalid collection endpoint.", status=404)
        collection_id = parts[1]

        if len(parts) == 2:
            if method == "GET":
                viewer_public_key = request.GET.get("viewer_public_key") or self._optional_session(network, request)
                collection = network.get_collection(
                    collection_id=collection_id,
                    viewer_public_key=viewer_public_key or None,
                )
                return self._ok(collection)

            session_key = self._require_session(network, request)
            if method == "PATCH":
                updated = network.update_collection(
                    owner_public_key=session_key,
                    collection_id=collection_id,
                    name=body.get("name"),
                    description=body.get("description"),
                    is_private=body.get("is_private"),
                    allow_submissions=body.get("allow_submissions"),
                )
                return self._ok(updated)

            if method == "DELETE":
                network.delete_collection(
                    owner_public_key=session_key,
                    collection_id=collection_id,
                )
                return self._ok({"ok": True})

            return self._error("Unsupported collection method.", status=405)

        action = parts[2]
        if method != "POST":
            return self._error("Unsupported collection sub-endpoint method.", status=405)

        session_key = self._require_session(network, request)
        if action == "archives":
            updated = network.add_archive_to_collection(
                owner_public_key=session_key,
                collection_id=collection_id,
                archive_id=body["archive_id"],
            )
            return self._ok(updated)

        if action == "submit":
            submission = network.submit_collection_entry(
                submitter_public_key=session_key,
                collection_id=collection_id,
                archive_id=body["archive_id"],
                note=body.get("note", ""),
            )
            return self._ok(submission, status=201)

        if action == "fork":
            fork = network.fork_collection(
                forker_public_key=session_key,
                source_collection_id=collection_id,
                name=body.get("name"),
                description=body.get("description"),
            )
            return self._ok(fork, status=201)

        return self._error("Unknown collection action.", status=404)

    def _submission_subroute(
        self,
        network: ArchiveTeamNetwork,
        request: HttpRequest,
        method: str,
        endpoint: str,
        body: Dict[str, Any],
    ) -> HttpResponse:
        # submissions/<submission_id>/review
        parts = endpoint.split("/")
        if len(parts) != 3 or parts[2] != "review":
            return self._error("Invalid submission endpoint.", status=404)
        if method != "POST":
            return self._error("Unsupported submission method.", status=405)

        session_key = self._require_session(network, request)
        approve = bool(body.get("approve", False))
        reviewed = network.review_collection_submission(
            owner_public_key=session_key,
            submission_id=parts[1],
            approve=approve,
        )
        return self._ok(reviewed)

    def _proposal_subroute(
        self,
        network: ArchiveTeamNetwork,
        request: HttpRequest,
        method: str,
        endpoint: str,
        body: Dict[str, Any],
    ) -> HttpResponse:
        # proposals/<id>, proposals/<id>/vote, proposals/<id>/finalize, proposals/<id>/close
        parts = endpoint.split("/")
        if len(parts) < 2:
            return self._error("Invalid proposal endpoint.", status=404)
        proposal_id = parts[1]

        if len(parts) == 2:
            if method != "GET":
                return self._error("Unsupported proposal method.", status=405)
            proposal = network.get_proposal(proposal_id)
            return self._ok(proposal)

        if method != "POST":
            return self._error("Unsupported proposal sub-endpoint method.", status=405)

        session_key = self._require_session(network, request)
        action = parts[2]
        if action == "vote":
            proposal = network.cast_proposal_vote(
                voter_public_key=session_key,
                proposal_id=proposal_id,
                vote=body["vote"],
                note=body.get("note", ""),
            )
            return self._ok(proposal)

        if action == "finalize":
            proposal = network.finalize_proposal(
                actor_public_key=session_key,
                proposal_id=proposal_id,
            )
            return self._ok(proposal)

        if action == "close":
            proposal = network.close_proposal(
                actor_public_key=session_key,
                proposal_id=proposal_id,
            )
            return self._ok(proposal)

        return self._error("Unknown proposal action.", status=404)

    @staticmethod
    def _optional_session(network: ArchiveTeamNetwork, request: HttpRequest) -> Optional[str]:
        header_key = request.META.get("HTTP_X_AT_SESSION", "").strip()
        if not header_key:
            auth_header = request.META.get("HTTP_AUTHORIZATION", "").strip()
            if auth_header.lower().startswith("bearer "):
                header_key = auth_header.split(" ", 1)[1].strip()
        if not header_key:
            return None
        session = network.sessions.get(header_key)
        if not session:
            raise ArchiveTeamError("Invalid session token.")
        return session["public_key"]

    @classmethod
    def _require_session(cls, network: ArchiveTeamNetwork, request: HttpRequest) -> str:
        session_key = cls._optional_session(network, request)
        if not session_key:
            raise ArchiveTeamError("Authentication required.")
        return session_key

    @staticmethod
    def _body(request: HttpRequest) -> Dict[str, Any]:
        if not request.body:
            return {}
        return json.loads(request.body.decode("utf-8"))

    @staticmethod
    def _ok(payload: Any, status: int = 200) -> HttpResponse:
        return JsonResponse(payload, status=status, safe=not isinstance(payload, list))

    @staticmethod
    def _error(message: str, status: int = 400) -> HttpResponse:
        return JsonResponse({"ok": False, "error": message}, status=status)
