#!/usr/bin/env python3

__package__ = 'archivebox.cli'
__command__ = 'archivebox archiveteam'

import sys
import json
import argparse

from pathlib import Path
from typing import Optional, List, IO

from ..util import docstring
from ..config import OUTPUT_DIR
from ..logging_util import SmartFormatter, reject_stdin
from ..archiveteam import ArchiveMode, ArchiveTeamNetwork, ArchiveTeamNode


@docstring("""ArchiveTeam decentralized archiving MVP commands.""")
def main(args: Optional[List[str]] = None, stdin: Optional[IO] = None, pwd: Optional[str] = None) -> None:
    parser = argparse.ArgumentParser(
        prog=__command__,
        description=main.__doc__,
        add_help=True,
        formatter_class=SmartFormatter,
    )
    parser.add_argument(
        '--state-file',
        default=str(Path(pwd or OUTPUT_DIR) / 'archiveteam_state.json'),
        help='Path to persistent ArchiveTeam state JSON file.',
    )

    subparsers = parser.add_subparsers(dest='action', required=True)

    register = subparsers.add_parser('register', help='Create user + keypair and store user profile.')
    register.add_argument('--username', required=True)
    register.add_argument('--country', required=True)
    register.add_argument('--worker', choices=('true', 'false'), default='true')

    profile = subparsers.add_parser('profile', help='Update user profile metadata.')
    profile.add_argument('--public-key', required=True)
    profile.add_argument('--pfp-url', default='')
    profile.add_argument('--bio', default='')
    profile.add_argument('--website', default='')

    heartbeat = subparsers.add_parser('heartbeat', help='Mark node online (with optional country update).')
    heartbeat.add_argument('--public-key', required=True)
    heartbeat.add_argument('--country', default='')

    submit = subparsers.add_parser('request', help='Submit archive request.')
    submit.add_argument('--public-key', required=True)
    submit.add_argument('--url', required=True)
    submit.add_argument('--mode', choices=(ArchiveMode.FULL_WARC.value, ArchiveMode.ZIP_WARC.value), default=ArchiveMode.FULL_WARC.value)
    submit.add_argument('--country-preference', default='')

    list_open = subparsers.add_parser('list-open', help='List currently open requests.')
    list_open.add_argument('--worker-public-key', default='')

    claim = subparsers.add_parser('claim', help='Claim next available request for worker.')
    claim.add_argument('--public-key', required=True)

    fulfill = subparsers.add_parser('fulfill', help='Fulfill a claimed request.')
    fulfill.add_argument('--public-key', required=True)
    fulfill.add_argument('--request-id', required=True)
    fulfill.add_argument('--content-hash', required=True)
    fulfill.add_argument('--storage-uri', required=True)

    search = subparsers.add_parser('search', help='Search available online archives.')
    search.add_argument('--query', default='')

    ratio = subparsers.add_parser('ratio', help='Get user ratio and score band.')
    ratio.add_argument('--public-key', required=True)

    command = parser.parse_args(args or ())
    reject_stdin(__command__, stdin)

    network = ArchiveTeamNetwork(storage_path=command.state_file)

    if command.action == 'register':
        keypair = ArchiveTeamNode.create(network)
        user = network.register_user(
            public_key=keypair['public_key'],
            username=command.username,
            country_code=command.country,
            is_worker=command.worker == 'true',
        )
        print(json.dumps({'user': user, 'keys': keypair}, indent=2, sort_keys=True))
        return

    if command.action == 'profile':
        profile_data = network.update_profile(
            public_key=command.public_key,
            pfp_url=command.pfp_url,
            bio=command.bio,
            website_url=command.website,
        )
        print(json.dumps(profile_data, indent=2, sort_keys=True))
        return

    if command.action == 'heartbeat':
        network.set_node_online(command.public_key, country_code=command.country or None)
        print(json.dumps({'ok': True, 'public_key': network.display_public_key(command.public_key)}, indent=2))
        return

    if command.action == 'request':
        request = network.submit_request(
            requester_public_key=command.public_key,
            url=command.url,
            archive_mode=command.mode,
            country_preference=command.country_preference,
        )
        print(json.dumps(request, indent=2, sort_keys=True))
        return

    if command.action == 'list-open':
        requests = network.list_open_requests(worker_public_key=command.worker_public_key or None)
        print(json.dumps(requests, indent=2, sort_keys=True))
        return

    if command.action == 'claim':
        next_request = network.poll_next_request(command.public_key)
        if not next_request:
            print(json.dumps({'request': None}, indent=2))
            return
        claimed = network.claim_request(command.public_key, next_request['request_id'])
        print(json.dumps(claimed, indent=2, sort_keys=True))
        return

    if command.action == 'fulfill':
        archive = network.fulfill_request(
            worker_public_key=command.public_key,
            request_id=command.request_id,
            content_hash=command.content_hash,
            storage_uri=command.storage_uri,
        )
        print(json.dumps(archive, indent=2, sort_keys=True))
        return

    if command.action == 'search':
        results = network.search_available_archives(query=command.query)
        print(json.dumps(results, indent=2, sort_keys=True))
        return

    if command.action == 'ratio':
        summary = network.get_user_summary(command.public_key)
        print(json.dumps(summary, indent=2, sort_keys=True))
        return

    raise SystemExit(f'Unhandled action: {command.action}')


if __name__ == '__main__':
    main(args=sys.argv[1:], stdin=sys.stdin)
