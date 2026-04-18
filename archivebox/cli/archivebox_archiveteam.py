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
    submit.add_argument(
        '--mode',
        choices=tuple(mode.value for mode in ArchiveMode),
        default=ArchiveMode.FULL_WARC.value,
    )
    submit.add_argument('--country-preference', default='')
    submit.add_argument('--download-profile', default='balanced')
    submit.add_argument('--video-quality', default='')
    submit.add_argument('--audio-only', choices=('true', 'false'))
    submit.add_argument('--include-subtitles', choices=('true', 'false'))
    submit.add_argument('--include-thumbnail', choices=('true', 'false'))
    submit.add_argument('--playlist', choices=('true', 'false'))
    submit.add_argument('--format', default='')
    submit.add_argument('--gallery-max-items', type=int)
    submit.add_argument('--cookies-from-browser', default='')
    submit.add_argument('--max-retries', type=int)
    submit.add_argument('--retry-backoff-seconds', type=int)
    submit.add_argument('--sleep-interval-seconds', type=int)
    submit.add_argument('--max-concurrent-downloads', type=int)

    list_open = subparsers.add_parser('list-open', help='List currently open requests.')
    list_open.add_argument('--worker-public-key', default='')

    request_candidates = subparsers.add_parser('request-candidates', help='List worker-eligible requests after rules/capacity checks.')
    request_candidates.add_argument('--public-key', required=True)
    request_candidates.add_argument('--limit', type=int, default=20)

    settings_network_get = subparsers.add_parser('settings-network-get', help='Get worker daily network/capacity settings.')
    settings_network_get.add_argument('--public-key', required=True)

    settings_network_update = subparsers.add_parser('settings-network-update', help='Update worker daily network/capacity settings.')
    settings_network_update.add_argument('--public-key', required=True)
    settings_network_update.add_argument('--max-jobs-per-day', type=int)
    settings_network_update.add_argument('--max-storage-gb-per-day', type=float)
    settings_network_update.add_argument('--max-upload-gb-per-day', type=float)
    settings_network_update.add_argument('--max-download-gb-per-day', type=float)
    settings_network_update.add_argument('--daily-upload-speed-mbps', type=int)
    settings_network_update.add_argument('--daily-download-speed-mbps', type=int)

    settings_rules_get = subparsers.add_parser('settings-rules-get', help='Get worker serving and policy rules.')
    settings_rules_get.add_argument('--public-key', required=True)

    settings_rules_update = subparsers.add_parser('settings-rules-update', help='Update worker serving and policy rules.')
    settings_rules_update.add_argument('--public-key', required=True)
    settings_rules_update.add_argument('--block-porn-links', choices=('true', 'false'))
    settings_rules_update.add_argument('--min-ratio-to-serve', type=float)
    settings_rules_update.add_argument('--prioritize-high-ratio-first', choices=('true', 'false'))
    settings_rules_update.add_argument('--prioritize-followed-first', choices=('true', 'false'))
    settings_rules_update.add_argument('--followed-public-key', action='append', default=[])
    settings_rules_update.add_argument('--site-blacklist-host', action='append', default=[])
    settings_rules_update.add_argument('--rules-md', default=None)

    claim = subparsers.add_parser('claim', help='Claim next available request for worker.')
    claim.add_argument('--public-key', required=True)

    fulfill = subparsers.add_parser('fulfill', help='Fulfill a claimed request.')
    fulfill.add_argument('--public-key', required=True)
    fulfill.add_argument('--request-id', required=True)
    fulfill.add_argument('--content-hash', required=True)
    fulfill.add_argument('--storage-uri', required=True)

    collection_create = subparsers.add_parser('collection-create', help='Create a collection.')
    collection_create.add_argument('--owner-public-key', required=True)
    collection_create.add_argument('--name', required=True)
    collection_create.add_argument('--description', default='')
    collection_create.add_argument('--private', choices=('true', 'false'), default='false')
    collection_create.add_argument('--allow-submissions', choices=('true', 'false'), default='false')

    collection_update = subparsers.add_parser('collection-update', help='Update a collection.')
    collection_update.add_argument('--owner-public-key', required=True)
    collection_update.add_argument('--collection-id', required=True)
    collection_update.add_argument('--name')
    collection_update.add_argument('--description')
    collection_update.add_argument('--private', choices=('true', 'false'))
    collection_update.add_argument('--allow-submissions', choices=('true', 'false'))

    collection_delete = subparsers.add_parser('collection-delete', help='Delete a collection.')
    collection_delete.add_argument('--owner-public-key', required=True)
    collection_delete.add_argument('--collection-id', required=True)

    collection_get = subparsers.add_parser('collection-get', help='Get collection details.')
    collection_get.add_argument('--collection-id', required=True)
    collection_get.add_argument('--viewer-public-key', default='')

    collection_list = subparsers.add_parser('collection-list', help='List collections visible to viewer.')
    collection_list.add_argument('--viewer-public-key', default='')
    collection_list.add_argument('--owner-public-key', default='')

    collection_add_archive = subparsers.add_parser('collection-add-archive', help='Owner adds archive to collection.')
    collection_add_archive.add_argument('--owner-public-key', required=True)
    collection_add_archive.add_argument('--collection-id', required=True)
    collection_add_archive.add_argument('--archive-id', required=True)

    collection_submit = subparsers.add_parser('collection-submit', help='Submit archive to owner-moderated collection.')
    collection_submit.add_argument('--submitter-public-key', required=True)
    collection_submit.add_argument('--collection-id', required=True)
    collection_submit.add_argument('--archive-id', required=True)
    collection_submit.add_argument('--note', default='')

    collection_review = subparsers.add_parser('collection-review', help='Owner approves/denies collection submission.')
    collection_review.add_argument('--owner-public-key', required=True)
    collection_review.add_argument('--submission-id', required=True)
    collection_review.add_argument('--approve', choices=('true', 'false'), required=True)

    collection_fork = subparsers.add_parser('collection-fork', help='Fork/copy an existing collection.')
    collection_fork.add_argument('--forker-public-key', required=True)
    collection_fork.add_argument('--source-collection-id', required=True)
    collection_fork.add_argument('--name', default='')
    collection_fork.add_argument('--description', default='')

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
        profile_options = {}
        worker_controls = {}
        if command.video_quality:
            profile_options['video_quality'] = command.video_quality
        if command.audio_only is not None:
            profile_options['audio_only'] = command.audio_only == 'true'
        if command.include_subtitles is not None:
            profile_options['include_subtitles'] = command.include_subtitles == 'true'
        if command.include_thumbnail is not None:
            profile_options['include_thumbnail'] = command.include_thumbnail == 'true'
        if command.playlist is not None:
            profile_options['playlist'] = command.playlist == 'true'
        if command.format:
            profile_options['format'] = command.format
        if command.gallery_max_items is not None:
            profile_options['gallery_max_items'] = command.gallery_max_items
        if command.cookies_from_browser:
            profile_options['cookies_from_browser'] = command.cookies_from_browser

        if command.max_retries is not None:
            worker_controls['max_retries'] = command.max_retries
        if command.retry_backoff_seconds is not None:
            worker_controls['retry_backoff_seconds'] = command.retry_backoff_seconds
        if command.sleep_interval_seconds is not None:
            worker_controls['sleep_interval_seconds'] = command.sleep_interval_seconds
        if command.max_concurrent_downloads is not None:
            worker_controls['max_concurrent_downloads'] = command.max_concurrent_downloads

        request = network.submit_request(
            requester_public_key=command.public_key,
            url=command.url,
            archive_mode=command.mode,
            country_preference=command.country_preference,
            download_profile=command.download_profile,
            profile_options=profile_options or None,
            worker_controls=worker_controls or None,
        )
        print(json.dumps(request, indent=2, sort_keys=True))
        return

    if command.action == 'list-open':
        requests = network.list_open_requests(worker_public_key=command.worker_public_key or None)
        print(json.dumps(requests, indent=2, sort_keys=True))
        return

    if command.action == 'request-candidates':
        candidates = network.get_request_candidates(
            worker_public_key=command.public_key,
            limit=max(command.limit, 1),
        )
        print(json.dumps(candidates, indent=2, sort_keys=True))
        return

    if command.action == 'settings-network-get':
        settings = network.get_network_settings(command.public_key)
        print(json.dumps(settings, indent=2, sort_keys=True))
        return

    if command.action == 'settings-network-update':
        settings = network.update_network_settings(
            public_key=command.public_key,
            max_jobs_per_day=command.max_jobs_per_day,
            max_storage_gb_per_day=command.max_storage_gb_per_day,
            max_upload_gb_per_day=command.max_upload_gb_per_day,
            max_download_gb_per_day=command.max_download_gb_per_day,
            daily_upload_speed_mbps=command.daily_upload_speed_mbps,
            daily_download_speed_mbps=command.daily_download_speed_mbps,
        )
        print(json.dumps(settings, indent=2, sort_keys=True))
        return

    if command.action == 'settings-rules-get':
        rules = network.get_serving_rules(command.public_key)
        print(json.dumps(rules, indent=2, sort_keys=True))
        return

    if command.action == 'settings-rules-update':
        followed_public_keys = command.followed_public_key if command.followed_public_key else None
        site_blacklist = command.site_blacklist_host if command.site_blacklist_host else None
        rules = network.update_serving_rules(
            public_key=command.public_key,
            block_porn_links=None if command.block_porn_links is None else command.block_porn_links == 'true',
            min_ratio_to_serve=command.min_ratio_to_serve,
            prioritize_high_ratio_first=None if command.prioritize_high_ratio_first is None else command.prioritize_high_ratio_first == 'true',
            prioritize_followed_first=None if command.prioritize_followed_first is None else command.prioritize_followed_first == 'true',
            followed_public_keys=followed_public_keys,
            site_blacklist=site_blacklist,
            rules_md=command.rules_md,
        )
        print(json.dumps(rules, indent=2, sort_keys=True))
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

    if command.action == 'collection-create':
        collection = network.create_collection(
            owner_public_key=command.owner_public_key,
            name=command.name,
            description=command.description,
            is_private=command.private == 'true',
            allow_submissions=command.allow_submissions == 'true',
        )
        print(json.dumps(collection, indent=2, sort_keys=True))
        return

    if command.action == 'collection-update':
        collection = network.update_collection(
            owner_public_key=command.owner_public_key,
            collection_id=command.collection_id,
            name=command.name,
            description=command.description,
            is_private=None if command.private is None else command.private == 'true',
            allow_submissions=None if command.allow_submissions is None else command.allow_submissions == 'true',
        )
        print(json.dumps(collection, indent=2, sort_keys=True))
        return

    if command.action == 'collection-delete':
        network.delete_collection(
            owner_public_key=command.owner_public_key,
            collection_id=command.collection_id,
        )
        print(json.dumps({'ok': True}, indent=2))
        return

    if command.action == 'collection-get':
        collection = network.get_collection(
            collection_id=command.collection_id,
            viewer_public_key=command.viewer_public_key or None,
        )
        print(json.dumps(collection, indent=2, sort_keys=True))
        return

    if command.action == 'collection-list':
        collections = network.list_collections(
            viewer_public_key=command.viewer_public_key or None,
            owner_public_key=command.owner_public_key or None,
        )
        print(json.dumps(collections, indent=2, sort_keys=True))
        return

    if command.action == 'collection-add-archive':
        collection = network.add_archive_to_collection(
            owner_public_key=command.owner_public_key,
            collection_id=command.collection_id,
            archive_id=command.archive_id,
        )
        print(json.dumps(collection, indent=2, sort_keys=True))
        return

    if command.action == 'collection-submit':
        submission = network.submit_collection_entry(
            submitter_public_key=command.submitter_public_key,
            collection_id=command.collection_id,
            archive_id=command.archive_id,
            note=command.note,
        )
        print(json.dumps(submission, indent=2, sort_keys=True))
        return

    if command.action == 'collection-review':
        submission = network.review_collection_submission(
            owner_public_key=command.owner_public_key,
            submission_id=command.submission_id,
            approve=command.approve == 'true',
        )
        print(json.dumps(submission, indent=2, sort_keys=True))
        return

    if command.action == 'collection-fork':
        fork = network.fork_collection(
            forker_public_key=command.forker_public_key,
            source_collection_id=command.source_collection_id,
            name=command.name or None,
            description=command.description if command.description else None,
        )
        print(json.dumps(fork, indent=2, sort_keys=True))
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
