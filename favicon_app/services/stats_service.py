# -*- coding: utf-8 -*-

import asyncio
import hashlib
import ipaddress
import json
import logging
import os
import re
import shutil
import uuid
from collections import Counter
from typing import Optional
from urllib.parse import urlsplit

import setting
from favicon_app.utils.file_util import FileUtil

logger = logging.getLogger(__name__)

_safe_boot_id = re.compile(r'[^a-zA-Z0-9_-]')
_domain_label = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$', re.I)
_sources: Counter[str] = Counter()
_targets: Counter[str] = Counter()
_source_total = 0
_target_total = 0
_snapshot_task: Optional[asyncio.Task] = None
_snapshot_file: Optional[str] = None
_snapshot_lock = asyncio.Lock()
_provider_snapshot_lock = asyncio.Lock()
_worker_pid: Optional[int] = None
_worker_id: Optional[str] = None

_PROVIDER_SNAPSHOT_FIELD_NAMES = {
    'field_names': '字段名称说明',
    'boot_id': '服务启动批次 ID',
    'worker_id': 'Worker 唯一 ID',
    'worker_pid': 'Worker 进程 ID',
    'generated_at_unix': '快照生成时间（Unix 时间戳）',
    'provider_count': '三方源数量',
    'providers': '三方源状态列表',
    'index': 'FAVICON_APIS 配置基准索引',
    'key': '三方源内部状态键',
    'name': '三方源名称',
    'template': '三方源 URL 模板',
    'selection_score': '调度评分（0 到 1）',
    'selection_weight': '选择权重（非归一化，实际选择仍包含随机探索）',
    'samples': '已计入评分的请求样本数',
    'valid_hits': '取得有效且非占位图标的次数',
    'target_misses': '当前目标未取得有效图标但三方源未判定故障的次数',
    'provider_failures': '三方源网络、限流、拒绝或异常 HTTP 故障次数',
    'latency_ewma_seconds': '第三方响应延迟 EWMA（秒）',
    'circuit': '熔断状态（closed、open 或 half_open）',
    'eligible': '当前是否可进入候选列表',
    'consecutive_failures': '尚未触发熔断的连续故障次数',
    'open_count': '连续熔断轮次',
    'open_remaining_seconds': '当前熔断剩余秒数',
    'half_open_active': '是否已有半开探测正在执行',
}


def normalize_origin(value: Optional[str]) -> Optional[str]:
    """Return a display-safe HTTP origin with default ports removed."""
    if not value or not isinstance(value, str):
        return None
    try:
        parsed = urlsplit(value.strip())
        scheme = parsed.scheme.lower()
        if scheme not in ('http', 'https') or not parsed.hostname:
            return None
        host = parsed.hostname.rstrip('.').encode('idna').decode('ascii').lower()
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if len(host) > 253 or any(not _domain_label.fullmatch(label) for label in host.split('.')):
                return None
        port = parsed.port
        if port == (80 if scheme == 'http' else 443):
            port = None
        display_host = f'[{host}]' if ':' in host else host
        netloc = f'{display_host}:{port}' if port is not None else display_host
        return f'{scheme}://{netloc}'
    except (UnicodeError, ValueError):
        return None


def _increment(counter: Counter[str], key: str) -> None:
    counter[key] += 1
    limit = max(setting.STATS_TOP_LIMIT, setting.STATS_MAX_ITEMS)
    if len(counter) > limit * 2:
        retained = counter.most_common(limit)
        counter.clear()
        counter.update(dict(retained))


def record_request(target: str, source: Optional[str] = None) -> None:
    """Record one validated favicon API request without performing I/O."""
    global _source_total, _target_total
    target_origin = normalize_origin(target)
    if not target_origin:
        return

    _increment(_targets, target_origin)
    _target_total += 1

    source_origin = normalize_origin(source)
    if source_origin:
        _increment(_sources, source_origin)
        _source_total += 1


def _current_boot_id() -> str:
    return _safe_boot_id.sub('_', setting.STATS_BOOT_ID)[:128] or 'default'


def _boot_file_token() -> str:
    """Return a short, collision-resistant token for the current boot batch."""
    return hashlib.sha256(
        _current_boot_id().encode('utf-8'),
    ).hexdigest()[:10]


def _worker_file_token() -> str:
    worker_id = _worker_id or f'{os.getpid()}-uninitialized'
    pid, separator, unique_id = worker_id.partition('-')
    if separator and unique_id:
        return f'{pid}-{unique_id[:8]}'
    return worker_id[:20]


def _runtime_stats_directory() -> str:
    return os.path.join(setting.icon_root_path, 'data', 'runtime_stats')


def _boot_directory() -> str:
    return os.path.join(_runtime_stats_directory(), _current_boot_id())


def provider_snapshot_path() -> str:
    filename = f'{_boot_file_token()}-{_worker_file_token()}.json'
    return os.path.join(_runtime_stats_directory(), 'providers', filename)


def _remove_runtime_entry(path: str, is_directory: bool) -> None:
    try:
        if is_directory:
            shutil.rmtree(path)
        else:
            os.remove(path)
    except FileNotFoundError:
        pass
    except OSError as exc:
        logger.warning('Failed to remove expired runtime stats %s: %s', path, exc)


def _cleanup_runtime_stats() -> None:
    """Remove snapshots that do not belong to the current service boot."""
    root = _runtime_stats_directory()
    current_boot_id = _current_boot_id()
    try:
        entries = list(os.scandir(root))
    except FileNotFoundError:
        return
    except OSError as exc:
        logger.warning('Failed to scan runtime stats directory %s: %s', root, exc)
        return

    for entry in entries:
        if entry.name in (current_boot_id, 'providers'):
            continue
        _remove_runtime_entry(
            entry.path,
            entry.is_dir(follow_symlinks=False),
        )

    providers_directory = os.path.join(root, 'providers')
    current_prefix = f'{_boot_file_token()}-'
    current_temp_prefix = f'.{current_prefix}'
    try:
        provider_entries = list(os.scandir(providers_directory))
    except FileNotFoundError:
        return
    except OSError as exc:
        logger.warning(
            'Failed to scan provider snapshots directory %s: %s',
            providers_directory,
            exc,
        )
        return

    for entry in provider_entries:
        if entry.name.startswith((current_prefix, current_temp_prefix)):
            continue
        _remove_runtime_entry(
            entry.path,
            entry.is_dir(follow_symlinks=False),
        )


def _snapshot_payload() -> dict:
    snapshot_limit = max(setting.STATS_TOP_LIMIT, setting.STATS_SNAPSHOT_ITEMS)
    return {
        'started_at': setting.STATS_STARTED_AT,
        'source_total': _source_total,
        'target_total': _target_total,
        'sources': dict(_sources.most_common(snapshot_limit)),
        'targets': dict(_targets.most_common(snapshot_limit)),
    }


def _write_snapshot(path: str, payload: dict) -> None:
    content = json.dumps(payload, ensure_ascii=True, separators=(',', ':'))
    if not FileUtil.write_file(path, content, atomic=True):
        logger.warning('Failed to write ranking snapshot: %s', path)


def _write_provider_snapshot(path: str, payload: dict) -> bool:
    document = {
        'field_names': _PROVIDER_SNAPSHOT_FIELD_NAMES,
        'boot_id': _current_boot_id(),
        'worker_id': _worker_id or f'{os.getpid()}-uninitialized',
        'worker_pid': os.getpid(),
        **payload,
    }
    content = json.dumps(document, ensure_ascii=False, indent=2, allow_nan=False)
    if not FileUtil.write_file(path, content, atomic=True):
        logger.warning('Failed to write provider snapshot: %s', path)
        return False
    return True


async def write_provider_snapshot(payload: dict) -> bool:
    """Atomically overwrite this worker's current provider snapshot."""
    async with _provider_snapshot_lock:
        write_task = asyncio.create_task(asyncio.to_thread(
            _cleanup_and_write_provider_snapshot,
            provider_snapshot_path(), payload,
        ))
        try:
            return await asyncio.shield(write_task)
        except asyncio.CancelledError:
            await write_task
            raise


def _cleanup_and_write_provider_snapshot(path: str, payload: dict) -> bool:
    _cleanup_runtime_stats()
    return _write_provider_snapshot(path, payload)


async def flush_snapshot() -> None:
    if not _snapshot_file:
        return
    async with _snapshot_lock:
        write_task = asyncio.create_task(asyncio.to_thread(
            _write_snapshot,
            _snapshot_file,
            _snapshot_payload(),
        ))
        try:
            await asyncio.shield(write_task)
        except asyncio.CancelledError:
            await write_task
            raise


async def _snapshot_loop() -> None:
    while True:
        await asyncio.sleep(max(0.1, setting.STATS_SNAPSHOT_INTERVAL))
        await flush_snapshot()


async def start_stats() -> None:
    global _source_total, _target_total, _snapshot_file, _snapshot_task, _worker_pid, _worker_id
    if _snapshot_task is not None:
        return
    _sources.clear()
    _targets.clear()
    _source_total = 0
    _target_total = 0
    current_pid = os.getpid()
    if _worker_pid != current_pid or not _worker_id:
        _worker_pid = current_pid
        _worker_id = f'{current_pid}-{uuid.uuid4().hex}'
    await asyncio.to_thread(_cleanup_runtime_stats)
    _snapshot_file = os.path.join(_boot_directory(), f'{_worker_id}.json')
    await flush_snapshot()
    _snapshot_task = asyncio.create_task(_snapshot_loop())


async def stop_stats() -> None:
    global _snapshot_file, _snapshot_task
    task = _snapshot_task
    if task is None:
        return
    _snapshot_task = None
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    await flush_snapshot()
    _snapshot_file = None


def _read_aggregate(directory: str) -> dict:
    sources: Counter[str] = Counter()
    targets: Counter[str] = Counter()
    source_total = 0
    target_total = 0
    try:
        entries = list(os.scandir(directory))
    except OSError:
        entries = []

    for entry in entries:
        if not entry.is_file() or not entry.name.endswith('.json'):
            continue
        try:
            if entry.stat().st_size > 2 * 1024 * 1024:
                continue
            with open(entry.path, 'r', encoding='utf-8') as file:
                payload = json.load(file)
            source_total += max(0, int(payload.get('source_total', 0)))
            target_total += max(0, int(payload.get('target_total', 0)))
            sources.update({str(key): int(value) for key, value in payload.get('sources', {}).items()})
            targets.update({str(key): int(value) for key, value in payload.get('targets', {}).items()})
        except (AttributeError, OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            logger.warning('Ignoring invalid ranking snapshot %s: %s', entry.path, exc)

    limit = max(1, setting.STATS_TOP_LIMIT)

    def ranked(counter: Counter[str]) -> list[dict[str, object]]:
        values = sorted(counter.items(), key=lambda item: (-item[1], item[0]))[:limit]
        return [{'url': url, 'count': count} for url, count in values]

    return {
        'started_at': setting.STATS_STARTED_AT,
        'total_source_requests': source_total,
        'total_target_requests': target_total,
        'sources': ranked(sources),
        'targets': ranked(targets),
    }


async def get_stats() -> dict:
    await flush_snapshot()
    return await asyncio.to_thread(_read_aggregate, _boot_directory())
