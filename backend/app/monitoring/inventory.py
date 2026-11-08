"""File inventory walking, streaming SHA-256 hashing and change detection.

This module is pure logic over a :class:`FileSource`; persistence lives in
``app.monitoring.file_scan``.

Correctness rules implemented here:

* A path is reported **deleted** only when its nearest surviving ancestor
  directory was listed completely in the current scan. Paths beneath a
  directory that failed to list, or that was not reached because a limit was
  hit, are reported as *unverified*, never as deleted.
* Symmetrically, a path is reported **added** only when its nearest ancestor
  in the previous snapshot had been listed completely; otherwise it is merely
  *first observed*.
* If the root listing fails the scan is *failed* and no comparison is made.
* If the root unexpectedly lists as empty while the previous snapshot had
  many files, the scan is downgraded to *partial* and deletions are withheld
  pending human review.
"""

from __future__ import annotations

import fnmatch
import hashlib
import posixpath
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime

from app.connectors.base import ConnectorError, FileSource, join_rel

ROOT = "."

DEFAULT_EXCLUSIONS = [
    ".cache/**",
    ".trash/**",
    "tmp/**",
    "**/node_modules/.cache/**",
]

# Directory statuses recorded in snapshot entries (hash_status column).
DIR_LISTED = "listed"
DIR_LIST_FAILED = "list_failed"
DIR_NOT_VISITED = "not_visited"


@dataclass
class ScanLimits:
    max_file_bytes: int
    max_total_bytes: int
    max_files: int
    max_seconds: int
    max_depth: int


@dataclass
class EntryRecord:
    path: str
    entry_type: str
    size: int | None = None
    mtime: datetime | None = None
    mode: int | None = None
    sha256: str | None = None
    hash_status: str = "not_applicable"
    symlink_target: str | None = None


@dataclass
class ScanErrorRecord:
    path: str
    error_type: str
    message: str
    is_directory: bool


@dataclass
class InventoryResult:
    status: str  # completed | partial | failed
    entries: dict[str, EntryRecord] = field(default_factory=dict)
    errors: list[ScanErrorRecord] = field(default_factory=list)
    limits_hit: set[str] = field(default_factory=set)
    files_seen: int = 0
    dirs_seen: int = 0
    files_hashed: int = 0
    files_not_hashed: int = 0
    bytes_hashed: int = 0
    failure_reason: str | None = None


class ScanCancelled(Exception):
    pass


def matches_any(path: str, patterns: list[str], is_dir: bool = False) -> bool:
    candidates = [path]
    if is_dir:
        candidates.append(path + "/")
    for pat in patterns:
        pat = pat.strip().lstrip("/")
        if not pat:
            continue
        for c in candidates:
            if fnmatch.fnmatchcase(c, pat):
                return True
            # "dir/**" should also exclude the directory itself
            if pat.endswith("/**") and (c == pat[:-3] or c.rstrip("/") == pat[:-3]):
                return True
            if pat.startswith("**/") and fnmatch.fnmatchcase(c, pat[3:]):
                return True
    return False


def hash_stream(chunks) -> tuple[str, int]:
    h = hashlib.sha256()
    n = 0
    for chunk in chunks:
        h.update(chunk)
        n += len(chunk)
    return h.hexdigest(), n


def walk_inventory(
    source: FileSource,
    exclusions: list[str],
    limits: ScanLimits,
    progress: Callable[[InventoryResult], None] | None = None,
    hash_files: bool = True,
) -> InventoryResult:
    result = InventoryResult(status="completed")
    started = time.monotonic()
    budget = limits.max_total_bytes
    queue: deque[tuple[str, int]] = deque([(ROOT, 0)])
    result.entries[ROOT] = EntryRecord(path=ROOT, entry_type="dir", hash_status=DIR_NOT_VISITED)
    stopped = False
    processed = 0

    while queue:
        rel_dir, depth = queue.popleft()
        if stopped:
            result.entries[rel_dir].hash_status = DIR_NOT_VISITED
            continue
        if time.monotonic() - started > limits.max_seconds:
            result.limits_hit.add("time")
            stopped = True
            result.entries[rel_dir].hash_status = DIR_NOT_VISITED
            continue
        try:
            children = source.list_dir(rel_dir)
        except ConnectorError as exc:
            result.entries[rel_dir].hash_status = DIR_LIST_FAILED
            result.errors.append(ScanErrorRecord(rel_dir, exc.code, exc.message, True))
            if rel_dir == ROOT:
                result.status = "failed"
                result.failure_reason = exc.message
                return result
            continue
        result.entries[rel_dir].hash_status = DIR_LISTED
        result.dirs_seen += 1

        for child in sorted(children, key=lambda c: c.name):
            try:
                rel = join_rel("" if rel_dir == ROOT else rel_dir, child.name)
            except ConnectorError as exc:
                result.errors.append(ScanErrorRecord(rel_dir, exc.code, exc.message, False))
                continue
            if matches_any(rel, exclusions, is_dir=child.entry_type == "dir"):
                continue
            if child.entry_type == "dir":
                rec = EntryRecord(rel, "dir", mtime=child.mtime, mode=child.mode, hash_status=DIR_NOT_VISITED)
                result.entries[rel] = rec
                if depth + 1 > limits.max_depth:
                    result.limits_hit.add("depth")
                    result.errors.append(ScanErrorRecord(rel, "limit", "Maximum directory depth reached.", True))
                else:
                    queue.append((rel, depth + 1))
                continue
            if result.files_seen >= limits.max_files:
                result.limits_hit.add("file_count")
                stopped = True
                # The current directory is now only partly enumerated.
                result.entries[rel_dir].hash_status = DIR_NOT_VISITED
                break
            result.files_seen += 1
            rec = EntryRecord(rel, child.entry_type, size=child.size, mtime=child.mtime, mode=child.mode)
            if child.entry_type == "symlink":
                rec.symlink_target = source.readlink(rel)
                rec.hash_status = "not_applicable"
            elif child.entry_type == "file":
                if not hash_files:
                    rec.hash_status = "metadata_only"
                    result.files_not_hashed += 1
                elif child.size is not None and child.size > limits.max_file_bytes:
                    rec.hash_status = "skipped_size"
                    result.files_not_hashed += 1
                    result.limits_hit.add("file_size")
                elif child.size is not None and child.size > budget:
                    rec.hash_status = "skipped_budget"
                    result.files_not_hashed += 1
                    result.limits_hit.add("total_bytes")
                else:
                    try:
                        digest, n = hash_stream(source.read_chunks(rel))
                        rec.sha256 = digest
                        rec.hash_status = "hashed"
                        rec.size = n if rec.size is None else rec.size
                        budget -= n
                        result.bytes_hashed += n
                        result.files_hashed += 1
                    except ConnectorError as exc:
                        rec.hash_status = "error"
                        result.files_not_hashed += 1
                        result.errors.append(ScanErrorRecord(rel, exc.code, exc.message, False))
            result.entries[rel] = rec
            processed += 1
            if progress and processed % 200 == 0:
                progress(result)

    if result.errors or result.limits_hit & {"file_count", "time", "depth"} or any(e.entry_type == "dir" and e.hash_status != DIR_LISTED for e in result.entries.values()):
        result.status = "partial"
    return result


# --------------------------------------------------------------------------
# Change detection
# --------------------------------------------------------------------------


@dataclass
class PrevEntry:
    entry_type: str
    size: int | None
    mtime: datetime | None
    sha256: str | None
    hash_status: str
    symlink_target: str | None = None
    mode: int | None = None


@dataclass
class Change:
    path: str
    change_type: str  # added | modified | deleted | renamed | metadata_changed | type_changed
    entry_type: str
    old: PrevEntry | None
    new: EntryRecord | None
    confidence: str = "high"
    old_path: str | None = None
    flags: list[str] = field(default_factory=list)
    severity: str = "low"


@dataclass
class DiffResult:
    changes: list[Change] = field(default_factory=list)
    unverified_missing: list[str] = field(default_factory=list)
    first_observed: list[str] = field(default_factory=list)
    withheld_reason: str | None = None


def _parent(path: str) -> str:
    parent = posixpath.dirname(path)
    return parent or ROOT


def _nearest_present_ancestor(path: str, entries: dict) -> str | None:
    p = path
    while p != ROOT:
        p = _parent(p)
        if p in entries:
            return p
    return ROOT if ROOT in entries else None


def _dir_listed(path: str | None, entries: dict) -> bool:
    if path is None:
        return False
    e = entries.get(path)
    return e is not None and e.entry_type == "dir" and e.hash_status == DIR_LISTED


def diff_inventories(
    previous: dict[str, PrevEntry],
    current: InventoryResult,
    exclusions: list[str],
) -> DiffResult:
    out = DiffResult()
    cur = current.entries
    if current.status == "failed":
        out.withheld_reason = "scan_failed"
        return out

    prev_files = sum(1 for e in previous.values() if e.entry_type != "dir")
    cur_files = sum(1 for e in cur.values() if e.entry_type != "dir")
    suspicious_empty = prev_files >= 10 and cur_files == 0
    if suspicious_empty:
        out.withheld_reason = "root_unexpectedly_empty"

    added: list[str] = []
    for path, rec in cur.items():
        if path == ROOT:
            continue
        old = previous.get(path)
        if old is None:
            anc = _nearest_present_ancestor(path, previous)
            if _dir_listed(anc, previous):
                added.append(path)
            else:
                out.first_observed.append(path)
            continue
        if old.entry_type != rec.entry_type:
            out.changes.append(Change(path, "type_changed", rec.entry_type, old, rec))
            continue
        if rec.entry_type == "dir":
            continue
        if rec.entry_type == "symlink":
            if (old.symlink_target or "") != (rec.symlink_target or ""):
                out.changes.append(Change(path, "modified", "symlink", old, rec))
            continue
        if old.sha256 and rec.sha256:
            if old.sha256 != rec.sha256:
                out.changes.append(Change(path, "modified", rec.entry_type, old, rec))
            continue
        # At least one side lacks a hash: fall back to metadata, lower confidence.
        if (old.size is not None and rec.size is not None and old.size != rec.size) or (
            old.mtime and rec.mtime and old.mtime != rec.mtime
        ):
            out.changes.append(Change(path, "metadata_changed", rec.entry_type, old, rec, confidence="low"))

    deleted: list[str] = []
    for path, old in previous.items():
        if path == ROOT or path in cur:
            continue
        if matches_any(path, exclusions, is_dir=old.entry_type == "dir"):
            continue
        anc = _nearest_present_ancestor(path, cur)
        if not suspicious_empty and _dir_listed(anc, cur):
            deleted.append(path)
        else:
            out.unverified_missing.append(path)

    # Rename inference: a deleted file and an added file with the same hash and size.
    added_by_hash: dict[str, list[str]] = {}
    for p in added:
        r = cur[p]
        if r.sha256:
            added_by_hash.setdefault(r.sha256, []).append(p)
    renamed_new: set[str] = set()
    remaining_deleted = []
    for p in deleted:
        old = previous[p]
        cands = [c for c in added_by_hash.get(old.sha256 or "", []) if c not in renamed_new] if old.sha256 else []
        if len(cands) == 1 and cur[cands[0]].size == old.size:
            new_path = cands[0]
            renamed_new.add(new_path)
            out.changes.append(Change(new_path, "renamed", cur[new_path].entry_type, old, cur[new_path], old_path=p))
        else:
            remaining_deleted.append(p)

    for p in added:
        if p not in renamed_new:
            out.changes.append(Change(p, "added", cur[p].entry_type, None, cur[p]))
    for p in remaining_deleted:
        out.changes.append(Change(p, "deleted", previous[p].entry_type, previous[p], None))
    out.changes.sort(key=lambda c: c.path)
    return out
