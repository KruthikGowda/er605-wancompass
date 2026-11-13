"""Isolated one-operation candidate trial with a durable independent undo path.

This is an operator API, not a production control or a Telegram write endpoint.
The caller supplies the approved endpoint observation and quiesces other writers.
"""
from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
import json
import math
import os
from pathlib import Path
import stat
import time
import uuid

from netpulse.router.compatibility import (CANDIDATE_FIRMWARE, CompatibilityError,
                                           build_plan, validate_plan)
from netpulse.router.er605 import acl_pilot_effective_match
from netpulse.router.trial_lock import TRIAL_PENDING

MAX_RECORD = 256 * 1024


def boottime():
    if not hasattr(time, "CLOCK_BOOTTIME"):
        raise CompatibilityError("A suspend-aware boot clock is required for live trials.")
    return time.clock_gettime(time.CLOCK_BOOTTIME)


def boot_id():
    return str(uuid.UUID(Path('/proc/sys/kernel/random/boot_id').read_text().strip()))


def required_uid():
    return 0


def private_metadata(info, directory=False):
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    mode = 0o700 if directory else 0o600
    if (not expected(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or (os.name == "posix" and (info.st_uid != required_uid() or stat.S_IMODE(info.st_mode) != mode))
            or (not directory and info.st_nlink != 1)):
        raise CompatibilityError("Trial files must be private, owned regular files/directories.")


class TrialJournal:
    def __init__(self, path, *, clock=boottime, boot=boot_id, marker=TRIAL_PENDING):
        self.path, self.clock, self.boot = Path(path), clock, boot
        self.marker = Path(marker)

    def _directory(self):
        private_metadata(self.path.parent.lstat(), directory=True)
        status = self.marker.parent.lstat()
        if (not stat.S_ISDIR(status.st_mode) or stat.S_ISLNK(status.st_mode)
                or (os.name == 'posix' and (status.st_uid != required_uid() or status.st_mode & 0o022))):
            raise CompatibilityError("Trial status directory must be owned and not writable by others.")

    @contextmanager
    def locked(self):
        self._directory()
        fd = os.open(self.path.with_suffix('.lock'), os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        try:
            private_metadata(os.fstat(fd))
            if os.name == 'posix':
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def arm(self, plan, seconds, restart_service=False, mode='live'):
        preparation = isinstance(plan,dict) and plan.get('kind') == 'preparation'
        if preparation:
            from netpulse.router.preparation import validate_preparation
            validate_preparation(plan)
        else:
            validate_plan(plan)
        if type(seconds) is not int or not 1 <= seconds <= 600:
            raise CompatibilityError("Trial deadline must be 1–600 seconds.")
        if type(restart_service) is not bool:
            raise CompatibilityError("Invalid service restoration intent.")
        if mode not in {'live', 'rehearsal'}:
            raise CompatibilityError("Unrecognized recovery mode.")
        self._directory()
        start = self.clock()
        record = {'version': 1, 'mode': mode, 'nonce': str(uuid.uuid4()), 'boot': self.boot(),
                  'created': start, 'deadline': start + seconds, 'owner_pid': os.getpid(),
                  'restart_service': restart_service, 'plan': deepcopy(plan)}
        if preparation:
            record.update(version=2,receipts=[],inflight=None)
        self._validate(record)
        payload = json.dumps(record, allow_nan=False).encode()
        if len(payload) > MAX_RECORD:
            raise CompatibilityError("Trial journal exceeds its bounded size.")
        with self.locked():
            if self.path.exists() or self.marker.exists():
                raise CompatibilityError("An earlier trial requires recovery or manual review.")
            fd = os.open(self.marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
            with os.fdopen(fd, 'w') as stream:
                stream.write(record['nonce']); stream.flush(); os.fsync(stream.fileno())
            self._sync_directory()
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(payload); stream.flush(); os.fsync(stream.fileno())
            self._sync_directory()
        return record

    def _validate(self, record):
        keys = {'version', 'mode', 'nonce', 'boot', 'created', 'deadline', 'owner_pid', 'restart_service', 'plan'}
        preparation = isinstance(record,dict) and isinstance(record.get('plan'),dict) and record['plan'].get('kind') == 'preparation'
        if preparation: keys.update({'receipts','inflight'})
        if not isinstance(record, dict) or set(record) != keys or type(record['version']) is not int or record['version'] != (2 if preparation else 1):
            raise CompatibilityError("Unrecognized trial journal format.")
        if record['mode'] not in {'live', 'rehearsal'}:
            raise CompatibilityError("Unrecognized recovery mode.")
        for key in ('nonce', 'boot'):
            if not isinstance(record[key], str) or str(uuid.UUID(record[key])) != record[key]:
                raise CompatibilityError("Invalid trial journal identity.")
        if (any(type(record[k]) not in (int, float) or not math.isfinite(record[k]) or record[k] < 0
                for k in ('created', 'deadline')) or not 0 < record['deadline'] - record['created'] <= 600
                or type(record['owner_pid']) is not int or record['owner_pid'] < 1
                or type(record['restart_service']) is not bool):
            raise CompatibilityError("Invalid trial deadline or owner.")
        if preparation:
            from netpulse.router.preparation import validate_progress
            validate_progress(record)
        else:
            validate_plan(record['plan'])
        return record

    def replace(self, updated, expected):
        """Durably advance preparation intent/receipts; caller holds locked()."""
        self._validate(updated)
        if self.read() != expected or expected['version'] != 2 or updated['version'] != 2:
            raise CompatibilityError('Preparation generation changed during journal update.')
        mutable = {'receipts','inflight'}
        if any(updated[k] != expected[k] for k in expected if k not in mutable):
            raise CompatibilityError('Immutable preparation approval/deadline changed.')
        old, new = expected['receipts'], updated['receipts']
        if len(new) not in {len(old),len(old)+1} or new[:len(old)] != old:
            raise CompatibilityError('Preparation receipts must be append-only.')
        previous = expected['inflight']
        if previous is not None and (updated['inflight'] is None or not previous <= updated['inflight'] <= previous+1):
            raise CompatibilityError('Preparation intent cannot move backward or skip writes.')
        payload = json.dumps(updated,allow_nan=False).encode()
        if len(payload)>MAX_RECORD: raise CompatibilityError('Preparation journal exceeds its size limit.')
        temp = self.path.with_name('.journal-update-'+str(uuid.uuid4()))
        fd = os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
        try:
            with os.fdopen(fd,'wb') as stream:
                stream.write(payload);stream.flush();os.fsync(stream.fileno())
            os.replace(temp,self.path);self._sync_directory()
        finally: temp.unlink(missing_ok=True)

    def read(self):
        self._directory()
        try:
            original = self.path.lstat()
        except FileNotFoundError:
            return None
        private_metadata(original)
        fd = os.open(self.path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        with os.fdopen(fd, 'rb') as stream:
            opened = os.fstat(stream.fileno()); private_metadata(opened)
            if (original.st_ino, original.st_dev) != (opened.st_ino, opened.st_dev):
                raise CompatibilityError("Trial journal changed during open.")
            payload = stream.read(MAX_RECORD + 1)
        if len(payload) > MAX_RECORD:
            raise CompatibilityError("Trial journal exceeds its bounded size.")
        def unique(pairs):
            out = {}
            for key, value in pairs:
                if key in out:
                    raise CompatibilityError("Duplicate JSON fields in trial journal.")
                out[key] = value
            return out
        return self._validate(json.loads(payload, object_pairs_hook=unique))

    def _sync_directory(self):
        if os.name == 'posix':
            for directory in {self.path.parent, self.marker.parent}:
                fd = os.open(directory, os.O_RDONLY)
                try: os.fsync(fd)
                finally: os.close(fd)

    def clear(self, nonce):
        current = self.read()
        if current is not None and current['nonce'] != nonce:
            raise CompatibilityError("Recovery journal identity changed.")
        private_metadata(self.marker.lstat())
        if self.marker.read_text() != nonce:
            raise CompatibilityError("Recovery marker identity changed; manual review is required.")
        self.path.unlink(missing_ok=True)
        try:
            self.marker.unlink()
        except OSError:
            # Keep the exact undo record if status-marker removal fails. This
            # also covers an incorrectly staged sandbox/filesystem permission.
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
            with os.fdopen(fd, 'w') as stream:
                json.dump(current, stream); stream.flush(); os.fsync(stream.fileno())
            self._sync_directory()
            raise
        ready = self.path.with_suffix('.ready')
        if ready.exists():
            private_metadata(ready.lstat())
            if ready.read_text() == nonce:
                ready.unlink()
        self._sync_directory()

    def due(self, record, pid_alive):
        # Changed boot or clock rollback forces recovery; wall-clock changes are irrelevant.
        now = self.clock()
        return (self.boot() != record['boot'] or now < record['created'] or now >= record['deadline']
                or not pid_alive(record['owner_pid']))


def rows_equal(a, b):
    return ([{k: v for k, v in row.items() if k != 'index'} for row in a] ==
            [{k: v for k, v in row.items() if k != 'index'} for row in b])


def assert_identity(snapshot, plan):
    before = plan['before']
    if any(snapshot.get(k) != before[k] for k in ('router_host', 'cert_sha256', 'model', 'hardware_version', 'firmware_version')):
        raise CompatibilityError("Router identity/build changed; manual recovery review required.")


def expected_collections(plan):
    before = plan['before']; expected = deepcopy(before)
    if plan['approval']['action'] == 'pause':
        expected['acls'] = [plan['change']]
    else:
        expected['routes'] = [plan['change'] if r.get('name') == plan['change']['name'] else r
                              for r in before['routes']]
    return expected


def assert_collections(actual, expected):
    for key in ('routes', 'ipscopes', 'ipgroups', 'reservations'):
        if not rows_equal(actual[key], expected[key]):
            raise CompatibilityError("Router objects differ from the reviewed transaction.")
    if not rows_equal(actual['acls'], expected['acls']):
        # ACL firmware display normalization is already narrowly vetted by the parser.
        if not (len(actual['acls']) == len(expected['acls']) == 1
                and acl_pilot_effective_match(actual['acls'][0], expected['acls'][0])):
            raise CompatibilityError("ACL state differs from the reviewed transaction.")


def recover(journal, adapter, *, after_restore=None, expected_nonce=None):
    """Exact owned-object undo, independent of new-action flags and Telegram.

    Caller holds no normal control locks. A dedicated journal lock serializes
    the trial transaction and watchdog. Failure deliberately leaves the journal.
    """
    with journal.locked():
        record = journal.read()
        if record is None:
            if journal.marker.exists():
                raise CompatibilityError("Orphan recovery marker requires manual review.")
            return
        if expected_nonce is not None and record['nonce'] != expected_nonce:
            raise CompatibilityError("Recovery generation changed; no object will be touched.")
        plan = record['plan']
        with adapter.transaction():
            current = adapter.snapshot()
            assert_identity(current, plan)
            if plan.get('kind') == 'preparation':
                from netpulse.router.preparation import restore_preparation
                restore_preparation(journal,record,adapter,current)
            else:
                adapter.restore(plan, current)
            restored = adapter.snapshot()
            assert_identity(restored, plan)
            if plan.get('kind') == 'preparation':
                from netpulse.router.preparation import assert_preparation_collections
                assert_preparation_collections(restored,plan['before'])
            else:
                assert_collections(restored, plan['before'])
        if after_restore is not None:
            after_restore()
        journal.clear(record['nonce'])


def run_trial(plan, journal, adapter, watchdog, observe, *, seconds=60):
    """Always undo after one bounded experiment; never mark a feature accepted.

    `watchdog.start(journal, record)` must acknowledge an independent process.
    `observe` is an operator-supplied, approved endpoint probe, not a Pi probe.
    """
    validate_plan(plan)
    if not callable(observe):
        raise CompatibilityError("A reviewed endpoint observer is required before any write.")
    if type(seconds) is not int or not 1 <= seconds <= 60:
        raise CompatibilityError("One disruptive trial operation must be bounded to at most 60 seconds.")
    was_active = adapter.monitor_active()
    record = journal.arm(plan, seconds, restart_service=was_active)
    failure = None
    try:
        if watchdog.start(journal, record) is not True:
            # No mutation was attempted. Cancel this exact generation without
            # requiring a router session while normal monitoring is still active.
            with journal.locked():
                if journal.read() == record:
                    journal.clear(record['nonce'])
            raise CompatibilityError("Independent watchdog did not acknowledge readiness.")
        adapter.quiesce()
        with journal.locked():
            if journal.read() != record or journal.due(record, lambda pid: True):
                raise CompatibilityError("Trial expired or recovery already started.")
            with adapter.transaction():
                fresh = adapter.snapshot()
                assert_identity(fresh, plan)
                build_plan(fresh, plan['approval'], acl_name=plan['change'].get('name'))
                assert_collections(fresh, plan['before'])
                if journal.due(record, lambda pid: True):
                    raise CompatibilityError("Trial expired during fresh preflight.")
                adapter.apply(plan)
                applied = adapter.snapshot()
                assert_identity(applied, plan)
                assert_collections(applied, expected_collections(plan))
        result = observe(deepcopy(plan))
        if journal.due(record, lambda pid: True) or journal.read() != record:
            raise CompatibilityError("Endpoint observation exceeded its trial window.")
        if not isinstance(result, dict) or result.get('lan_ok') is not True:
            raise CompatibilityError("Endpoint LAN observation failed.")
        if plan['approval']['action'] == 'pause':
            passed = result.get('internet_ipv4_ok') is False and result.get('established_blocked') is True
        else:
            passed = (result.get('egress_wan') == plan['approval']['wan'] and result.get('old_wan_leak') is False
                      and result.get('established_checked') is True)
        if not passed:
            raise CompatibilityError("Endpoint enforcement observation failed.")
    except BaseException as exc:
        failure = exc
    finally:
        resume_attempted = False
        def resume_monitor():
            nonlocal resume_attempted
            resume_attempted = True
            adapter.resume()
        try:
            recover(journal, adapter, after_restore=resume_monitor if was_active else None,
                    expected_nonce=record['nonce'])
        finally:
            if was_active and not resume_attempted:
                adapter.resume()
    try:
        recovered = observe(None)
        if not isinstance(recovered, dict) or recovered.get('lan_ok') is not True or recovered.get('internet_ipv4_ok') is not True:
            raise CompatibilityError("Router objects restored but endpoint recovery is unconfirmed.")
    except Exception:
        # An orphan marker intentionally blocks ordinary writes until owner review.
        fd = os.open(journal.marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        with os.fdopen(fd, 'w') as stream:
            stream.write(record['nonce']); stream.flush(); os.fsync(stream.fileno())
        raise
    if failure is not None:
        raise failure
    return {'observation_passed': True, 'objects_restored': True, 'production_enabled': False}
