"""Write-ahead recovery for an isolated endpoint's four temporary prerequisites.

No production capability is enabled. Every preparation run tears its objects
down; it is not a way to retain a reservation or start an unreviewed live trial.
"""
from __future__ import annotations

from copy import deepcopy
import ipaddress

from netpulse.router.compatibility import CompatibilityError, build_plan

COLLECTIONS = ('reservations', 'ipscopes', 'ipgroups', 'routes')
FORMS = (('dhcps', 'reservation'), ('ipgroup', 'ipscope_reservation'),
         ('ipgroup', 'ipgroup_reservation'), ('policy_route', 'policy_route'))


def preparation_plan(before, approval):
    if (not isinstance(approval, dict) or set(approval) != {'confirmed','mac','ip','wan','note'}
            or approval['confirmed'] is not True or not isinstance(approval['note'], str)
            or not approval['note'].startswith('NetPulse: ') or len(approval['note']) > 64
            or any(ord(c) < 32 for c in approval['note'])):
        raise CompatibilityError('Explicit exact endpoint and reservation-note review is required.')
    mac, ip = approval['mac'], approval['ip']
    if not isinstance(mac, str) or not isinstance(ip, str):
        raise CompatibilityError('Invalid endpoint identity.')
    if mac in before.get('preparation_blocked_macs',[]):
        raise CompatibilityError('An existing pause, saved route or Smart WAN intent requires review.')
    suffix = mac.replace('-', '')
    names = ('NP_I_' + suffix, 'NP_G_' + suffix, 'NP_R_' + suffix)
    if any(not isinstance(before.get(k), list) or any(not isinstance(r, dict) for r in before[k])
           for k in COLLECTIONS):
        raise CompatibilityError('Complete prerequisite collections are required.')
    if any(r.get('mac') == mac or r.get('ip') == ip for r in before['reservations']):
        raise CompatibilityError('A reservation already uses this MAC or IP; do not adopt it.')
    if any(any(r.get('name') == n for r in before[k]) for k,n in zip(COLLECTIONS[1:],names)):
        raise CompatibilityError('A prerequisite already exists; do not adopt or overwrite it.')
    if (any(names[0] in r.get('rule_scope', []) for r in before['ipgroups'])
            or any(r.get('src_ipgroup') == names[1] or r.get('dst_ipgroup') == names[1] for r in before['routes'])):
        raise CompatibilityError('Existing objects reference the proposed namespace.')
    try:
        lans = before['lan_scopes']
        matches = [r for r in lans if r.get('name') == 'IP_LAN']
        if len(matches) != 1: raise ValueError
        network = ipaddress.IPv4Network(matches[0]['scope'], strict=False)
        settings = before['lan']
        if isinstance(settings, list):
            if len(settings) != 1: raise ValueError
            settings = settings[0]
        pools = settings['ipRangePool']
        if (len(pools) != 1 or set(pools[0]) != {'start','end'}
                or 'ipaddr_start' in settings or 'ipaddr_end' in settings): raise ValueError
        start, end, address = (ipaddress.IPv4Address(v) for v in (pools[0]['start'], pools[0]['end'], ip))
        if (not start <= address <= end or start not in network or end not in network
                or any(v in (network.network_address, network.broadcast_address) for v in (start,end,address))):
            raise ValueError
    except (KeyError, ValueError, TypeError, AttributeError):
        raise CompatibilityError('A complete unambiguous 2.4.10 IPv4 LAN/pool check is required.') from None
    if any(not str(r.get('index','')).isdigit() for r in before['routes']):
        raise CompatibilityError('Policy-route ordering is unreadable; no preparation can be reviewed.')
    indexes = [int(r['index']) for r in before['routes']]
    index = max(indexes, default=0) + 1
    if index > 64: raise CompatibilityError('The policy-route table has no reviewed free slot.')
    objects = [
        {'ip':ip, 'mac':mac, 'note':approval['note'], 'enable':'on', 'bind':'0', 'interface':'LAN1'},
        {'name':names[0], 'type':'range', 'flag':'user', 'scope':f'{ip}-{ip}',
         'scope_start':ip, 'scope_end':ip, 'comment':'NetPulse'},
        {'name':names[1], 'rule_scope':[names[0]], 'comment':'', 'flag':'user'},
        {'name':names[2], 'service_type':'ALL', 'src_ipgroup':names[1], 'dst_ipgroup':'IPGROUP_ANY',
         'interfaces':approval['wan'], 'timeobj':'Any', 'mode':'Priority', 'comment':'NetPulse',
         'state':'on', 'index':index, 'src':'ipgroup', 'dst':'ipgroup'}]
    virtual = deepcopy(before)
    for key, obj in zip(COLLECTIONS, objects): virtual[key].append(deepcopy(obj))
    # Reuse exact firmware, identity, protection, unique-lease and scope checks.
    build_plan(virtual, {'confirmed':True,'mac':mac,'ip':ip,'action':'pause','wan':approval['wan']},
               acl_name='NP_TEST_P_' + '0' * 32)
    return {'kind':'preparation', 'before':deepcopy(before), 'approval':deepcopy(approval), 'objects':objects}


def validate_preparation(plan):
    if not isinstance(plan, dict) or set(plan) != {'kind','before','approval','objects'} or plan['kind'] != 'preparation':
        raise CompatibilityError('Invalid preparation plan.')
    if plan != preparation_plan(plan['before'], plan['approval']):
        raise CompatibilityError('Preparation objects differ from the exact reviewed plan.')
    return plan


def matches_object(index, observed, proposed):
    """Narrow field matching; only known generated metadata may be extra."""
    if not isinstance(observed, dict): return False
    extras = {'id','key','.name','uniq_id'}
    if index != 3: extras.add('index')
    if index == 0: extras.update({'ip_bind','dhcp_option_bind'})
    if index in {1,2}: extras.update({'.anonymous','.type'})
    if index == 2: extras.add('ref')
    if index == 3: extras.add('t_label')
    if set(observed) - set(proposed) - extras: return False
    if index == 0:
        if observed.get('ip_bind','on') != 'on' or observed.get('dhcp_option_bind','off') != 'off': return False
    if index in {1,2}:
        if '.anonymous' in observed and observed['.anonymous'] is not False: return False
        if observed.get('.type', 'rule_ipscope' if index==1 else 'rule_ipgroup') != ('rule_ipscope' if index==1 else 'rule_ipgroup'): return False
    if index == 2 and 'ref' in observed and not str(observed['ref']).isdigit(): return False
    if index == 3 and observed.get('t_label', {'WAN1':'WAN1','WAN2':'WAN/LAN2'}[proposed['interfaces']]) != {'WAN1':'WAN1','WAN2':'WAN/LAN2'}[proposed['interfaces']]: return False
    for key, value in proposed.items():
        actual = observed.get(key)
        if index == 1 and key in {'scope_start','scope_end'} and key not in observed:
            actual = proposed['scope'].split('-')[0 if key=='scope_start' else 1]
        if index == 2 and key == 'comment' and key not in observed: actual = ''
        if key == 'mac':
            if str(actual).replace(':','-').upper() != value: return False
        elif key in {'enable','state'}:
            if str(actual).lower() not in {'on','1','true'}: return False
        elif key == 'bind':
            if str(actual).lower() not in {'0','false','off'}: return False
        elif actual != value: return False
    if any(type(observed[k]) not in (str,int) or len(str(observed[k])) > 128
           for k in set(observed) - set(proposed) - {'.anonymous'}): return False
    if index == 0 and not str(observed.get('id','')).isdigit(): return False
    return True


def receipt_identity(index,row):
    value = deepcopy(row)
    if index == 0:
        value['mac'] = str(value['mac']).replace(':','-').upper()
        value['enable'] = 'on';value['bind'] = '0'
    if index == 1:
        value.setdefault('scope_start',value['scope'].split('-')[0])
        value.setdefault('scope_end',value['scope'].split('-')[1])
    if index == 2:
        value.pop('ref',None);value.setdefault('comment','')
    value.pop('index',None) if index != 3 else None
    return value


def assert_preparation_collections(actual,expected):
    from netpulse.router.trial import assert_collections
    values = []
    for snapshot in (actual,expected):
        cleaned = deepcopy(snapshot)
        for group in cleaned['ipgroups']:
            if 'ref' in group and not str(group['ref']).isdigit():
                raise CompatibilityError('Unreviewed group-reference metadata.')
            group.pop('ref',None)  # Derived from the routes, which remain compared exactly.
        values.append(cleaned)
    assert_collections(*values)


def validate_progress(record):
    plan = record['plan']; validate_preparation(plan)
    receipts, inflight = record['receipts'], record['inflight']
    if not isinstance(receipts, list) or len(receipts) > 4:
        raise CompatibilityError('Invalid preparation receipt prefix.')
    if inflight is None:
        if receipts: raise CompatibilityError('Receipts have no write-ahead intent.')
    elif type(inflight) is not int or not 0 <= inflight < 4 or inflight not in {len(receipts)-1,len(receipts)}:
        raise CompatibilityError('Invalid preparation write-ahead position.')
    for i, row in enumerate(receipts):
        if not matches_object(i, row, plan['objects'][i]):
            raise CompatibilityError('An object receipt does not match the reviewed operation.')


def inspect_progress(record, snapshot):
    """Return owned rows, refusing unknown edits before any deletion begins."""
    validate_progress(record)
    plan = record['plan']; stripped = deepcopy(snapshot); owned = []
    if plan['approval']['mac'] in snapshot.get('preparation_blocked_macs',[]):
        raise CompatibilityError('A saved endpoint control intent changed during preparation.')
    if snapshot.get('lan') != plan['before']['lan'] or snapshot.get('lan_scopes') != plan['before']['lan_scopes']:
        raise CompatibilityError('LAN or DHCP pool changed; preparation recovery needs review.')
    for i, key in enumerate(COLLECTIONS):
        proposed = plan['objects'][i]
        def identity(row):
            if i == 0:
                return str(row.get('mac','')).replace(':','-').upper() == proposed['mac'] or row.get('ip') == proposed['ip']
            return row.get('name') == proposed['name']
        found = [r for r in snapshot[key] if identity(r)]
        if len(found) > 1: raise CompatibilityError('Duplicate preparation identity requires review.')
        row = found[0] if found else None
        if row is not None:
            if record['inflight'] is None or i > record['inflight']:
                raise CompatibilityError('An unattempted object appeared; never adopt it.')
            if not matches_object(i, row, proposed):
                raise CompatibilityError('An owned preparation object changed; do not delete it.')
            if i < len(record['receipts']) and receipt_identity(i,row) != receipt_identity(i,record['receipts'][i]):
                raise CompatibilityError('Generated object identity/content changed after its receipt.')
        owned.append(row)
        stripped[key] = [r for r in snapshot[key] if not identity(r)]
    assert_preparation_collections(stripped, plan['before'])
    return owned


def restore_preparation(journal, record, adapter, current):
    """Caller holds the shared journal lock and serialized router transaction."""
    from netpulse.router.trial import assert_identity
    assert_identity(current, record['plan'])
    owned = inspect_progress(record, current)
    # After a lost add acknowledgment, capture the exact recovered row and ID
    # durably before deleting it. Missing is already clean; never re-add it.
    index = record['inflight']
    if index is not None and index == len(record['receipts']) and owned[index] is not None:
        updated = deepcopy(record); updated['receipts'].append(deepcopy(owned[index]))
        journal.replace(updated, record); record = updated
    for i in reversed(range(4)):
        current = adapter.snapshot(); assert_identity(current, record['plan'])
        owned = inspect_progress(record, current)
        if owned[i] is not None:
            adapter.delete_preparation_object(i, owned[i])
            after = adapter.snapshot(); assert_identity(after, record['plan'])
            if inspect_progress(record, after)[i] is not None:
                raise CompatibilityError('Preparation deletion was not verified.')


def run_preparation(plan, journal, adapter, watchdog, *, seconds=180):
    """Create all four prerequisites and always tear down; no live probe hook."""
    from netpulse.router.trial import assert_identity, recover, assert_collections
    validate_preparation(plan)
    if type(seconds) is not int or not 1 <= seconds <= 600:
        raise CompatibilityError('Preparation transaction must be bounded to 1–600 seconds.')
    active = adapter.monitor_active(); record = journal.arm(plan,seconds,restart_service=active)
    resume_attempted = False
    def resume():
        nonlocal resume_attempted
        resume_attempted = True; adapter.resume()
    try:
        if watchdog.start(journal,record) is not True:
            with journal.locked():
                if journal.read() == record: journal.clear(record['nonce'])
            raise CompatibilityError('Independent preparation watchdog did not acknowledge readiness.')
        adapter.quiesce()
        for i in range(4):
            with journal.locked():
                latest = journal.read()
                if latest != record or journal.due(record,lambda pid:True):
                    raise CompatibilityError('Preparation expired or recovery already started.')
                with adapter.transaction():
                    snapshot = adapter.snapshot(); assert_identity(snapshot,plan)
                    # Endpoint identity/protection and LAN checks must still pass.
                    clean = deepcopy(snapshot)
                    owned = inspect_progress(record,snapshot)
                    for key,row in zip(COLLECTIONS,owned):
                        if row is not None: clean[key].remove(row)
                    preparation_plan(clean,plan['approval'])
                    if any(owned[j] is None for j in range(i)):
                        raise CompatibilityError('A previously created preparation object disappeared.')
                    updated = deepcopy(record); updated['inflight'] = i
                    journal.replace(updated,record); record = updated
                    if journal.due(record,lambda pid:True):
                        raise CompatibilityError('Preparation expired during fresh preflight.')
                    adapter.create_preparation_object(i,deepcopy(plan['objects'][i]))
                    observed = adapter.snapshot(); assert_identity(observed,plan)
                    owned = inspect_progress(record,observed)
                    if owned[i] is None: raise CompatibilityError('Preparation add was not read back.')
                    updated = deepcopy(record); updated['receipts'].append(deepcopy(owned[i]))
                    journal.replace(updated,record); record = updated
    finally:
        try: recover(journal,adapter,expected_nonce=record['nonce'],after_restore=resume if active else None)
        finally:
            if active and not resume_attempted: adapter.resume()
    return {'preparation_verified':True,'objects_restored':True,'production_enabled':False}
