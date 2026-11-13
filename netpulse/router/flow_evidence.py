"""Strict observation contracts for a native, single-phone diagnostic trial."""
from netpulse.router.compatibility import CompatibilityError

PHASES = {'baseline','prepared','blocked','recovery','restored'}
FLOW_KEYS = {'prepared_new_connection','reuse_confirmed','existing_request_ok',
             'fresh_processes_verified','existing_result_conclusive'}


def validate_flow_evidence(data):
    if (not isinstance(data,dict) or data.get('phase') not in PHASES
            or type(data.get('internet_ipv4_ok')) is not bool or data.get('lan_ok') is not True):
        raise CompatibilityError('Invalid native phase/heartbeat.')
    checks, flow = data.get('checks'), data.get('flow')
    if (data.get('transport') != 'native_curl'
            or not isinstance(checks,dict) or set(checks) != {'ipify','cloudflare'}
            or any(type(v) is not bool for v in checks.values())
            or not isinstance(flow,dict) or set(flow) != FLOW_KEYS
            or any(type(v) is not bool for v in flow.values())
            or flow['fresh_processes_verified'] is not True):
        raise CompatibilityError('Invalid native connection evidence.')
    reachable = any(checks.values())
    if data['phase'] == 'blocked':
        reachable = reachable or flow['existing_request_ok']
        if (not flow['prepared_new_connection'] or not flow['existing_result_conclusive']
                or (flow['existing_request_ok'] and not flow['reuse_confirmed'])):
            raise CompatibilityError('Existing connection evidence is inconclusive.')
    elif not all(checks.values()):
        raise CompatibilityError('Both native baseline/recovery destinations must succeed.')
    if reachable != data['internet_ipv4_ok']:
        raise CompatibilityError('Native reachability summary contradicts its evidence.')
    if data['phase'] == 'prepared' and not flow['prepared_new_connection']:
        raise CompatibilityError('Prepared connection was not established.')
    return {'transport':'native_curl','checks':dict(checks),'flow':dict(flow)}
