"""Authentication and confirmation boundaries for the combined action endpoints."""
from unittest import TestCase
from unittest.mock import Mock

from tests import test_pause_http
from netpulse.storage import sqlite


class FakeActions:
    def __init__(self):
        self.calls = []

    def state(self):
        return {'enabled': True, 'reason': '', 'actions': [
            {'id': 'prefer_wan2', 'label': 'Prefer WAN 2', 'enabled': True}]}

    def preview(self, **kwargs):
        self.calls.append(('preview', kwargs))
        return {'token': 'reviewed-token', 'members': [], 'count': 1}

    def apply(self, token, actor):
        self.calls.append(('apply', token, actor))
        return {'count': 1, 'applied': True}


class SimpleActionsHttp(TestCase):
    request = test_pause_http.PauseHttp.request

    def setUp(self):
        test_pause_http.PauseHttp.setUp(self)
        self.actions = FakeActions()
        self.board.set_extra('action_control', self.actions)

    def test_catalog_requires_authentication(self):
        self.assertEqual(self.request('GET', '/api/actions', auth=False)[0], 401)
        status, data = self.request('GET', '/api/actions')
        self.assertEqual(status, 200)
        self.assertTrue(data['control']['enabled'])
        self.assertEqual(data['actions'][0]['id'], 'prefer_wan2')

    def test_cross_site_and_missing_origin_do_not_reach_controller(self):
        self.assertEqual(self.request('POST', '/api/actions/preview', {'action': 'auto'}, origin=False)[0], 403)
        self.assertEqual(self.actions.calls, [])

    def test_preview_is_bound_to_request_address_and_passes_management_guard(self):
        status, data = self.request('POST', '/api/actions/preview', {
            'macs': ['02-00-00-00-00-01'], 'action': 'prefer_wan2'})
        self.assertEqual(status, 200)
        self.assertEqual(data['token'], 'reviewed-token')
        call = self.actions.calls[0][1]
        self.assertEqual(call['actor'], 'dashboard:127.0.0.1')
        self.assertEqual(call['management_ip'], '127.0.0.1')
        self.assertIsNone(call['group_id'])

    def test_apply_requires_boolean_confirmation_and_valid_token(self):
        for body in ({'token': 'reviewed-token'}, {'token': 'reviewed-token', 'confirmed': 'true'},
                     {'token': [], 'confirmed': True}):
            with self.subTest(body=body):
                self.assertEqual(self.request('POST', '/api/actions/apply', body)[0], 409)
        self.assertEqual(self.actions.calls, [])
        self.assertEqual(self.request('POST', '/api/actions/apply', {
            'token': 'reviewed-token', 'confirmed': True})[0], 200)
        self.assertEqual(self.actions.calls, [('apply', 'reviewed-token', 'dashboard:127.0.0.1')])

    def test_absent_controller_and_invalid_body_fail_closed(self):
        self.board.set_extra('action_control', None)
        status, data = self.request('GET', '/api/actions')
        self.assertEqual(status, 200)
        self.assertFalse(data['control']['enabled'])
        self.assertEqual(self.request('POST', '/api/actions/preview', {'action': 'auto'})[0], 503)
        self.assertEqual(self.request('POST', '/api/actions/preview', [1, 2])[0], 400)

    def test_device_traffic_requires_authentication(self):
        traffic = Mock()
        traffic.read.return_value = {'available': True, 'devices': []}
        self.board.set_extra('device_traffic', traffic)
        status, _ = self.request('GET', '/api/devices/traffic?mac=02-00-00-00-00-01', auth=False)
        self.assertEqual(status, 401)
        traffic.read.assert_not_called()

    def test_device_traffic_rejects_missing_invalid_and_stale_group_selection(self):
        traffic = Mock()
        self.board.set_extra('device_traffic', traffic)
        for path in ('/api/devices/traffic',
                     '/api/devices/traffic?mac=not-a-mac',
                     '/api/devices/traffic?group_id=not-an-id',
                     '/api/devices/traffic?group_id=999'):
            with self.subTest(path=path):
                status, data = self.request('GET', path)
                self.assertEqual(status, 400)
                self.assertIn('error', data)
        traffic.read.assert_not_called()

    def test_device_traffic_reports_unavailable_when_reader_is_not_configured(self):
        self.board.set_extra('device_traffic', None)
        status, data = self.request('GET', '/api/devices/traffic?mac=02-00-00-00-00-01')
        self.assertEqual(status, 503)
        self.assertIn('not configured', data['error'])

    def test_device_traffic_group_read_uses_saved_members(self):
        first, second = '02-00-00-00-00-01', '02-00-00-00-00-02'
        group = sqlite.save_device_group(self.db, 'Test group', [first, second], 1)
        traffic = Mock()
        expected = {'available': True, 'devices': [
            {'mac': first, 'rx_mbps': 0.5, 'tx_mbps': 0.25},
            {'mac': second, 'rx_mbps': 1.0, 'tx_mbps': 0.75}]}
        traffic.read.return_value = expected
        self.board.set_extra('device_traffic', traffic)

        status, data = self.request('GET', f"/api/devices/traffic?group_id={group['id']}")

        self.assertEqual(status, 200)
        self.assertEqual(data, expected)
        traffic.read.assert_called_once_with([first, second])
