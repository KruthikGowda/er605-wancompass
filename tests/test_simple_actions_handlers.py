"""The real monitor hooks connect numbered Telegram selection to one reviewed action."""
import tempfile
from types import SimpleNamespace
from unittest import TestCase, mock

from netpulse.notifications.telegram import TelegramBot
from netpulse.storage import sqlite
from tests.harness import Scenario, local


class SimpleActionHandlers(TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.s = Scenario(directory.name, local(12))
        self.addCleanup(self.s.close)
        self.preview_calls, self.apply_calls = [], []
        self.mac = '02-00-00-00-00-01'
        self.s.board.set_extra('router_raw', {'clients': [
            {'macaddr': self.mac, 'ipaddr': '192.0.2.10', 'name': 'Work phone'}]})
        def preview(**kwargs):
            self.preview_calls.append(kwargs)
            return {'token': 'opaque-token', 'action': kwargs['action'], 'reservation_count': 1,
                    'members': [{'mac': self.mac, 'ip': '192.0.2.10', 'name': 'Work phone',
                                 'reservation_needed': True, 'current': 'AUTO'}],
                    'effect': 'Prefer WAN 2 with native failover.'}
        def apply(token, actor):
            self.apply_calls.append((token, actor))
            return {'count': 1}
        self.s.mon.action_control = SimpleNamespace(
            routes=SimpleNamespace(is_local_device=lambda _: False),
            state=lambda: {'actions': [{'id': 'prefer_wan2', 'label': 'Prefer WAN 2', 'enabled': True}]},
            preview=preview, apply=apply)
        self.handlers = self.s.mon.bot_handlers()

    def test_numbered_owner_flow_reaches_real_hooks_without_typing_identifiers(self):
        bot = TelegramBot('synthetic-token', '101', self.handlers)
        messages = []
        bot.send = lambda text, chat=None, markup=None: messages.append((text, markup))
        def message(text):
            bot._handle({'chat': {'id': 101, 'type': 'private'}, 'from': {'id': 101}, 'text': text})
        def click(text):
            markup = messages[-1][1]
            button = next(b for row in markup['inline_keyboard'] for b in row if text in b['text'])
            bot._handle_button({'id': 'synthetic-callback', 'from': {'id': 101}, 'data': button['callback_data'],
                                'message': {'chat': {'id': 101, 'type': 'private'}}})
        with mock.patch.object(bot, '_call', return_value={'ok': True}):
            message('/devices')
            self.assertIn('Work phone', messages[-1][0])
            message('1')
            click('Prefer WAN 2')
            self.assertEqual(self.apply_calls, [])
            self.assertIn('automatic DHCP reservation', messages[-1][0])
            self.assertNotIn('opaque-token', messages[-1][0])
            click('Confirm')
        self.assertEqual(self.apply_calls, [('opaque-token', 'telegram:101')])
        self.assertGreaterEqual(len(self.preview_calls), 2, 'confirmation must revalidate the reviewed selection')

    def test_preview_fingerprint_does_not_include_random_token(self):
        payload = {'kind': 'devices', 'items': [{'mac': self.mac}], 'action': 'prefer_wan2'}
        first = self.handlers['quick_preview'](payload, '101')
        second = self.handlers['quick_preview'](payload, '101')
        self.assertEqual(first['fingerprint'], second['fingerprint'])
        self.assertNotIn('opaque-token', first['fingerprint'])

    def test_group_hooks_create_remove_and_rename_without_router_writes(self):
        self.s.mon.router = SimpleNamespace(snap=SimpleNamespace(
            raw=self.s.board.get_extra('router_raw'), checked_at=self.s.clock()))
        preview = self.handlers['quick_group_preview']({
            'action': 'create', 'name': 'Work group', 'macs': [self.mac]}, '101')
        self.assertIn('confirm_token', preview)
        self.assertNotIn(preview['confirm_token'], preview['text'])
        self.assertEqual(sqlite.device_groups(self.s.cfg.db_path), [])
        self.handlers['quick_group_apply'](preview['confirm_token'], '101')
        group = sqlite.device_groups(self.s.cfg.db_path)[0]
        self.assertEqual(group['members'], [self.mac])
        renamed = self.handlers['quick_group_preview']({
            'action': 'rename', 'group_id': group['id'], 'name': 'Office'}, '101')
        self.handlers['quick_group_apply'](renamed['confirm_token'], '101')
        self.assertEqual(sqlite.device_groups(self.s.cfg.db_path)[0]['name'], 'Office')
        removed = self.handlers['quick_group_preview']({
            'action': 'remove', 'group_id': group['id'], 'macs': [self.mac]}, '101')
        self.handlers['quick_group_apply'](removed['confirm_token'], '101')
        self.assertEqual(sqlite.device_groups(self.s.cfg.db_path)[0]['members'], [])
        self.assertEqual(self.apply_calls, [])
        self.assertEqual(self.preview_calls, [])

    def test_group_hooks_fail_closed_for_stale_inventory_and_foreign_actor(self):
        payload = {'action': 'create', 'name': 'Work group', 'macs': [self.mac]}
        self.assertNotIn('confirm_token', self.handlers['quick_group_preview'](payload, '101'))
        self.s.mon.router = SimpleNamespace(snap=SimpleNamespace(
            raw=self.s.board.get_extra('router_raw'), checked_at=self.s.clock()))
        preview = self.handlers['quick_group_preview'](payload, '101')
        self.handlers['quick_group_apply'](preview['confirm_token'], '202')
        self.assertEqual(sqlite.device_groups(self.s.cfg.db_path), [])

    def test_bandwidth_reply_does_not_invent_a_device_meter_or_rate_limit(self):
        result = self.handlers['quick_bandwidth']({'items': [{'name': 'Work phone'}]}, '101')
        self.assertIn('not a device', result['text'])
        self.assertEqual(result['actions'], [])

    def test_bandwidth_hook_reads_measured_group_members_and_stays_clear_about_limits(self):
        group = sqlite.save_device_group(self.s.cfg.db_path, 'Work', [self.mac], int(self.s.clock()))
        reader = mock.Mock(return_value={
            'available': True,
            'sample_seconds': 2.0,
            'age_seconds': 1.0,
            'devices': [{'mac': self.mac, 'available': True,
                         'rx_mbps': 1.25, 'tx_mbps': 0.5}],
        })
        self.s.mon.device_traffic = SimpleNamespace(read=reader)

        result = self.handlers['quick_bandwidth']({'items': [{'id': group['id']}]}, '101')

        reader.assert_called_once_with([self.mac])
        self.assertIn('Work phone: RX 1.25 Mbps · TX 0.50 Mbps', result['text'])
        self.assertIn('over 2.0s', result['text'])
        self.assertIn('Per-device bandwidth caps and traffic priority are unavailable', result['text'])
        self.assertIn('WAN preference selects a connection', result['text'])
        self.assertEqual(result['actions'], [])

    def test_action_reviews_show_all_targets_or_refuse_to_issue_confirmation(self):
        members = [{'name': f'Device {index:02}', 'ip': f'192.0.2.{index + 1}',
                    'reservation_needed': False} for index in range(17)]
        self.s.mon.action_control.preview = lambda **kwargs: {
            'token': 'route-token', 'action': 'auto', 'members': members, 'effect': 'Autobalance'}
        payload = {'kind': 'devices', 'items': [{'mac': self.mac}], 'action': 'auto'}
        review = self.handlers['quick_preview'](payload, '101')
        for index in range(17):
            self.assertIn(f'Device {index:02}', review['text'])
        self.assertEqual(review['confirm_token'], 'route-token')

        self.s.mon.action_control.preview = lambda **kwargs: {
            'token': 'route-token', 'action': 'auto',
            'members': [{'name': f'Device {index:03}', 'ip': f'192.0.2.{index % 254 + 1}',
                         'reservation_needed': True} for index in range(100)],
            'effect': 'Autobalance'}
        oversized = self.handlers['quick_preview'](payload, '101')
        self.assertIn('Too many devices for one chat review', oversized['text'])
        self.assertNotIn('confirm_token', oversized)

    def test_group_reviews_show_all_changed_members_or_refuse_confirmation(self):
        added = [{'name': f'Device {index:02}', 'ip': f'192.0.2.{index + 1}'} for index in range(17)]
        self.s.mon.group_control = SimpleNamespace(preview=lambda **kwargs: {
            'token': 'group-token', 'group': 'Work', 'effect': 'Membership update', 'added': added})
        review = self.handlers['quick_group_preview']({'action': 'add', 'group_id': 7}, '101')
        for index in range(17):
            self.assertIn(f'Device {index:02}', review['text'])
        self.assertEqual(review['confirm_token'], 'group-token')

        oversized = [{'name': f'Device {index:03}', 'ip': f'192.0.2.{index % 254 + 1}'}
                     for index in range(150)]
        self.s.mon.group_control = SimpleNamespace(preview=lambda **kwargs: {
            'token': 'group-token', 'group': 'Work', 'effect': 'Membership update', 'added': oversized})
        refused = self.handlers['quick_group_preview']({'action': 'add', 'group_id': 7}, '101')
        self.assertIn('Too many devices for one chat review', refused['text'])
        self.assertNotIn('confirm_token', refused)
