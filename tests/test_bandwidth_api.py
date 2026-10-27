"""Synthetic contract tests for the isolated ER605 bandwidth-rule writer."""
import copy
import json
import unittest

from netpulse.router.bandwidth_api import BandwidthAPIError, BandwidthRuleAPI
from netpulse.router.qos import canonical_rate_rule_row


MAC = "AA-BB-CC-DD-EE-01"
NAME = "NP_Q_AABBCCDDEE01"
GROUP = "NP_G_AABBCCDDEE01"
MAC_B = "AA-BB-CC-DD-EE-02"
NAME_B = "NP_Q_AABBCCDDEE02"
GROUP_B = "NP_G_AABBCCDDEE02"


def global_response(enabled="on", threshold="off"):
    return {"id": 1, "result": {
        ".name": "qos_global", ".type": "qos", "qos_threshold": "0",
        "threshold_enable": threshold, "bandwidth": 100000, ".anonymous": False,
        "qos_enable": enabled, "interface": [], "qos_setting_number": "0",
    }, "error_code": "0"}


def observed(name=NAME, *, group=GROUP, position=1, rate="1000", setting_index="0"):
    return {".name": name, ".type": "rule", ".anonymous": False,
            "setting_index": setting_index, "t_ping_label": "LAN", "t_pong_label": "WAN/LAN2",
            "position": position, "name": name, "if_ping": "LAN", "if_pong": "WAN2",
            "source_type": "ip_group", "ip_group": group, "rate_max": rate,
            "rate_max_mate": rate, "mode": "priv", "time": "Any",
            "comment": "NetPulse validation", "enable": "on", "ip_type": "src"}


def collection_response(rows, max_rules=64):
    return {"id": 2, "others": {"max_rules": max_rules},
            "result": copy.deepcopy(rows) if rows else {}, "error_code": "0"}


def unrelated(name="operator-rule", position=1):
    return observed(name, group="OTHER_GROUP", position=position, rate="2500") | {
        ".name": name, "comment": "operator rule", "if_pong": "WAN1", "t_pong_label": "WAN/LAN1"}


class FakeClient:
    _stok = "synthetic-session"

    def __init__(self, rows=None, engine="on", threshold="off", max_rules=64):
        self.rows = copy.deepcopy(rows or [])
        self.engine = engine
        self.threshold = threshold
        self.max_rules = max_rules
        self.calls = []
        self.posts = []
        self.fail_after_write = False
        self.bad_readback = False
        self.extra_readback = False
        self.mutate_on_second_collection = None
        self.collection_reads = 0
        self.renumber_after_delete = False
        self.mutate_survivor_after_delete = None

    def get_response(self, module, form):
        self.calls.append(("get", module, form))
        if (module, form) == ("qos", "global"):
            return global_response(self.engine, self.threshold)
        if (module, form) != ("qos", "rule"):
            raise AssertionError((module, form))
        self.collection_reads += 1
        if self.collection_reads == 2 and self.mutate_on_second_collection is not None:
            self.rows = copy.deepcopy(self.mutate_on_second_collection)
        return collection_response(self.rows, self.max_rules)

    def _post(self, url, payload):
        self.posts.append((url, copy.deepcopy(payload)))
        data = json.loads(payload["data"])
        params = data["params"]
        if data["method"] == "add":
            row = params["new"]
            added = observed(row["name"], group=row["ip_group"],
                             position=len(self.rows) + 1, rate=row["rate_max"],
                             setting_index=str(7 + len(self.rows)))
            added["rate_max_mate"] = row["rate_max_mate"]
            self.rows.append(added)
            if self.bad_readback:
                self.rows[-1]["t_pong_label"] = "unknown label"
            if self.extra_readback:
                self.rows[-1]["unexpected_metadata"] = "unknown"
        elif data["method"] == "delete":
            index = int(params["index"])
            self.rows.pop(index)
            if self.renumber_after_delete:
                for ix, row in enumerate(self.rows):
                    row["position"] = ix + 1
                    row["setting_index"] = str(3 + ix)
            if self.mutate_survivor_after_delete and self.rows:
                field, value = self.mutate_survivor_after_delete
                self.rows[0][field] = value
        if self.fail_after_write:
            raise TimeoutError("simulated lost write response")
        return {"error_code": "0"}


class BandwidthAPITests(unittest.TestCase):
    def test_add_uses_reviewed_payload_and_validates_observed_row(self):
        client = FakeClient()
        result = BandwidthRuleAPI(client).add_rule("aa:bb:cc:dd:ee:01")
        expected_observed = observed()
        expected_observed["rate_max"] = expected_observed["rate_max_mate"] = 1000
        expected_observed["setting_index"] = "7"
        self.assertEqual(result, expected_observed)
        url, request = client.posts[0]
        self.assertIn("/admin/qos?form=rule", url)
        self.assertEqual(request, {"data": json.dumps({"method": "add", "params": {
            "index": 0, "key": "key-0", "old": "add", "new": {
                "name": NAME, "if_ping": "LAN", "if_pong": "WAN2", "source_type": "ip_group",
                "network": "", "ip_group": GROUP, "rate_max": "1000", "rate_max_mate": "1000",
                "mode": "priv", "time": "Any", "comment": "NetPulse validation",
                "position": "", "enable": "on", "ip_type": "src",
            }}})})

    def test_add_requires_active_session_engine_on_and_bounded_rates(self):
        client = FakeClient(engine="off")
        with self.assertRaisesRegex(BandwidthAPIError, "engine is off"):
            BandwidthRuleAPI(client).add_rule(MAC)
        self.assertEqual(client.posts, [])
        client = FakeClient(threshold="on")
        with self.assertRaisesRegex(BandwidthAPIError, "threshold mode is on"):
            BandwidthRuleAPI(client).add_rule(MAC)
        self.assertEqual(client.posts, [])
        client = FakeClient()
        client._stok = None
        with self.assertRaisesRegex(BandwidthAPIError, "active client session"):
            BandwidthRuleAPI(client).add_rule(MAC)
        client = FakeClient()
        with self.assertRaises(ValueError):
            BandwidthRuleAPI(client).add_rule(MAC, True, 1000)
        self.assertEqual(client.posts, [])
        for rate in (99, 1_000_001):
            with self.assertRaises(ValueError):
                BandwidthRuleAPI(client).add_rule(MAC, rate, 1000)

    def test_invalid_mac_is_rejected_before_any_router_api_call(self):
        client = FakeClient()
        with self.assertRaisesRegex(ValueError, "valid device MAC"):
            BandwidthRuleAPI(client).add_rule("not-a-mac")
        self.assertEqual(client.calls, [])
        self.assertEqual(client.posts, [])

    def test_add_respects_advertised_rule_bound(self):
        client = FakeClient(max_rules=1)
        client.rows = [unrelated()]
        with self.assertRaisesRegex(BandwidthAPIError, "table is full"):
            BandwidthRuleAPI(client).add_rule(MAC)
        self.assertEqual(client.posts, [])

    def test_add_refuses_changed_baseline_unknown_rows_and_existing_target(self):
        client = FakeClient()
        client.mutate_on_second_collection = [observed(NAME_B, group=GROUP_B)]
        with self.assertRaisesRegex(BandwidthAPIError, "changed during review"):
            BandwidthRuleAPI(client).add_rule(MAC)
        self.assertEqual(client.posts, [])

        unknown = unrelated() | {"surprise": "field"}
        client = FakeClient([unknown])
        with self.assertRaisesRegex(BandwidthAPIError, "unknown fields"):
            BandwidthRuleAPI(client).add_rule(MAC)
        self.assertEqual(client.posts, [])

        client = FakeClient([observed()])
        with self.assertRaisesRegex(BandwidthAPIError, "already exists"):
            BandwidthRuleAPI(client).add_rule(MAC)
        self.assertEqual(client.posts, [])

    def test_add_write_timeout_or_bad_metadata_retains_unknown_row_without_cleanup(self):
        client = FakeClient()
        client.fail_after_write = True
        with self.assertRaisesRegex(BandwidthAPIError, "uncertain"):
            BandwidthRuleAPI(client).add_rule(MAC)
        self.assertEqual(len(client.posts), 1)
        self.assertEqual(client.rows[0]["name"], NAME)

    def test_add_appends_after_exact_managed_rows_with_dynamic_index_and_key(self):
        first = observed(position=1, setting_index="8")
        client = FakeClient([first])
        result = BandwidthRuleAPI(client).add_rule(MAC_B, 2000, 2000)
        self.assertEqual(result["name"], NAME_B)
        self.assertEqual([row["name"] for row in client.rows], [NAME, NAME_B])
        request = json.loads(client.posts[0][1]["data"])
        self.assertEqual(request["params"]["index"], 1)
        self.assertEqual(request["params"]["key"], "key-1")
        self.assertEqual(client.rows[0], first)

    def test_add_refuses_external_or_overlapping_rows_without_write(self):
        client = FakeClient([unrelated()])
        with self.assertRaisesRegex(BandwidthAPIError, "non-NetPulse rule"):
            BandwidthRuleAPI(client).add_rule(MAC)
        self.assertEqual(client.posts, [])

        mismatched_group = observed(NAME_B, group=GROUP, position=2)
        client = FakeClient([observed(), mismatched_group])
        with self.assertRaisesRegex(BandwidthAPIError, "exact managed"):
            BandwidthRuleAPI(client).add_rule("AA-BB-CC-DD-EE-03")
        self.assertEqual(client.posts, [])

    def test_add_bad_metadata_readback_leaves_row_without_cleanup(self):
        client = FakeClient()
        client.bad_readback = True
        with self.assertRaises(BandwidthAPIError):
            BandwidthRuleAPI(client).add_rule(MAC)
        self.assertEqual(len(client.posts), 1)
        self.assertEqual(client.rows[0]["name"], NAME)

        client = FakeClient()
        client.extra_readback = True
        with self.assertRaisesRegex(BandwidthAPIError, "unknown fields"):
            BandwidthRuleAPI(client).add_rule(MAC)
        self.assertEqual(len(client.posts), 1)
        self.assertEqual(client.rows[0]["name"], NAME)

    def test_delete_resolves_fresh_exact_index_and_preserves_managed_row(self):
        first = observed(position=1, setting_index="4")
        target = observed(NAME_B, group=GROUP_B, position=2, setting_index="9", rate="2000")
        client = FakeClient([first, target])
        BandwidthRuleAPI(client).delete_rule(MAC_B, target)
        self.assertEqual(client.rows, [first])
        request = json.loads(client.posts[0][1]["data"])
        self.assertEqual(request, {"method": "delete", "params": {"index": "1", "key": "key-1"}})

    def test_delete_first_row_allows_only_bounded_position_and_index_renumbering(self):
        first = observed(position=1, setting_index="8")
        second = observed(NAME_B, group=GROUP_B, position=2, setting_index="11", rate="2000")
        client = FakeClient([first, second])
        client.renumber_after_delete = True
        remaining = BandwidthRuleAPI(client).delete_rule(MAC, first)
        self.assertEqual([row["name"] for row in remaining], [NAME_B])
        self.assertEqual(remaining[0]["position"], 1)
        self.assertEqual(remaining[0]["setting_index"], "3")
        canonical_second = canonical_rate_rule_row(second)
        self.assertTrue(all(canonical_second[field] == remaining[0][field]
                            for field in canonical_second
                            if field not in ("position", "setting_index")))

    def test_delete_rejects_effective_or_label_drift_after_write(self):
        for field, value in (("rate_max", "3000"), ("t_pong_label", "unknown")):
            with self.subTest(field=field):
                first = observed(position=1)
                second = observed(NAME_B, group=GROUP_B, position=2, rate="2000")
                client = FakeClient([first, second])
                client.renumber_after_delete = True
                client.mutate_survivor_after_delete = (field, value)
                with self.assertRaises(BandwidthAPIError):
                    BandwidthRuleAPI(client).delete_rule(MAC, first)
                self.assertEqual(len(client.posts), 1)
                self.assertEqual([row["name"] for row in client.rows], [NAME_B])

    def test_delete_refuses_stale_or_unrelated_identity_and_checks_engine(self):
        target = observed(position=1)
        changed = observed(position=1, rate="2000")
        client = FakeClient([changed])
        with self.assertRaisesRegex(BandwidthAPIError, "changed or is ambiguous"):
            BandwidthRuleAPI(client).delete_rule(MAC, target)
        self.assertEqual(client.posts, [])

        unknown = observed() | {"unexpected_metadata": "unknown"}
        client = FakeClient([unknown])
        with self.assertRaisesRegex(BandwidthAPIError, "unknown fields"):
            BandwidthRuleAPI(client).delete_rule(MAC, observed())
        self.assertEqual(client.posts, [])

        client = FakeClient([target], engine="off")
        BandwidthRuleAPI(client).delete_rule(MAC, target)
        self.assertEqual(client.rows, [])
        self.assertEqual(len(client.posts), 1)

    def test_delete_timeout_leaves_row_and_does_not_retry_or_delete_more(self):
        target = observed()
        client = FakeClient([target])
        client.fail_after_write = True
        with self.assertRaisesRegex(BandwidthAPIError, "uncertain"):
            BandwidthRuleAPI(client).delete_rule(MAC, target)
        self.assertEqual(len(client.posts), 1)
        self.assertEqual(client.rows, [])


if __name__ == "__main__":
    unittest.main()
