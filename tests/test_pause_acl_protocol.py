import json
import unittest

from netpulse.router.er605 import (ER605Client, RouterError, canonical_pause_acl_row,
                                   pause_acl_effective_match, valid_pause_acl_row)


def rule(suffix="A"):
    return {"name": "NP_PAUSE_" + suffix * 32, "policy": "DROP", "service": "ALL", "iptype": "ipv4",
            "zone": "LAN", "is_src": "ipgroup", "src": "NP_G_AABBCCDDEEFF", "is_dst": "ipgroup",
            "dest": "IPGROUP_ANY", "time": "Any", "states": ["new", "established", "related", "invalid"],
            "position": "", "flag": "1", "user": "1"}


def firmware_row(canonical):
    row = dict(canonical)
    row["zone"] = ["LAN"]
    row.pop("position")
    row["id"] = "row-1"
    row["key"] = "key-0"
    return row


class Protocol(ER605Client):
    def __init__(self, rows):
        self._stok = "session"
        self.rows = rows
        self.payloads = []

    def get_response(self, module, form, params=None):
        return {"error_code": "0", "result": {"rules": self.rows}}

    def _post(self, path, form, referer="/webpages/index.html"):
        payload = json.loads(form["data"])
        self.payloads.append(payload)
        params = payload["params"]
        if payload["method"] == "add":
            self.rows.insert(params["index"], params["new"])
        elif payload["method"] == "delete":
            self.rows.pop(int(params["index"]))
        return {"error_code": "0"}


class BadAdd(Protocol):
    def _post(self, path, form, referer="/webpages/index.html"):
        payload = json.loads(form["data"]); self.payloads.append(payload)
        self.rows.insert(0, payload["params"]["new"])
        return {"error_code": "0"}


class MutatingAdd(Protocol):
    def _post(self, path, form, referer="/webpages/index.html"):
        payload = json.loads(form["data"]); self.payloads.append(payload)
        self.rows.append(payload["params"]["new"])
        self.rows[0]["policy"] = "ACCEPT"
        return {"error_code": "0"}


class PauseACLProtocolTests(unittest.TestCase):
    def test_firmware_canonicalization_and_multirow_append_delete(self):
        prior, new = rule("A"), rule("B")
        raw_prior = firmware_row(prior)
        self.assertEqual(canonical_pause_acl_row(raw_prior), prior)
        self.assertTrue(pause_acl_effective_match(raw_prior, prior))
        cli = Protocol([raw_prior.copy()])
        added = cli.add_pause_acl_rule([raw_prior], new)
        self.assertEqual(added["name"], new["name"])
        self.assertEqual(cli.payloads[0]["params"]["index"], 1)
        self.assertEqual(cli.payloads[0]["params"]["key"], "add")
        cli.delete_pause_acl_rule(new["name"], new)
        self.assertEqual([r["name"] for r in cli.rows], [prior["name"]])

    def test_refuses_owner_rows_duplicates_and_malformed_rows(self):
        owner = dict(rule("A"), name="NP_TEST_P_" + "C" * 32)
        for provided in ([owner], [rule("A"), rule("A")], [dict(rule("A"), policy="ACCEPT")]):
            cli = Protocol([r.copy() for r in provided])
            with self.subTest(provided=provided), self.assertRaises(RouterError):
                cli.add_pause_acl_rule(provided, rule("B"))
            self.assertEqual(cli.payloads, [])

    def test_changed_delete_target_refused(self):
        existing = rule("A")
        cli = Protocol([dict(existing, src="NP_G_112233445566")])
        with self.assertRaises(RouterError):
            cli.delete_pause_acl_rule(existing["name"], existing)
        self.assertEqual(cli.payloads, [])

    def test_readback_placement_mismatch_and_existing_row_change_raise(self):
        prior = rule("A")
        for client_type in (BadAdd, MutatingAdd):
            cli = client_type([prior.copy()])
            with self.subTest(client=client_type.__name__), self.assertRaises(RouterError):
                cli.add_pause_acl_rule([prior], rule("B"))

    def test_new_rule_is_strict_and_states_order_is_normalized(self):
        expected = rule()
        self.assertTrue(valid_pause_acl_row(expected))
        observed = firmware_row(expected)
        observed["states"] = list(reversed(observed["states"]))
        self.assertTrue(pause_acl_effective_match(observed, expected))
        self.assertFalse(valid_pause_acl_row(observed))
        observed["position"] = "99"
        self.assertTrue(pause_acl_effective_match(observed, expected))
        observed["unknown_filter"] = "changed"
        self.assertIsNone(canonical_pause_acl_row(observed))


if __name__ == "__main__":
    unittest.main()
