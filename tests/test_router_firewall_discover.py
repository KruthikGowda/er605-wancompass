"""The read-only router form probe must not reveal private device identities."""

from __future__ import annotations

import unittest
from contextlib import redirect_stdout
from io import StringIO
from types import SimpleNamespace
from unittest import mock

from netpulse.router.er605 import RouterError
from tools import router_firewall_discover
from tools.router_firewall_discover import summarize, summarize_acl_order


class FirewallProbeRedaction(unittest.TestCase):
    def test_acl_order_summary_exposes_only_safe_rule_facts(self):
        private_name = "Family-Phone-Rule"
        private_source = "FamilyPhones"
        private_destination = "PrivateDestinations"
        summary = summarize_acl_order({"error_code": "0", "result": {"rules": [
            {"name": private_name, "policy": "DROP", "service": "ALL", "iptype": "ipv4",
             "zone": "LAN", "is_src": "ipgroup", "src": private_source,
             "is_dst": "ipgroup", "dest": "IPGROUP_ANY", "state": "on"},
            {"name": "NP_PAUSE_ABC", "policy": "ACCEPT", "service": "web-only",
             "iptype": "ipv6", "zone": "WAN", "src": "NP_PAUSE_ABC",
             "dest": private_destination, "state": "off"},
        ]}})
        self.assertTrue(summary["readable"])
        self.assertEqual(summary["count"], 2)
        self.assertEqual(summary["rules"], [
            {"order": 1, "policy": "Block", "direction": "LAN-to-WAN", "ip_version": "IPv4",
             "service": "ALL", "source": "owner/unknown", "destination": "any", "state": "enabled"},
            {"order": 2, "policy": "Allow", "direction": "WAN-to-LAN", "ip_version": "IPv6",
             "service": "custom/unknown", "source": "NetPulse-managed", "destination": "owner/unknown",
             "state": "disabled"},
        ])
        rendered = repr(summary)
        for private in (private_name, private_source, private_destination, "web-only", "NP_PAUSE_ABC"):
            self.assertNotIn(private, rendered)
        self.assertFalse(summary["enforcement_verified"])

    def test_acl_order_summary_handles_live_empty_shape_and_ambiguous_lists(self):
        self.assertEqual(summarize_acl_order({"error_code": 0, "result": {},
                                               "others": {"max_rules": 128}})["count"], 0)
        ambiguous = summarize_acl_order({"result": {"rules": [
            {"policy": "DROP", "src": "NP_TEST"}], "acl": [
            {"policy": "ACCEPT", "src": "NP_OTHER"}]}})
        self.assertFalse(ambiguous["readable"])
        self.assertEqual(ambiguous["reason"], "ambiguous row collections")

    def test_acl_order_summary_redacts_unknown_values(self):
        summary = summarize_acl_order({"result": [{
            "name": "Secret name", "policy": "secret-policy", "service": "secret-service",
            "zone": "custom-zone", "iptype": "secret-ip-type", "src": "secret-source",
            "dest": "secret-destination", "state": "secret-state",
        }]})
        self.assertTrue(summary["readable"])
        rendered = repr(summary)
        for private in ("Secret name", "secret-policy", "secret-service", "custom-zone",
                        "secret-ip-type", "secret-source", "secret-destination", "secret-state"):
            self.assertNotIn(private, rendered)

    def test_acl_status_exposes_bounded_numeric_limit_and_code_only(self):
        result = summarize({
            "error_code": "0",
            "others": {"max_rules": 128, "private_field": "private-value"},
            "result": {},
        })
        self.assertEqual(result["error_code"], 0)
        self.assertEqual(result["nested_objects"][0]["max_rules"], 128)
        rendered = repr(summarize({
            "error_code": "secret-response",
            "max_rules": "router-token",
        }))
        self.assertNotIn("secret-response", rendered)
        self.assertNotIn("router-token", rendered)

    def test_firmware_values_are_allowlisted_and_serials_remain_redacted(self):
        result = summarize({
            "firmware_version": "2.3.3 Build 20251029 Rel.18054",
            "model": "ER605 v2.30",
            "serial_number": "private-serial",
        })
        self.assertEqual(result["firmware_version"], "2.3.3 Build 20251029 Rel.18054")
        self.assertEqual(result["model"], "ER605 v2.30")
        self.assertNotIn("serial_number", repr(result))
        self.assertNotIn("private-serial", repr(result))

    def test_dynamic_keys_and_identity_values_are_redacted(self):
        private_mac = "AA-BB-CC-DD-EE-FF"
        private_name = "Family tablet"
        private_ip = "192.0.2.44"
        output = repr(summarize({
            "enable": "on",
            "direction": "LAN-WAN",
            private_mac: {private_name: {"address": private_ip}},
        }))
        self.assertIn("LAN-WAN", output)
        for private in (private_mac, private_name, private_ip):
            self.assertNotIn(private, output)

    def test_list_reports_safe_schema_without_row_values(self):
        output = summarize([{"name": "Child phone", "mac": "AA-BB-CC-DD-EE-FF",
                             "ip": "192.0.2.45", "direction": "LAN-WAN"}])
        self.assertEqual(output["row_count"], 1)
        self.assertEqual(output["row_fields"], ["direction", "ip", "mac", "name"])
        rendered = repr(output)
        self.assertNotIn("Child phone", rendered)
        self.assertNotIn("AA-BB-CC-DD-EE-FF", rendered)
        self.assertNotIn("192.0.2.45", rendered)

    def test_nested_form_wrappers_reveal_schema_but_not_values(self):
        secret_name = "Family tablet"
        secret_ip = "192.0.2.45"
        output = summarize({"result": {"acl_rules": [
            {"name": secret_name, "source_ipgroup": "Home", "destination": secret_ip,
             "direction": "LAN-WAN", "policy": "deny"}
        ]}})
        rendered = repr(output)
        self.assertIn("source_ipgroup", rendered)
        self.assertIn("destination", rendered)
        self.assertIn("LAN-WAN", rendered)
        self.assertNotIn(secret_name, rendered)
        self.assertNotIn(secret_ip, rendered)

    def test_arbitrary_identifier_row_keys_are_not_mistaken_for_schema(self):
        private_name = "KitchenTV"
        private_mac_key = "AABBCCDDEEFF"
        private_ip = "192.0.2.46"
        output = summarize([{
            private_name: private_ip,
            private_mac_key: "secret-value",
            "source_ipgroup": "FamilyDevices",
        }])
        rendered = repr(output)
        self.assertIn("source_ipgroup", rendered)
        for private in (private_name, private_mac_key, private_ip, "secret-value", "FamilyDevices"):
            self.assertNotIn(private, rendered)

    def test_known_interface_state_keeps_rows_associated_and_hides_custom_labels(self):
        private_ip = "192.168.0.77"
        result = summarize([
            {"t_label": "WAN1", "t_isup": True, "t_proto": "pppoe", "t_type": "physical",
             "ipaddr": private_ip},
            {"t_name": "wan2", "t_isup": False, "t_proto": "static", "t_linktype": "static"},
            {"t_label": "Family tablet", "t_isup": False, "ipaddr": "192.168.0.88"},
        ])
        self.assertEqual(result["known_interfaces"], [
            {"interface": "WAN1", "is_up": "true", "protocol": "pppoe", "type": "physical"},
            {"interface": "WAN2", "is_up": "false", "protocol": "static", "link_type": "static"},
        ])
        self.assertNotIn(private_ip, repr(result))
        self.assertNotIn("Family tablet", repr(result))

    def test_discovery_entry_point_only_reads_and_redacts_router_data(self):
        private_name = "Family tablet"
        private_mac = "AA-BB-CC-DD-EE-FF"
        calls = []

        class FakeClient:
            def __init__(self, *_args):
                pass

            def __enter__(self):
                return self

            def session(self):
                return self

            def __exit__(self, *_args):
                return False

            def get(self, module, form):
                calls.append((module, form))
                if (module, form) == ("access_ctl", "acl_inner"):
                    return {"result": {"rules": [
                        {"name": private_name, "source_mac": private_mac,
                         "direction": "LAN-WAN", "policy": "deny"}
                    ]}}
                if (module, form) == ("interface", "status2"):
                    return {"normal": [{"t_name": "WAN1", "t_proto": "pppoe", "t_isup": True,
                                        "ipaddr": "10.2.3.4", "username": "pppoe-user",
                                        "password": "secret-pass"}]}
                if (module, form) == ("system", "getproduct"):
                    return {"firmware_version": "2.3.3 Build 20251029 Rel.18054",
                            "serial_number": "private-serial"}
                if (module, form) == ("status", "all"):
                    return {"software_version": "2.3.3 Build 20251029 Rel.18054"}
                raise RouterError("not present")

        cfg = SimpleNamespace(router=SimpleNamespace(
            enabled=True, host="192.0.2.1", cert_sha256="fingerprint",
            credentials_file="credentials.toml"))
        credentials = SimpleNamespace(username="router-user", password="router-password",
                                      cert_sha256="fingerprint")
        output = StringIO()
        with (mock.patch.object(router_firewall_discover, "load", return_value=cfg),
              mock.patch.object(router_firewall_discover, "load_router_credentials", return_value=credentials),
              mock.patch.object(router_firewall_discover, "ER605Client", FakeClient),
              mock.patch("sys.argv", ["router_firewall_discover.py", "--config", "test.toml"]),
              redirect_stdout(output)):
            self.assertEqual(router_firewall_discover.main(), 0)

        self.assertEqual(calls, list(router_firewall_discover.FORMS))
        rendered = output.getvalue()
        self.assertIn("READ OK: access_ctl/acl_inner", rendered)
        self.assertIn("ACL order summary (identifiers redacted)", rendered)
        self.assertIn("READ OK: interface/status2", rendered)
        self.assertIn("'t_proto': ['pppoe']", rendered)
        self.assertIn("'t_isup': ['true']", rendered)
        self.assertIn("2.3.3 Build 20251029 Rel.18054", rendered)
        self.assertIn("LAN-WAN", rendered)
        self.assertNotIn(private_name, rendered)
        self.assertNotIn(private_mac, rendered)
        self.assertNotIn("10.2.3.4", rendered)
        self.assertNotIn("pppoe-user", rendered)
        self.assertNotIn("secret-pass", rendered)
        self.assertNotIn("private-serial", rendered)
        self.assertNotIn("router-password", rendered)

    def test_wan_status_read_does_not_count_as_acl_form_discovery(self):
        class FakeClient:
            def __init__(self, *_args):
                pass

            def __enter__(self):
                return self

            def session(self):
                return self

            def __exit__(self, *_args):
                return False

            def get(self, module, form):
                if (module, form) == ("interface", "status2"):
                    return {"normal": [{"t_proto": "pppoe", "t_isup": True}]}
                if (module, form) == ("system", "getproduct"):
                    return {"firmware_version": "2.3.3 Build 20251029 Rel.18054"}
                if (module, form) == ("status", "all"):
                    return {"software_version": "2.3.3 Build 20251029 Rel.18054"}
                raise RouterError("not present")

        cfg = SimpleNamespace(router=SimpleNamespace(
            enabled=True, host="192.0.2.1", cert_sha256="fingerprint",
            credentials_file="credentials.toml"))
        credentials = SimpleNamespace(username="router-user", password="router-password",
                                      cert_sha256="fingerprint")
        output = StringIO()
        with (mock.patch.object(router_firewall_discover, "load", return_value=cfg),
              mock.patch.object(router_firewall_discover, "load_router_credentials", return_value=credentials),
              mock.patch.object(router_firewall_discover, "ER605Client", FakeClient),
              mock.patch("sys.argv", ["router_firewall_discover.py", "--config", "test.toml"]),
              redirect_stdout(output)):
            self.assertEqual(router_firewall_discover.main(), 1)
        self.assertIn("No candidate ACL form responded", output.getvalue())
        self.assertIn("READ OK: interface/status2", output.getvalue())
        self.assertIn("READ OK: system/getproduct", output.getvalue())
        self.assertIn("READ OK: status/all", output.getvalue())
        self.assertIn("2.3.3 Build 20251029 Rel.18054", output.getvalue())
        self.assertNotIn("router-password", output.getvalue())


if __name__ == "__main__":
    unittest.main()
