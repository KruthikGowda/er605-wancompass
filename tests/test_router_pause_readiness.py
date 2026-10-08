"""Same-LAN Internet-pause read-only precheck fails closed on ambiguous evidence."""

from __future__ import annotations

import ipaddress
import sys
import unittest
from contextlib import redirect_stdout
from io import StringIO
from types import SimpleNamespace
from unittest import mock

from tools import router_pause_readiness
from tools.router_pause_readiness import evaluate_candidate, pi_ipv4_addresses


MAC = "AA-BB-CC-DD-EE-01"
LAN = [{"name": "IP_LAN", "scope": "192.168.0.0/24"}]
CLIENT = [{"name": "Spare test handset", "ipaddr": "192.168.0.135", "macaddr": MAC}]
RESERVATION = [{"ip": "192.168.0.135", "mac": MAC, "enable": "on"}]
PI_ADDRESSES = [ipaddress.ip_address("192.168.0.157")]
EMPTY_ACL = {"error_code": "0", "result": {}}


def evaluate(candidate="192.168.0.135", lan=LAN, clients=CLIENT, reservations=RESERVATION,
             pi_addresses=PI_ADDRESSES, acl=EMPTY_ACL, router="192.168.0.1"):
    return evaluate_candidate(candidate, lan, clients, reservations, acl_snapshot=acl,
                              pi_addresses=pi_addresses, router_address=router)


class SameLanEndpointReadiness(unittest.TestCase):
    def test_selector_accepts_ip_mac_or_exact_case_insensitive_name(self):
        self.assertEqual(router_pause_readiness.resolve_candidate_ip("192.168.0.135", CLIENT),
                         "192.168.0.135")
        self.assertEqual(router_pause_readiness.resolve_candidate_ip(MAC.replace("-", ":"), CLIENT),
                         "192.168.0.135")
        self.assertEqual(router_pause_readiness.resolve_candidate_ip("spare test handset", CLIENT),
                         "192.168.0.135")

    def test_same_lan_candidate_passes_with_unique_lease_and_reservation(self):
        result = evaluate()
        self.assertEqual(result, {
            "lease_confirmed": True, "reservation_confirmed": True,
            "within_er605_lan": True, "not_pi_address": True, "not_router_address": True,
            "subnet_precheck": True, "acl_readable": True, "acl_rule_count": 0,
            "acl_rules": [], "acl_precheck": True, "control_precheck": True,
        })

    def test_candidate_cannot_be_pi_or_router_address(self):
        for candidate, field in (("192.168.0.157", "not_pi_address"),
                                 ("192.168.0.1", "not_router_address")):
            with self.subTest(candidate=candidate):
                result = evaluate(candidate=candidate,
                    clients=[dict(CLIENT[0], ipaddr=candidate)],
                    reservations=[dict(RESERVATION[0], ip=candidate)])
                self.assertTrue(result["lease_confirmed"])
                self.assertTrue(result["reservation_confirmed"])
                self.assertFalse(result[field])
                self.assertFalse(result["subnet_precheck"])

    def test_network_broadcast_and_non_host_scope_addresses_fail(self):
        for candidate in ("192.168.0.0", "192.168.0.255"):
            with self.subTest(candidate=candidate):
                result = evaluate(candidate=candidate,
                    clients=[dict(CLIENT[0], ipaddr=candidate)],
                    reservations=[dict(RESERVATION[0], ip=candidate)])
                self.assertTrue(result["lease_confirmed"])
                self.assertTrue(result["reservation_confirmed"])
                self.assertFalse(result["subnet_precheck"])
        self.assertFalse(evaluate(lan=[{"name": "IP_LAN", "scope": "192.168.0.0/31"}])[
            "subnet_precheck"])

    def test_duplicate_conflicting_lease_and_reservation_rows_fail(self):
        self.assertFalse(evaluate(clients=CLIENT * 2)["subnet_precheck"])
        other_ip_same_mac = CLIENT + [{"ipaddr": "192.168.0.136", "macaddr": MAC}]
        self.assertFalse(evaluate(clients=other_ip_same_mac)["subnet_precheck"])
        self.assertFalse(evaluate(reservations=RESERVATION * 2)["subnet_precheck"])
        conflict = RESERVATION + [{"ip": "192.168.0.135", "mac": "AA-BB-CC-DD-EE-02", "enable": "on"}]
        self.assertFalse(evaluate(reservations=conflict)["subnet_precheck"])
        another_ip = RESERVATION + [{"ip": "192.168.0.136", "mac": MAC, "enable": "on"}]
        self.assertFalse(evaluate(reservations=another_ip)["subnet_precheck"])

    def test_missing_disabled_or_unreadable_evidence_fails_closed(self):
        self.assertFalse(evaluate(reservations=[])["subnet_precheck"])
        self.assertFalse(evaluate(reservations=[dict(RESERVATION[0], enable="off")])["subnet_precheck"])
        self.assertFalse(evaluate(pi_addresses=[])["subnet_precheck"])
        self.assertFalse(evaluate(pi_addresses=None)["subnet_precheck"])
        self.assertFalse(evaluate(router=None)["subnet_precheck"])
        self.assertFalse(evaluate(lan=[])["subnet_precheck"])
        self.assertFalse(evaluate(lan=LAN * 2)["subnet_precheck"])
        self.assertFalse(evaluate(lan=[{"name": "IP_LAN", "scope": "bad scope"}])["subnet_precheck"])
        self.assertFalse(evaluate(candidate="10.0.0.135",
            clients=[dict(CLIENT[0], ipaddr="10.0.0.135")],
            reservations=[dict(RESERVATION[0], ip="10.0.0.135")],
            lan=[{"name": "IP_LAN", "scope": "10.0.0.0/7"}])["subnet_precheck"])

    def test_acl_precheck_fails_closed_for_existing_or_unreadable_rules(self):
        rule = {"name": "Private family rule", "policy": "drop", "zone": "lan",
                "iptype": "ipv4", "is_src": "ipgroup", "src": "NP_G_AABBCCDDEE01",
                "is_dst": "ipgroup", "dest": "IPGROUP_ANY", "service": "ALL", "enable": "on"}
        existing = evaluate(acl=[rule])
        self.assertTrue(existing["subnet_precheck"])
        self.assertFalse(existing["acl_precheck"])
        self.assertEqual(existing["acl_rule_count"], 1)
        self.assertFalse(existing["control_precheck"])
        unreadable = evaluate(acl={"unexpected": "response"})
        self.assertFalse(unreadable["acl_readable"])
        self.assertFalse(unreadable["control_precheck"])

    def test_non_private_and_non_unicast_candidates_are_rejected(self):
        for candidate in ("8.8.8.8", "169.254.1.2", "127.0.0.1", "224.0.0.1", "0.0.0.0",
                          "2001:db8::10", "not-an-address"):
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                evaluate(candidate=candidate)

    def test_pi_address_parser_keeps_exact_global_ipv4_hosts(self):
        addresses = pi_ipv4_addresses('[{"ifname":"lo","addr_info":[{"family":"inet",'
                                      '"local":"127.0.0.1","prefixlen":8,"scope":"host"}]},'
                                      '{"ifname":"eth0","addr_info":[{"family":"inet",'
                                      '"local":"192.168.0.157","prefixlen":24,"scope":"global"},'
                                      '{"family":"inet","local":"192.168.0.158",'
                                      '"prefixlen":24,"scope":"global"},{"family":"inet6",'
                                      '"local":"fe80::1","prefixlen":64,"scope":"link"}]}]')
        self.assertEqual(addresses, [ipaddress.ip_address("192.168.0.157"),
                                     ipaddress.ip_address("192.168.0.158")])

    def test_cli_uses_envelope_acl_read_and_does_not_print_candidate_identity(self):
        calls = []

        class FakeClient:
            def __init__(self, *_args): pass
            def session(self): return self
            def __enter__(self): return self
            def __exit__(self, *_args): return False
            def get(self, module, form):
                calls.append((module, form))
                return {("ipgroup", "ipscope_list"): LAN,
                        ("dhcps", "client"): CLIENT,
                        ("dhcps", "reservation"): RESERVATION}[(module, form)]
            def get_response(self, module, form):
                calls.append((module, form, "envelope"))
                return EMPTY_ACL

        cfg = SimpleNamespace(router=SimpleNamespace(
            enabled=True, host="192.168.0.1", cert_sha256="fingerprint",
            credentials_file="credentials.toml"))
        credentials = SimpleNamespace(username="router-user", password="router-password",
                                      cert_sha256="fingerprint")
        output = StringIO()
        ip_json = '[{"ifname":"eth0","addr_info":[{"family":"inet",' \
                  '"local":"192.168.0.157","prefixlen":24,"scope":"global"}]}]'
        with (mock.patch.object(router_pause_readiness.os, "geteuid", return_value=0, create=True),
              mock.patch.object(router_pause_readiness, "load", return_value=cfg),
              mock.patch.object(router_pause_readiness, "load_router_credentials", return_value=credentials),
              mock.patch.object(router_pause_readiness, "ER605Client", FakeClient),
              mock.patch.object(router_pause_readiness.subprocess, "run",
                                return_value=SimpleNamespace(stdout=ip_json)),
              mock.patch.object(sys, "argv", ["router_pause_readiness.py", "Spare test handset"]),
              redirect_stdout(output)):
            self.assertEqual(router_pause_readiness.main(), 0)

        self.assertIn(("access_ctl", "acl_inner", "envelope"), calls)
        self.assertIn("LAN candidate precheck: PASS", output.getvalue())
        self.assertIn("Current ACL order precheck: PASS", output.getvalue())
        self.assertIn("Read-only candidate/ACL precheck: PASS (packet enforcement UNVERIFIED)",
                      output.getvalue())
        self.assertIn("both WAN paths, or IPv6 behavior", output.getvalue())
        for private in ("192.168.0.135", MAC, "Spare test handset", "router-password"):
            self.assertNotIn(private, output.getvalue())


if __name__ == "__main__":
    unittest.main()
