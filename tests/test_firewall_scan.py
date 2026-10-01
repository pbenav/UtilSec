"""Tests for firewall rule scanning and startup synchronisation.

These cover the three bugs that made reconciliation between the live firewall
and the bans table impossible:

* ``_extract_ip_from_iptables_line`` returned a *network address* (no CIDR) and
  could return the local destination address instead of the source.
* ``_sync_bans_with_firewall`` read ``get_firewall_rules()``, which filters out
  UtilSec rules, so it never saw a single rule to restore.
* the nft backend never created its table/set, and its scanner only accepted
  bare addresses.
"""

import os
import tempfile
import time
import unittest
from unittest import mock

import ipaddress

from core.firewall import FirewallManager, FirewallRuleInfo, _ban_key_variants, _nft_set_for
from core.models import BanRecord
from core.storage import StorageManager


class TestSourceExtraction(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.fw = FirewallManager(backend="auto", dry_run=True, storage=None,
                                  audit_dir=self.tmp_dir.name)

    def tearDown(self):
        self.fw.stop()
        self.tmp_dir.cleanup()

    def test_iptables_source_keeps_cidr_prefix(self):
        cases = [
            # (iptables -L -n -v --line-numbers line, expected source)
            ("1        0     0 DROP  all  --  *  *  45.156.129.0/24  0.0.0.0/0",
             "45.156.129.0/24"),
            ("2      120  7200 DROP  all  --  *  *  8.8.8.8/32  0.0.0.0/0",
             "8.8.8.8"),
            ("3        0     0 DROP  all  --  *  *  10.0.0.0/8  0.0.0.0/0",
             "10.0.0.0/8"),
            ("4        0     0 DROP  all  --  *  *  2001:db8:1::/64  ::/0",
             "2001:db8:1::/64"),
            ("5     10  600 fail2ban-ssh  all  --  *  *  203.0.113.9/32  0.0.0.0/0",
             "203.0.113.9"),
        ]
        for line, expected in cases:
            with self.subTest(line=line):
                self.assertEqual(self.fw._extract_ip_from_iptables_line(line), expected)

    def test_iptables_destination_is_never_reported_as_source(self):
        # A rule with no -s matches everything; the address on the right is the
        # local destination. Reporting it used to put our own IP in the panel.
        line = "4        0     0 DROP  all  --  *  *  0.0.0.0/0  192.168.1.100"
        self.assertEqual(self.fw._extract_ip_from_iptables_line(line), "")

    def test_iptables_unrecognized_layout_falls_back_to_source_column(self):
        # Without --line-numbers there are 9 columns, source at index 7.
        line = "7  0  DROP  all  --  *  *  192.168.5.0/24  0.0.0.0/0"
        self.assertEqual(self.fw._extract_ip_from_iptables_line(line), "192.168.5.0/24")

    def test_ufw_source_extraction(self):
        cases = [
            ("[ 1] 22/tcp    DENY IN    192.168.1.0/24", "192.168.1.0/24"),
            ("[ 2] Anywhere  DENY IN     1.2.3.4", "1.2.3.4"),
            ("[ 3] Anywhere  DENY IN     Anywhere", ""),
            ("[ 4] 80/tcp    DENY OUT    10.0.0.5", "10.0.0.5"),
        ]
        for line, expected in cases:
            with self.subTest(line=line):
                self.assertEqual(self.fw._extract_ip_from_ufw_line(line), expected)

    def test_ban_key_variants_bridge_prefix_forms(self):
        self.assertEqual(set(_ban_key_variants("1.2.3.4")),
                         {"1.2.3.4", "1.2.3.4/32"})
        self.assertEqual(set(_ban_key_variants("1.2.3.0/24")), {"1.2.3.0/24"})
        self.assertEqual(set(_ban_key_variants("2001:db8::1")),
                         {"2001:db8::1", "2001:db8::1/128"})
        self.assertEqual(_ban_key_variants(""), ())

    def test_nft_set_selection_by_family(self):
        self.assertEqual(_nft_set_for("1.2.3.4"), "utilsec_bans4")
        self.assertEqual(_nft_set_for("1.2.3.0/24"), "utilsec_bans4")
        self.assertEqual(_nft_set_for("2001:db8::1/64"), "utilsec_bans6")


class TestNftScan(unittest.TestCase):

    RULESET = """
table inet utilsec {
    set utilsec_bans4 {
        type ipv4_addr
        flags interval
        elements = { 45.156.129.0/24,
            9.9.9.9,
            185.220.101.0/24 }
    }
    set utilsec_bans6 {
        type ipv6_addr
        flags interval
        elements = { 2001:db8::/32 }
    }
    chain input {
        type filter hook input priority -10; policy accept;
        ip saddr @utilsec_bans4 drop
        ip6 saddr @utilsec_bans6 drop
    }
}
"""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.fw = FirewallManager(backend="auto", dry_run=True, storage=None,
                                  audit_dir=self.tmp_dir.name)

    def tearDown(self):
        self.fw.stop()
        self.tmp_dir.cleanup()

    def _scan(self, output: str, returncode: int = 0):
        result = mock.Mock(returncode=returncode, stdout=output.encode())
        with mock.patch("core.firewall.subprocess.run", return_value=result):
            return self.fw._scan_nft_rules()

    def test_scan_accepts_cidr_and_wrapped_elements(self):
        rules = self._scan(self.RULESET)
        self.assertEqual({r.ip for r in rules},
                         {"45.156.129.0/24", "9.9.9.9", "185.220.101.0/24",
                          "2001:db8::/32"})
        self.assertTrue(all(r.source == "utilsec" and r.backend == "nft" for r in rules))

    def test_scan_single_element_set_is_not_dropped(self):
        output = (
            "table inet utilsec {\n"
            "  set utilsec_bans4 {\n"
            "    type ipv4_addr\n"
            "    flags interval\n"
            "    elements = { 1.2.3.0/24 }\n"
            "  }\n"
            "}\n"
        )
        self.assertEqual([r.ip for r in self._scan(output)], ["1.2.3.0/24"])

    def test_scan_ignores_foreign_tables_and_errors(self):
        self.assertEqual(self._scan("table inet filter {\n}\n"), [])
        self.assertEqual(self._scan(self.RULESET, returncode=1), [])


class TestStartupSync(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self._prev_audit_dir = os.environ.get("UTILSEC_AUDIT_DIR")
        os.environ["UTILSEC_AUDIT_DIR"] = self.tmp_dir.name
        self.db_path = os.path.join(self.tmp_dir.name, "sync.db")
        self.storage = StorageManager(db_path=self.db_path)
        self.fw = FirewallManager(backend="auto", dry_run=True, storage=self.storage,
                                  audit_dir=self.tmp_dir.name)

    def tearDown(self):
        self.fw.stop()
        self.storage.close()
        if self._prev_audit_dir is None:
            os.environ.pop("UTILSEC_AUDIT_DIR", None)
        else:
            os.environ["UTILSEC_AUDIT_DIR"] = self._prev_audit_dir
        self.tmp_dir.cleanup()

    @staticmethod
    def _rule(ip, backend="iptables"):
        return FirewallRuleInfo(ip=ip, source="utilsec", reason="UtilSec ban rule",
                                rule_num=1, backend=backend)

    def _save(self, ip, duration=3600, age=10, status="BANNED"):
        self.storage.save_ban(BanRecord(
            ip=ip, reason="old", matched_pattern="", attack_count=1,
            banned_at=time.time() - age, ban_duration=duration, status=status,
        ))

    def test_rule_only_in_firewall_is_restored_with_original_ttl(self):
        self._save("7.7.7.0/24", duration=3600, age=100)
        self.fw._scan_utilsec_rules = lambda: [self._rule("7.7.7.0/24")]
        self.fw._sync_bans_with_firewall()
        self.assertIn("7.7.7.0/24", self.fw.active_bans)
        # TTL must be preserved, not reset to "now"
        self.assertLess(self.fw.active_bans["7.7.7.0/24"].banned_at,
                        time.time() - 50)

    def test_prefix_mismatch_between_firewall_and_db_still_matches(self):
        # iptables prints 1.2.3.4/32, the bans table keys the row as 1.2.3.4
        self._save("1.2.3.4", duration=3600)
        self.fw._scan_utilsec_rules = lambda: [self._rule("1.2.3.4/32")]
        self.fw._sync_bans_with_firewall()
        self.assertIn("1.2.3.0/24", self.fw.active_bans)

    def test_expired_ban_is_dropped_and_row_marked(self):
        self._save("7.7.7.0/24", duration=60, age=3600)
        self.fw._scan_utilsec_rules = lambda: [self._rule("7.7.7.0/24")]
        self.fw._sync_bans_with_firewall()
        self.assertNotIn("7.7.7.0/24", self.fw.active_bans)
        self.assertEqual(self.storage.load_active_bans(), {})

    def test_whitelisted_rule_is_removed_and_row_marked(self):
        fw = FirewallManager(
            backend="auto", dry_run=True, storage=self.storage,
            audit_dir=self.tmp_dir.name,
            whitelist_networks=[ipaddress.ip_network("9.9.9.0/24")],
        )
        try:
            self._save("9.9.9.0/24", duration=3600)
            fw._scan_utilsec_rules = lambda: [self._rule("9.9.9.0/24")]
            fw._sync_bans_with_firewall()
            self.assertNotIn("9.9.9.0/24", fw.active_bans)
            self.assertEqual(self.storage.load_active_bans(), {})
        finally:
            fw.stop()

    def test_orphan_rule_without_db_row_is_adopted(self):
        self.fw._scan_utilsec_rules = lambda: [self._rule("5.5.5.0/24")]
        self.fw._sync_bans_with_firewall()
        self.assertIn("5.5.5.0/24", self.fw.active_bans)
        adopted = self.fw.active_bans["5.5.5.0/24"]
        self.assertEqual(adopted.ban_duration, 0)
        persisted = self.storage.load_active_bans()
        self.assertIn("5.5.5.0/24", persisted)
        self.assertEqual(persisted["5.5.5.0/24"].ban_duration, 0)

    def test_get_firewall_rules_still_hides_utilsec_rules(self):
        """The [U] panel must keep showing only *external* rules."""
        rules = [
            self._rule("5.5.5.0/24"),
            FirewallRuleInfo(ip="6.6.6.6", source="fail2ban", reason="jail",
                             backend="iptables"),
        ]
        with mock.patch.object(self.fw, "_scan_iptables_rules", return_value=rules):
            was_dry_run, backend = self.fw.dry_run, self.fw.active_backend
            self.fw.dry_run, self.fw.active_backend = False, "iptables"
            try:
                ips = {r.ip for r in self.fw.get_firewall_rules()}
            finally:
                self.fw.dry_run, self.fw.active_backend = was_dry_run, backend
        self.assertEqual(ips, {"6.6.6.6"})


class TestNftInfra(unittest.TestCase):

    READY_TABLE = (
        "table inet utilsec {\n"
        "    set utilsec_bans4 {\n"
        "        type ipv4_addr\n"
        "        flags interval\n"
        "    }\n"
        "    set utilsec_bans6 {\n"
        "        type ipv6_addr\n"
        "        flags interval\n"
        "    }\n"
        "}\n"
    )

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.fw = FirewallManager(
            backend="auto", dry_run=True, storage=None, audit_dir=self.tmp_dir.name,
            whitelist_networks=[ipaddress.ip_network("10.0.0.0/8")],
        )

    def tearDown(self):
        self.fw.stop()
        self.tmp_dir.cleanup()

    def _run(self, probe_ok=True):
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(list(cmd))
            if "list" in cmd and "table" in cmd:
                return mock.Mock(returncode=0 if probe_ok else 1,
                                 stdout=self.READY_TABLE.encode() if probe_ok else b"",
                                 stderr=b"")
            return mock.Mock(returncode=0, stdout=b"", stderr=b"")

        with mock.patch("core.firewall.subprocess.run", side_effect=fake_run):
            self.fw._ensure_nft_infra()
        return [" ".join(c) for c in calls]

    def test_creates_table_sets_chain_and_ordered_rules(self):
        joined = self._run()
        self.assertTrue(any("add table inet utilsec" in c for c in joined))
        self.assertTrue(any("add set inet utilsec utilsec_bans4" in c for c in joined))
        self.assertTrue(any("add set inet utilsec utilsec_bans6" in c for c in joined))
        self.assertTrue(any("flush chain inet utilsec input" in c for c in joined))
        # Whitelist ACCEPT must be installed before the drops
        accept = next(i for i, c in enumerate(joined)
                      if "add rule" in c and c.endswith("accept"))
        drop4 = next(i for i, c in enumerate(joined) if "@utilsec_bans4 drop" in c)
        drop6 = next(i for i, c in enumerate(joined) if "@utilsec_bans6 drop" in c)
        self.assertLess(accept, drop4)
        self.assertLess(drop4, drop6)
        self.assertIn("ip saddr 10.0.0.0/8 accept", joined[accept])

    def test_infra_is_built_only_once(self):
        self._run()
        before = self.fw._nft_infra_ready
        self.assertTrue(before)
        with mock.patch("core.firewall.subprocess.run") as run:
            self.fw._ensure_nft_infra()
        run.assert_not_called()

    def test_failure_to_create_table_is_reported_once(self):
        with self.assertLogs("UtilSec.Firewall", level="ERROR") as logs:
            joined = self._run(probe_ok=False)
        self.assertTrue(any("NOT enforced" in m for m in logs.output))
        # Still no rules were added against a missing table
        self.assertFalse(any("add rule" in c for c in joined))

    def test_ban_targets_the_family_specific_set(self):
        from core.firewall import NFT_SETS, _nft_set_for
        self.assertEqual(_nft_set_for("192.0.2.0/24"), NFT_SETS[4])
        self.assertEqual(_nft_set_for("2001:db8::/48"), NFT_SETS[6])


if __name__ == "__main__":
    unittest.main()
