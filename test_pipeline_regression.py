"""Offline regressions: never publish, touch DNS, or use the production pool."""
import base64
import contextlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch, Mock

import main as cfnb
import push_api
import dnshe_sync


class PoolTests(unittest.TestCase):
    def test_matching_country_labels_are_not_deleted(self):
        nodes = [f"203.0.113.{i}:443#JP" for i in range(1, 7)]
        details = {n: {"country": "JP"} for n in nodes}
        actual, changed = cfnb.relabel_by_exit(nodes, nodes, details, {"JP"})
        self.assertEqual(actual, nodes)
        self.assertEqual(changed, [])

    def test_relabel_deduplicates_endpoint_not_label(self):
        nodes = ["203.0.113.1:443#JP", "203.0.113.1:443#SG"]
        actual, _ = cfnb.relabel_by_exit(nodes, nodes, {nodes[0]: {"country": "JP"}}, {"JP", "SG"})
        self.assertEqual(len(actual), 1)

    def test_relabel_preserves_measurement_identity(self):
        old, new = "203.0.113.1:443#JP", "203.0.113.1:443#SG"
        metrics = {old: 0.075}
        cfnb.remap_node_metrics([new], metrics)
        self.assertEqual(metrics[new], 0.075)

    def pipeline(self, *, count=6, bandwidth=True, synced=True, latency=0.075, country="JP", dry_run=False):
        nodes = [f"203.0.113.{i}:443#JP" for i in range(1, count + 1)]
        with tempfile.TemporaryDirectory() as temp, contextlib.ExitStack() as stack:
            output = Path(temp, "ip.txt")
            output.write_text("KEEP_OLD_POOL\n", encoding="utf-8")
            options = dict(ADDITIONAL_SOURCES=[{"url": "local-test", "enabled": True}],
                           PRE_FILTER_PORT_ENABLED=False, PRE_FILTER_BLOCKED_ENABLED=False,
                           FILTER_COUNTRIES_ENABLED=True, ALLOWED_COUNTRIES=["JP", "SG"],
                           USE_GLOBAL_MODE=True, GLOBAL_TOP_N=30, BANDWIDTH_CANDIDATES=80,
                           MAX_WORKERS=2, TEST_AVAILABILITY=True, MIN_POOL_NODES=5,
                           BANDWIDTH_RETRY_MAX=2, BANDWIDTH_RETRY_DELAY=0,
                           REGION_RESERVE_N=0, INCUMBENT_RATIO=0, STABILITY_BONUS=0,
                           CF_OFFICIAL_RATIO=0, OUTPUT_FILE=str(output), HANDSHAKE_MS={},
                           AD_HEADER_ENABLED=False, AD_FOOTER_ENABLED=False,
                           AD_PERLINE_ENABLED=False)
            stack.enter_context(patch.multiple(cfnb, **options))
            stack.enter_context(patch.object(cfnb, "fetch_additional_source", return_value=nodes))
            stack.enter_context(patch.object(cfnb, "calibrate_regions"))
            stack.enter_context(patch.object(cfnb, "load_cf_nets", return_value=[]))
            stack.enter_context(patch.object(cfnb, "test_node", side_effect=lambda n: (n, latency, 0, 1)))
            details = {n: {"country": country} for n in nodes}
            stack.enter_context(patch.object(cfnb, "availability_filter_with_retry", return_value=(nodes, {}, details)))
            stack.enter_context(patch.object(cfnb, "http_server_filter", return_value=(nodes, {}, {})))
            bw = [(n, 10.0 + i) for i, n in enumerate(nodes)] if bandwidth else []
            stack.enter_context(patch.object(cfnb, "bandwidth_filter", return_value=bw))
            stack.enter_context(patch.object(cfnb, "_load_pool_history", return_value=[]))
            history = stack.enter_context(patch.object(cfnb, "_save_pool_history"))
            dns = stack.enter_context(patch.object(cfnb, "batch_update_cloudflare_dns"))
            sync = stack.enter_context(patch.object(cfnb, "sync_to_github", return_value=synced))
            stack.enter_context(patch.object(cfnb, "send_wxpusher_notification"))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            try:
                status = cfnb.main(dry_run=dry_run)
            except SystemExit as exc:
                status = exc.code
            return status, output.read_text(encoding="utf-8"), sync.call_count, dns.call_count, history.call_count

    def test_valid_round_publishes_six_nodes(self):
        status, text, sync, dns, history = self.pipeline()
        self.assertEqual(status, 0)
        self.assertEqual(len(text.splitlines()), 6)
        self.assertEqual((sync, dns, history), (1, 1, 1))

    def test_dry_run_measures_without_any_publish_or_pool_write(self):
        status, text, *calls = self.pipeline(dry_run=True)
        self.assertEqual(status, 0)
        self.assertEqual(text, "KEEP_OLD_POOL\n")
        self.assertEqual(calls, [0, 0, 0])

    def test_zero_bandwidth_does_not_publish_tcp_only_nodes(self):
        status, text, *calls = self.pipeline(bandwidth=False)
        self.assertEqual(status, 4)
        self.assertEqual(text, "KEEP_OLD_POOL\n")
        self.assertEqual(calls, [0, 0, 0])

    def test_small_pool_preserves_old_pool_and_reports_failure(self):
        status, text, *calls = self.pipeline(count=3)
        self.assertEqual(status, 4)
        self.assertEqual(text, "KEEP_OLD_POOL\n")
        self.assertEqual(calls, [0, 0, 0])

    def test_empty_source_reports_failure(self):
        status, text, *calls = self.pipeline(count=0)
        self.assertNotEqual(status, 0)
        self.assertEqual(text, "KEEP_OLD_POOL\n")
        self.assertEqual(calls, [0, 0, 0])

    def test_github_failure_keeps_fresh_pool_but_reports_failure(self):
        status, text, sync, _, _ = self.pipeline(synced=False)
        self.assertEqual(status, 5)
        self.assertEqual(len(text.splitlines()), 6)
        self.assertEqual(sync, 1)

    def test_relabel_cannot_bypass_tun_gate(self):
        status, text, *calls = self.pipeline(latency=0.001, country="SG")
        self.assertEqual(status, 2)
        self.assertEqual(text, "KEEP_OLD_POOL\n")
        self.assertEqual(calls, [0, 0, 0])

    def test_latency_limit_remains_a_hard_gate(self):
        status, text, *calls = self.pipeline(latency=0.250)
        self.assertEqual(status, 4)
        self.assertEqual(text, "KEEP_OLD_POOL\n")
        self.assertEqual(calls, [0, 0, 0])

    def test_failed_atomic_replace_keeps_previous_pool(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp, "ip.txt")
            path.write_bytes(b"previous\n")
            with patch.object(cfnb.os, "replace", side_effect=OSError("simulated replace failure")):
                with self.assertRaises(OSError):
                    cfnb.write_ip_txt(["203.0.113.1:443#JP"], str(path), False, [], False, [], False, "")
            self.assertEqual(path.read_bytes(), b"previous\n")
            self.assertEqual(sorted(p.name for p in Path(temp).iterdir()), ["ip.txt"])


class BandwidthTests(unittest.TestCase):
    node = "203.0.113.1:443#JP"

    def measure(self, output, *, rc=0):
        result = subprocess.CompletedProcess([], rc, stdout=output.encode(), stderr=b"")
        with patch.object(cfnb.subprocess, "run", return_value=result) as call, patch.object(cfnb, "HANDSHAKE_MS", {}):
            value = cfnb.measure_bandwidth_curl(self.node)
            return value[1], dict(cfnb.HANDSHAKE_MS), call.call_args[0][0]

    def test_tls_score_does_not_count_tcp_twice(self):
        speed, timing, _ = self.measure("1048576 0.5 1.5 0.3 0.1 200 203.0.113.1")
        self.assertGreater(speed, 0)
        self.assertAlmostEqual(timing[self.node], 200, delta=1)

    def test_http_error_body_is_not_bandwidth(self):
        speed, _, _ = self.measure("1048576 0.5 1.5 0.3 0.1 503 203.0.113.1")
        self.assertEqual(speed, 0)

    def test_other_endpoint_cannot_pass_as_candidate(self):
        speed, _, _ = self.measure("1048576 0.5 1.5 0.3 0.1 200 203.0.113.2")
        self.assertEqual(speed, 0)

    def test_partial_download_stays_rejected(self):
        speed, _, _ = self.measure("1000 0.5 1.5 0.3 0.1 200 203.0.113.1")
        self.assertEqual(speed, 0)

    def test_template_host_is_pinned_and_redirect_is_not_followed(self):
        with patch.object(cfnb, "BANDWIDTH_URL_TEMPLATE", "https://download.example.test:{port}/?bytes={bytes}"):
            _, _, command = self.measure("1048576 0.5 1.5 0.3 0.1 200 203.0.113.1")
        self.assertIn("download.example.test:443:203.0.113.1", command)
        self.assertNotIn("-L", command)
        self.assertEqual(command[1], "-q")


class PublishingTests(unittest.TestCase):
    def test_api_ignores_inherited_dead_proxy(self):
        response = Mock()
        response.status = 200
        response.read.return_value = b"{}"
        manager = Mock()
        manager.__enter__ = Mock(return_value=response)
        manager.__exit__ = Mock(return_value=False)
        opener = Mock()
        opener.open.return_value = manager
        with patch.object(push_api.urllib.request, "build_opener", return_value=opener) as build:
            self.assertEqual(push_api.api("https://api.github.com/example", "test-placeholder"), (200, {}))
        self.assertEqual(build.call_args[0][0].proxies, {})

    def invoke(self, remote_same=True, verified=True):
        content = b"203.0.113.1:443#JP\n"
        def record(data):
            import hashlib
            sha = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
            return {"sha": sha, "content": base64.b64encode(data).decode(), "encoding": "base64"}
        initial = record(content if remote_same else b"old\n")
        reread = record(content if verified else b"wrong\n")
        with tempfile.TemporaryDirectory() as temp, contextlib.ExitStack() as stack:
            Path(temp, "ip.txt").write_bytes(content)
            stack.enter_context(patch.object(push_api, "HERE", temp))
            stack.enter_context(patch.object(push_api, "read_creds", return_value=("test-placeholder", "example", "example", "main")))
            stack.enter_context(patch.object(push_api.sys, "argv", ["push_api.py"]))
            responses = [(200, initial)] if remote_same else [(200, initial), (200, {"commit": {"sha": "example"}}), (200, reread)]
            api = stack.enter_context(patch.object(push_api, "api", side_effect=responses))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            result = push_api.main()
            return result, api.call_count

    def test_identical_content_is_noop(self):
        result, calls = self.invoke()
        self.assertEqual((result, calls), (0, 1))

    def test_update_requires_readback(self):
        result, calls = self.invoke(remote_same=False)
        self.assertEqual((result, calls), (0, 3))

    def test_readback_mismatch_fails(self):
        result, calls = self.invoke(remote_same=False, verified=False)
        self.assertEqual(result, 1)
        self.assertEqual(calls, 3)


class DnsSafetyTests(unittest.TestCase):
    def invoke(self, creation_status=200, visible=True, stale_after_delete=False):
        desired = "203.0.113.1"
        old = "203.0.113.2"
        events = []
        initial = {old: "old-record"}
        expanded = {old: "old-record", desired: "new-record"} if visible else initial
        final = expanded if stale_after_delete else {desired: "new-record"}
        reads = 0

        def listing(*args):
            nonlocal reads
            reads += 1
            events.append("list")
            if reads == 1:
                return initial, None
            if "delete" not in events:
                return expanded, None
            return final, None

        def call(endpoint, action, body=None, **kwargs):
            events.append(action)
            return (creation_status, "simulated") if action == "create" else (200, "simulated")

        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(dnshe_sync.sys, "argv", ["dnshe_sync.py", "--apply"]))
            stack.enter_context(patch.object(dnshe_sync, "read_pool", return_value=[desired]))
            stack.enter_context(patch.object(dnshe_sync, "find_subdomain", return_value=("test", "cf", "example.test")))
            stack.enter_context(patch.object(dnshe_sync, "list_a", side_effect=listing))
            stack.enter_context(patch.object(dnshe_sync, "call", side_effect=call))
            stack.enter_context(patch("time.sleep"))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            try:
                rc = dnshe_sync.main()
            except SystemExit as exc:
                rc = exc.code
        return rc, events

    def test_failed_create_cannot_delete_working_records(self):
        rc, events = self.invoke(creation_status=500, visible=False)
        self.assertNotEqual(rc, 0)
        self.assertNotIn("delete", events)

    def test_creation_not_visible_cannot_delete_working_records(self):
        rc, events = self.invoke(visible=False)
        self.assertNotEqual(rc, 0)
        self.assertNotIn("delete", events)

    def test_success_checks_new_records_before_deleting_old(self):
        rc, events = self.invoke()
        self.assertEqual(rc, 0)
        self.assertIn("list", events[events.index("create") + 1:events.index("delete")])

    def test_stale_old_records_are_not_reported_as_success(self):
        rc, events = self.invoke(stale_after_delete=True)
        self.assertNotEqual(rc, 0)


@unittest.skipUnless(os.name == "nt", "Windows cmd wrapper")
class WrapperTests(unittest.TestCase):
    def run_wrapper(self, main_rc=0, dns_rc=0, env_rc=0, fetch_rc=0, credentials="both"):
        # Execute the real wrapper only in a temporary directory, with all stages replaced.
        # No --shutdown, no networking, no service operations, no production pool.
        wrapper = Path(__file__).with_name("run_and_shutdown.cmd").read_text(encoding="utf-8")
        wrapper = "\n".join("set PY=" + sys.executable if line.startswith("set PY=") else line
                            for line in wrapper.splitlines())
        with tempfile.TemporaryDirectory(prefix="cfnb wrapper test ") as temp:
            root = Path(temp)
            script = root / "run.cmd"
            script.write_text(wrapper, encoding="utf-8", newline="\r\n")
            for name, code in [("e2e_test.py", env_rc), ("fetch_sources.py", fetch_rc),
                               ("main.py", main_rc), ("dnshe_sync.py", dns_rc)]:
                text = ("from pathlib import Path\nimport sys\n"
                        f"with Path('stages.txt').open('a') as f: f.write({name!r} + '\\n')\n")
                if name == "main.py" and code in (0, 5):
                    text += "Path('ip.txt').write_text('fresh\\n')\n"
                text += f"sys.exit({code})\n"
                (root / name).write_text(text, encoding="utf-8")
            (root / "ip.txt").write_text("previous\n", encoding="utf-8")
            if credentials != "none":
                env = "DNSHE_KEY=test-placeholder\n"
                if credentials == "both":
                    env += "DNSHE_SECRET=test-placeholder\n"
                (root / "dnshe.env").write_text(env, encoding="utf-8")
            proc = subprocess.run([os.environ.get("COMSPEC", "cmd.exe"), "/d", "/c", str(script)],
                                  cwd=temp, capture_output=True, timeout=25)
            stages = (root / "stages.txt").read_text().splitlines() if (root / "stages.txt").exists() else []
            log = (root / "scheduled_run.log").read_text(encoding="utf-8", errors="replace") if (root / "scheduled_run.log").exists() else ""
            return proc.returncode, stages, log, proc.stdout.decode("utf-8", errors="replace")

    def test_full_success(self):
        rc, stages, log, stdout = self.run_wrapper()
        self.assertEqual(rc, 0, (log, stdout))
        self.assertEqual(stages, ["e2e_test.py", "fetch_sources.py", "main.py", "dnshe_sync.py"])

    def test_failed_or_polluted_round_never_syncs_previous_pool(self):
        for main_rc in (1, 2, 4):
            with self.subTest(main_rc=main_rc):
                rc, stages, log, _ = self.run_wrapper(main_rc=main_rc)
                self.assertEqual(rc, main_rc, log)
                self.assertNotIn("dnshe_sync.py", stages)

    def test_github_failure_still_syncs_fresh_dns_and_stays_visible(self):
        rc, stages, log, _ = self.run_wrapper(main_rc=5)
        self.assertEqual(rc, 5, log)
        self.assertIn("dnshe_sync.py", stages)

    def test_dns_and_dual_failure_return_nonzero(self):
        for main_rc, expected in [(0, 6), (5, 7)]:
            with self.subTest(main_rc=main_rc):
                rc, _, log, _ = self.run_wrapper(main_rc=main_rc, dns_rc=1)
                self.assertEqual(rc, expected, log)

    def test_missing_credentials_fail_without_running_dns(self):
        for credentials in ("none", "key-only"):
            with self.subTest(credentials=credentials):
                rc, stages, log, _ = self.run_wrapper(credentials=credentials)
                self.assertEqual(rc, 6, log)
                self.assertNotIn("dnshe_sync.py", stages)

    def test_environment_and_fetch_failures_stop_downstream(self):
        for env_rc, fetch_rc, expected, count in [(1, 0, 2, 1), (0, 1, 3, 2)]:
            with self.subTest(env_rc=env_rc, fetch_rc=fetch_rc):
                rc, stages, log, _ = self.run_wrapper(env_rc=env_rc, fetch_rc=fetch_rc)
                self.assertEqual(rc, expected, log)
                self.assertEqual(len(stages), count)


class LxReserveTests(unittest.TestCase):
    """良心云保底（2026-09-25 拍板）：放宽口径必须放得进主池拒收的样本，
    也必须仍然拒收垃圾；名额选取必须去重、封顶、强制 #LX 标签。"""
    node = "203.0.113.1:443#JP"

    def measure(self, output, *, rc=0, **kwargs):
        result = subprocess.CompletedProcess([], rc, stdout=output.encode(), stderr=b"")
        with patch.object(cfnb.subprocess, "run", return_value=result) as call, \
                patch.object(cfnb, "HANDSHAKE_MS", {}):
            value = cfnb.measure_bandwidth_curl(self.node, **kwargs)
            return value[1], dict(cfnb.HANDSHAKE_MS), call.call_args[0][0]

    def test_relaxed_gates_admit_what_strict_rejects(self):
        # 0.8MB 下载 + TLS 2.4s：主池口径（整 1MB / TLS <=2.0s）拒收；
        # 放宽 30%（>=0.7MB / <=2.6s）后必须放行——这就是保底名额存在的意义。
        strict, _, _ = self.measure("838861 0.5 1.5 2.4 0.1 200 203.0.113.1")
        relaxed, _, _ = self.measure(
            "838861 0.5 1.5 2.4 0.1 200 203.0.113.1",
            min_bytes=cfnb.LX_RESERVE_MIN_BYTES, tls_max_s=cfnb.LX_RESERVE_MAX_TLS_S)
        self.assertEqual(strict, 0)
        self.assertGreater(relaxed, 0)

    def test_relaxed_gates_still_reject_garbage(self):
        # TLS 2.7s 超放宽线、700000 字节低于 0.7MB 下限：放宽口径也必须拒收。
        self.assertEqual(self.measure(
            "838861 0.5 1.5 2.7 0.1 200 203.0.113.1",
            min_bytes=cfnb.LX_RESERVE_MIN_BYTES, tls_max_s=cfnb.LX_RESERVE_MAX_TLS_S)[0], 0)
        self.assertEqual(self.measure(
            "700000 0.5 1.5 2.4 0.1 200 203.0.113.1",
            min_bytes=cfnb.LX_RESERVE_MIN_BYTES, tls_max_s=cfnb.LX_RESERVE_MAX_TLS_S)[0], 0)

    def test_strict_default_is_unchanged_by_relax_params(self):
        # 不传参数=主池口径：整档 1MB 才收（沿用 Codex 严格化语义，防放宽参数泄漏默认行为）
        self.assertEqual(self.measure("838861 0.5 1.5 0.4 0.1 200 203.0.113.1")[0], 0)
        self.assertGreater(self.measure("1048576 0.5 1.5 0.4 0.1 200 203.0.113.1")[0], 0)

    def test_select_lx_reserve_dedups_caps_and_labels(self):
        measured = [("1.1.1.1:443#JP", 5.0), ("2.2.2.2:443#SG", 4.0),
                    ("3.3.3.3:443#US", 3.0), ("4.4.4.4:443#TW", 2.0)]
        main_pool = ["2.2.2.2:443#SG", "5.5.5.5:443#JP"]
        picked = cfnb.select_lx_reserve(measured, main_pool, 2)
        self.assertEqual(picked, ["1.1.1.1:443#LX", "3.3.3.3:443#LX"])

    def test_select_lx_reserve_empty_or_zero_slots(self):
        self.assertEqual(cfnb.select_lx_reserve([], ["1.1.1.1:443#JP"], 10), [])
        self.assertEqual(
            cfnb.select_lx_reserve([("1.1.1.1:443#JP", 5.0)], [], 0), [])
    def test_measure_lx_reserve_reads_and_picks(self):
        # 回归：2026-09-26 凌晨跑批实测抓到 io.open 未导入 NameError（pipeline exit=1）。
        # 本测试走 measure_lx_reserve 的真实读文件路径，防止同类盲区复发。
        import os as _os
        import tempfile as _tf
        fd, path = _tf.mkstemp(suffix=".txt")
        with _os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("203.0.113.9:443#JP\n")
        try:
            with patch.object(cfnb, "LX_RESERVE_ENABLED", True), \
                    patch.object(cfnb, "LX_RESERVE_FILE", path), \
                    patch.object(cfnb, "LX_RESERVE_SLOTS", 10), \
                    patch.object(cfnb, "test_tcp_latency", return_value=(0.05, True)), \
                    patch.object(cfnb, "measure_bandwidth_curl",
                                 return_value=("203.0.113.9:443#JP", 5.0)):
                picked = cfnb.measure_lx_reserve([])
            self.assertEqual(picked, ["203.0.113.9:443#LX"])
        finally:
            _os.unlink(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)

