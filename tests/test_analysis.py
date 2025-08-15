from core.analysis import Analyzer

def test_basic_rules(tmp_path):
    # Create temp rule files
    bad_ips = tmp_path / "bad_ips.txt"
    bad_ips.write_text("203.0.113.5\n")
    ja3 = tmp_path / "ja3_blacklist.json"
    ja3.write_text('{"bad_fingerprints": ["X"]}')

    a = Analyzer(
        rules_paths={"bad_ips": str(bad_ips), "ja3_blacklist": str(ja3)},
        thresholds={"beacon_min_events": 3, "beacon_max_jitter_ms": 2500},
    )

    evt_bad_ip = {"src_ip": "203.0.113.5", "ja3": "OK", "packet_timestamps": []}
    evt_bad_ja3 = {"src_ip": "1.2.3.4", "ja3": "X", "packet_timestamps": []}
    evt_ok = {"src_ip": "1.2.3.4", "ja3": "OK", "packet_timestamps": []}

    assert a.analyze(evt_bad_ip)["indicator"] == "bad_ip"
    assert a.analyze(evt_bad_ja3)["indicator"] == "ja3_blacklist"
    assert a.analyze(evt_ok) is None
