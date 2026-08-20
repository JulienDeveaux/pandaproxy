"""Tests for the merged printer-state cache and MQTT topic matching."""

import json

import pytest

from pandaproxy.mqtt_proxy import topic_matches
from pandaproxy.state_cache import (
    MAX_CACHEABLE_PAYLOAD,
    PrinterStateCache,
    as_ipv4,
    decode_ipv4,
    deep_merge,
    encode_ipv4,
    is_ipv4,
    payload_is_full_state,
    payload_reports_ip,
    rewrite_reported_ip,
)

# Captured from a real P1S full state dump: the printer encodes its own
# address as a little-endian uint32, and slicers read it to pick an upload
# target. 302098624 is 192.168.1.18.
REAL_IP_ENCODED = 302098624
REAL_IP = "192.168.1.18"


class TestDeepMerge:
    """Merge semantics for printer report deltas."""

    def test_merges_nested_keys_without_dropping_siblings(self):
        base = {"print": {"gcode_state": "RUNNING", "bed_temper": 60}}
        deep_merge(base, {"print": {"bed_temper": 65}})
        assert base == {"print": {"gcode_state": "RUNNING", "bed_temper": 65}}

    def test_adds_new_sections(self):
        base = {"print": {"a": 1}}
        deep_merge(base, {"info": {"b": 2}})
        assert base == {"print": {"a": 1}, "info": {"b": 2}}

    def test_lists_are_replaced_not_merged(self):
        # The printer resends whole arrays (e.g. ams.tray), so element-wise
        # merging would resurrect entries the printer just removed.
        base = {"print": {"ams": {"tray": [{"id": 0}, {"id": 1}]}}}
        deep_merge(base, {"print": {"ams": {"tray": [{"id": 0}]}}})
        assert base["print"]["ams"]["tray"] == [{"id": 0}]

    def test_scalar_replaces_dict(self):
        base = {"print": {"ams": {"tray": []}}}
        deep_merge(base, {"print": {"ams": None}})
        assert base["print"]["ams"] is None


class TestPrinterStateCache:
    """Accumulation and replay of printer state."""

    def test_starts_empty(self):
        cache = PrinterStateCache()
        assert not cache.has_state
        assert cache.snapshot() is None
        assert cache.update_count == 0

    def test_accumulates_deltas_into_full_state(self):
        cache = PrinterStateCache()
        # Full dump from pushall, then two deltas as the print progresses.
        cache.update(
            json.dumps(
                {"print": {"gcode_state": "IDLE", "mc_percent": 0, "nozzle_temper": 25}}
            ).encode()
        )
        cache.update(json.dumps({"print": {"gcode_state": "RUNNING"}}).encode())
        cache.update(json.dumps({"print": {"mc_percent": 42}}).encode())

        snapshot = cache.snapshot()
        assert snapshot is not None
        state = json.loads(snapshot)
        assert state["print"] == {
            "gcode_state": "RUNNING",
            "mc_percent": 42,
            "nozzle_temper": 25,
        }
        assert cache.update_count == 3

    def test_snapshot_strips_sequence_id(self):
        # Replaying a stale sequence_id can make a client believe one of its
        # own commands was acknowledged.
        cache = PrinterStateCache()
        cache.update(json.dumps({"print": {"sequence_id": "17", "a": 1}}).encode())
        state = json.loads(cache.snapshot())
        assert "sequence_id" not in state["print"]
        assert state["print"]["a"] == 1

    def test_snapshot_is_a_copy(self):
        cache = PrinterStateCache()
        cache.update(json.dumps({"print": {"a": 1}}).encode())
        first = json.loads(cache.snapshot())
        first["print"]["a"] = 999
        assert json.loads(cache.snapshot())["print"]["a"] == 1

    def test_rejects_non_json(self):
        cache = PrinterStateCache()
        assert cache.update(b"\x00\x01not json") is False
        assert not cache.has_state

    def test_rejects_json_that_is_not_an_object(self):
        cache = PrinterStateCache()
        assert cache.update(b"[1, 2, 3]") is False
        assert not cache.has_state

    def test_rejects_empty_and_oversized_payloads(self):
        cache = PrinterStateCache()
        assert cache.update(b"") is False
        assert cache.update(b"x" * (MAX_CACHEABLE_PAYLOAD + 1)) is False
        assert not cache.has_state

    def test_clear_drops_state(self):
        cache = PrinterStateCache()
        cache.update(json.dumps({"print": {"a": 1}}).encode())
        cache.clear()
        assert not cache.has_state
        assert cache.snapshot() is None
        assert cache.update_count == 0


class TestReportedIpRewriting:
    """The printer's advertised address must point at the proxy."""

    def test_encoding_matches_the_captured_value(self):
        assert encode_ipv4(REAL_IP) == REAL_IP_ENCODED
        assert decode_ipv4(REAL_IP_ENCODED) == REAL_IP

    def test_encode_decode_round_trip(self):
        for address in ("10.0.0.1", "172.16.5.9", "192.168.1.50", "127.0.0.1"):
            assert decode_ipv4(encode_ipv4(address)) == address

    def test_rewrites_the_reported_address(self):
        state = {
            "print": {
                "net": {"conf": 0, "info": [{"ip": REAL_IP_ENCODED, "mask": 16777215}]}
            }
        }
        assert rewrite_reported_ip(state, "192.168.1.50") == 1
        entry = state["print"]["net"]["info"][0]
        assert decode_ipv4(entry["ip"]) == "192.168.1.50"
        # Everything else must survive untouched.
        assert entry["mask"] == 16777215
        assert state["print"]["net"]["conf"] == 0

    def test_rewrites_every_interface(self):
        state = {
            "print": {
                "net": {
                    "info": [{"ip": REAL_IP_ENCODED}, {"ip": encode_ipv4("10.0.0.7")}]
                }
            }
        }
        assert rewrite_reported_ip(state, "192.168.1.50") == 2

    def test_already_correct_address_is_not_counted(self):
        state = {"print": {"net": {"info": [{"ip": encode_ipv4("192.168.1.50")}]}}}
        assert rewrite_reported_ip(state, "192.168.1.50") == 0

    @pytest.mark.parametrize(
        "state",
        [
            {},
            {"print": {}},
            {"print": {"net": {}}},
            {"print": {"net": {"info": []}}},
            {"print": {"net": {"info": "not-a-list"}}},
            {"print": {"net": {"info": [{"no_ip_here": 1}]}}},
            {"print": "not-a-dict"},
        ],
    )
    def test_absent_or_malformed_sections_are_left_alone(self, state):
        assert rewrite_reported_ip(state, "192.168.1.50") == 0

    def test_snapshot_rewrites_when_asked(self):
        cache = PrinterStateCache()
        cache.update(
            json.dumps(
                {"print": {"net": {"info": [{"ip": REAL_IP_ENCODED}]}, "a": 1}}
            ).encode()
        )
        state = json.loads(cache.snapshot(advertise_ip="192.168.1.50"))
        assert decode_ipv4(state["print"]["net"]["info"][0]["ip"]) == "192.168.1.50"

    def test_snapshot_leaves_the_address_alone_by_default(self):
        cache = PrinterStateCache()
        cache.update(
            json.dumps({"print": {"net": {"info": [{"ip": REAL_IP_ENCODED}]}}}).encode()
        )
        state = json.loads(cache.snapshot())
        assert state["print"]["net"]["info"][0]["ip"] == REAL_IP_ENCODED

    def test_rewriting_does_not_corrupt_the_cache(self):
        # The rewrite must apply to the copy handed out, never to the
        # authoritative state, or the printer's real address would be lost.
        cache = PrinterStateCache()
        cache.update(
            json.dumps({"print": {"net": {"info": [{"ip": REAL_IP_ENCODED}]}}}).encode()
        )
        cache.snapshot(advertise_ip="192.168.1.50")
        state = json.loads(cache.snapshot())
        assert state["print"]["net"]["info"][0]["ip"] == REAL_IP_ENCODED

    def test_payload_precheck_detects_network_reports(self):
        assert payload_reports_ip(b'{"print":{"net":{"info":[]}}}')

    def test_payload_precheck_skips_ordinary_deltas(self):
        # The real delta shape seen on the wire: no network section.
        delta = (
            b'{"print":{"bed_temper":38.9,"command":"push_status",'
            b'"msg":1,"sequence_id":"35947"}}'
        )
        assert not payload_reports_ip(delta)


class TestTopicMatches:
    """MQTT topic filter matching, including wildcards."""

    REPORT = "device/01P00A000000001/report"

    def test_exact_match(self):
        assert topic_matches(self.REPORT, self.REPORT)

    def test_hash_wildcard_matches_everything(self):
        assert topic_matches("#", self.REPORT)

    def test_hash_wildcard_matches_suffix(self):
        assert topic_matches("device/#", self.REPORT)

    def test_plus_wildcard_matches_single_level(self):
        assert topic_matches("device/+/report", self.REPORT)

    def test_plus_does_not_span_levels(self):
        assert not topic_matches("device/+", self.REPORT)

    def test_different_topic_does_not_match(self):
        assert not topic_matches("device/01P00A000000001/request", self.REPORT)

    def test_longer_filter_does_not_match(self):
        assert not topic_matches(f"{self.REPORT}/extra", self.REPORT)


class TestIpv4Validation:
    """A bad advertise address must never reach inet_aton."""

    @pytest.mark.parametrize(
        "value", ["192.168.1.18", "10.0.0.1", "127.0.0.1", "255.255.255.255"]
    )
    def test_accepts_dotted_quads(self, value):
        assert is_ipv4(value)

    @pytest.mark.parametrize(
        "value",
        [
            "nas.lan",
            "::1",
            "fe80::1",
            "::ffff:192.168.1.10",
            "",
            "192.168.1",
            "192.168.1.256",
            "1.2.3.4.5",
        ],
    )
    def test_rejects_everything_else(self, value):
        # inet_aton would accept "192.168.1" and silently expand it to
        # 192.168.0.1, and raise OSError on the rest - which used to tear the
        # upstream MQTT connection down on every report.
        assert not is_ipv4(value)

    def test_encode_refuses_non_ipv4(self):
        with pytest.raises(ValueError, match="not an IPv4 address"):
            encode_ipv4("nas.lan")

    def test_rewrite_relays_untouched_on_a_bad_address(self):
        state = {"print": {"net": {"info": [{"ip": REAL_IP_ENCODED}]}}}
        assert rewrite_reported_ip(state, "nas.lan") == 0
        assert state["print"]["net"]["info"][0]["ip"] == REAL_IP_ENCODED


class TestCommandAckFiltering:
    """A command result must not be replayed to unrelated clients."""

    def test_acks_are_not_merged(self):
        cache = PrinterStateCache()
        cache.update(json.dumps({"print": {"gcode_state": "IDLE"}}).encode())
        merged = cache.update(
            json.dumps(
                {
                    "print": {
                        "command": "project_file",
                        "result": "FAIL",
                        "reason": "wrong file",
                        "sequence_id": "42",
                    }
                }
            ).encode()
        )
        assert merged is False

        state = json.loads(cache.snapshot())
        assert state["print"] == {"gcode_state": "IDLE"}

    def test_ack_fields_are_stripped_from_the_snapshot(self):
        # Defence in depth: even if one slipped into the cache, it must not
        # look like an answer to the new client's own command.
        cache = PrinterStateCache()
        cache.update(json.dumps({"print": {"gcode_state": "RUNNING"}}).encode())
        cache._state["print"]["result"] = "SUCCESS"
        cache._state["print"]["reason"] = "stale"
        state = json.loads(cache.snapshot())
        assert "result" not in state["print"]
        assert "reason" not in state["print"]

    def test_real_status_pushes_still_merge(self):
        cache = PrinterStateCache()
        assert cache.update(
            json.dumps(
                {"print": {"command": "push_status", "msg": 1, "bed_temper": 38.9}}
            ).encode()
        )
        assert json.loads(cache.snapshot())["print"]["bed_temper"] == 38.9


class TestSnapshotFullDumpMarker:
    """A replayed snapshot must not be labelled as a delta."""

    def test_msg_is_forced_to_zero(self):
        # Bambu sets msg 0 on a full pushall and 1 on deltas, and clients gate
        # full-state ingestion on 0. Replaying a complete document still
        # marked as a delta made them ignore it and ask the printer directly -
        # exactly the load the cache removes.
        cache = PrinterStateCache()
        cache.update(json.dumps({"print": {"msg": 0, "gcode_state": "IDLE"}}).encode())
        cache.update(json.dumps({"print": {"msg": 1, "bed_temper": 38.9}}).encode())

        state = json.loads(cache.snapshot())
        assert state["print"]["msg"] == 0
        assert state["print"]["gcode_state"] == "IDLE"
        assert state["print"]["bed_temper"] == 38.9

    def test_absent_msg_is_not_invented(self):
        cache = PrinterStateCache()
        cache.update(json.dumps({"print": {"gcode_state": "IDLE"}}).encode())
        assert "msg" not in json.loads(cache.snapshot())["print"]


class TestAckWithStateIsKept:
    """A command reply carrying real state must survive."""

    def test_get_version_is_cached(self):
        # The get_version reply carries result: success alongside the module
        # array clients read for firmware and AMS versions. Dropping the whole
        # section on `result` lost it.
        cache = PrinterStateCache()
        assert cache.update(
            json.dumps(
                {
                    "info": {
                        "command": "get_version",
                        "result": "success",
                        "sequence_id": "3",
                        "module": [{"name": "ota", "sw_ver": "01.09.01.00"}],
                    }
                }
            ).encode()
        )
        state = json.loads(cache.snapshot())
        assert state["info"]["module"][0]["sw_ver"] == "01.09.01.00"
        # The ack metadata itself is still stripped from the replay.
        assert "result" not in state["info"]

    def test_bare_ack_is_still_dropped(self):
        cache = PrinterStateCache()
        cache.update(json.dumps({"print": {"gcode_state": "IDLE"}}).encode())
        assert (
            cache.update(
                json.dumps(
                    {
                        "print": {
                            "command": "project_file",
                            "result": "FAIL",
                            "reason": "nope",
                            "sequence_id": "9",
                        }
                    }
                ).encode()
            )
            is False
        )
        assert json.loads(cache.snapshot())["print"] == {"gcode_state": "IDLE"}


class TestFullStateDetection:
    """Only a full dump may prime the cache."""

    def test_full_dump_is_recognised(self):
        assert payload_is_full_state(b'{"print":{"msg":0,"gcode_state":"IDLE"}}')

    def test_delta_is_not(self):
        # Priming on a delta would let the proxy relabel a one-field document
        # as full state, leaving the client silently missing everything else.
        assert not payload_is_full_state(b'{"print":{"msg":1,"bed_temper":38.9}}')

    def test_missing_msg_is_not_a_full_dump(self):
        assert not payload_is_full_state(b'{"print":{"bed_temper":38.9}}')

    def test_garbage_is_not_a_full_dump(self):
        assert not payload_is_full_state(b"not json")
        assert not payload_is_full_state(b"[0]")
        assert not payload_is_full_state(b"")


class TestMappedAddresses:
    """A dual-stack listener must not look like "no IPv4 address"."""

    def test_mapped_ipv4_is_unwrapped(self):
        # Regression: refusing ::ffff:a.b.c.d dropped every MQTT client on a
        # dual-stack listener - after CONNACK had already been accepted - and
        # answered 522 to every PASV.
        assert as_ipv4("::ffff:192.168.1.10") == "192.168.1.10"

    def test_plain_ipv4_passes_through(self):
        assert as_ipv4("192.168.1.18") == "192.168.1.18"

    def test_real_ipv6_is_refused(self):
        assert as_ipv4("::1") is None
        assert as_ipv4("fe80::1") is None

    def test_nonsense_is_refused(self):
        assert as_ipv4("nas.lan") is None
        assert as_ipv4("192.168.1") is None
        assert as_ipv4("") is None


class TestPerSectionSnapshots:
    """Replay one report per section, as the printer does."""

    def test_each_section_gets_its_own_payload(self):
        # A client dispatching on the top-level key with an if/elif chain would
        # ingest only the first section of a bundled report and silently drop
        # the rest - a replay less complete than a real pushall.
        cache = PrinterStateCache()
        cache.update(json.dumps({"print": {"gcode_state": "IDLE"}}).encode())
        cache.update(json.dumps({"info": {"module": [{"name": "ota"}]}}).encode())

        payloads = cache.snapshots()
        assert len(payloads) == 2
        sections = {next(iter(json.loads(p))) for p in payloads}
        assert sections == {"print", "info"}
        for payload in payloads:
            assert len(json.loads(payload)) == 1

    def test_empty_cache_yields_nothing(self):
        assert PrinterStateCache().snapshots() == []

    def test_rewriting_still_applies(self):
        cache = PrinterStateCache()
        cache.update(
            json.dumps({"print": {"net": {"info": [{"ip": REAL_IP_ENCODED}]}}}).encode()
        )
        payload = cache.snapshots(advertise_ip="192.168.1.50")[0]
        state = json.loads(payload)
        assert decode_ipv4(state["print"]["net"]["info"][0]["ip"]) == "192.168.1.50"
