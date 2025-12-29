#!/usr/bin/env python3
"""Pulsar battery logger for Windows.

The dongles expose vendor HID collections. Battery is read via report 0x08
command 0x04 and returned on an interrupt-IN input report (commonly report
0x08 or 0x09) with battery % at byte 6 and charging flag at byte 7.

This module keeps a small auto-detection list so the original Pulsar X2
Crazylight dongle and the Pulsar X2 V1 dongle (different VID/PID) both work.
"""

from __future__ import annotations

import argparse
import datetime as dt
import glob
import importlib.machinery
import importlib.util
import os
import sys
import time
from typing import Any


def load_hid_backend():
    errors = []

    try:
        import hid as hid_module
        if hasattr(hid_module, "device") or hasattr(hid_module, "Device"):
            return hid_module
        errors.append(RuntimeError("hid module lacks expected API"))
    except Exception as exc:
        errors.append(exc)

    for base in sys.path:
        if not base or not os.path.isdir(base):
            continue
        for path in glob.glob(os.path.join(base, "hid*.pyd")):
            name = os.path.basename(path).lower()
            if not (name == "hid.pyd" or name.startswith("hid.")):
                continue
            try:
                loader = importlib.machinery.ExtensionFileLoader("hid", path)
                spec = importlib.util.spec_from_file_location("hid", path, loader=loader)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                sys.modules["hid"] = module
                return module
            except Exception as exc:
                errors.append(exc)

    message = (
        "Unable to load the HID backend. On Windows, run:\n"
        "  pip uninstall hid\n"
        "  pip install hidapi\n"
    )
    raise ImportError(message) from errors[-1] if errors else None


try:
    hid = load_hid_backend()
except ImportError as exc:
    print(str(exc).strip())
    sys.exit(1)


HidDevice = Any


class DeviceProfile:
    def __init__(self, name: str, vid: int, pid_wireless: int, pid_wired: int):
        self.name = name
        self.vid = vid
        self.pid_wireless = pid_wireless
        self.pid_wired = pid_wired


# Known working profiles.
# - Original project target: Pulsar X2 Crazylight dongle (VID 0x3710)
# - This workspace: Pulsar X2 V1 dongle (VID 0x25a7)
KNOWN_PROFILES: list[DeviceProfile] = [
    DeviceProfile("x2_crazylight", vid=0x3710, pid_wireless=0x5406, pid_wired=0x3414),
    DeviceProfile("x2_v1", vid=0x25A7, pid_wireless=0xFA7C, pid_wired=0xFA7B),
]

# Back-compat module constants (some callers import these).
VID = KNOWN_PROFILES[0].vid
PID_WIRELESS = KNOWN_PROFILES[0].pid_wireless
PID_WIRED = KNOWN_PROFILES[0].pid_wired

# Optional vendor usage-page filter. Default: None (probe all).
USAGE_PAGE_VENDOR: int | None = None

OUTPUT_REPORT_ID = 0x08
INPUT_REPORT_IDS = {0x08, 0x09}
DEFAULT_INPUT_REPORT_ID = 0x09

CMD03_PACKET = bytes([OUTPUT_REPORT_ID, 0x03] + [0x00] * 14 + [0x4A])
CMD04_PACKET = bytes([OUTPUT_REPORT_ID, 0x04] + [0x00] * 14 + [0x49])

# cmd01 appears to include a 4-byte session value and a 1-byte checksum.
# From the user's USB capture, the checksum is a simple additive check byte:
#   (sum(packet_bytes) & 0xFF) == 0x55
CMD01_TARGET_SUM = 0x55


def build_cmd01_packet(nonce: int | bytes | None = None) -> bytes:
    if nonce is None:
        nonce_bytes = int(time.time_ns() & 0xFFFFFFFF).to_bytes(4, "little")
    elif isinstance(nonce, int):
        nonce_bytes = int(nonce & 0xFFFFFFFF).to_bytes(4, "little")
    else:
        nonce_bytes = bytes(nonce)
        if len(nonce_bytes) != 4:
            raise ValueError("cmd01 nonce must be exactly 4 bytes")

    body = bytes([OUTPUT_REPORT_ID, 0x01, 0x00, 0x00, 0x00, 0x08]) + nonce_bytes + bytes(
        [0x00] * 6
    )
    chk = (CMD01_TARGET_SUM - (sum(body) & 0xFF)) & 0xFF
    return body + bytes([chk])

# Minimal warmup sequence observed in the user's USB capture around cmd04.
# We prepend a generated cmd01 packet to replicate Fusion's startup behavior.
CMD0E_PACKET = bytes.fromhex("080e00000000000000000000000000003f")

# Minimal warmup that helps some dongles respond without the official software.
CMD04_WARMUP_MINIMAL = [
    build_cmd01_packet,
    lambda: CMD03_PACKET,
    lambda: CMD0E_PACKET,
]


def format_path(path) -> str:
    if isinstance(path, bytes):
        return path.hex()
    return str(path)


def list_candidate_devices(
    mode: str,
    interface: int | None,
    vid: int | None = None,
    pid_wireless: int | None = None,
    pid_wired: int | None = None,
    usage_page: int | None = USAGE_PAGE_VENDOR,
) -> list[dict]:
    def wanted_pairs() -> list[tuple[int, int]]:
        # Explicit override.
        if vid is not None and pid_wireless is not None and pid_wired is not None:
            if mode == "wireless":
                return [(vid, pid_wireless)]
            if mode == "wired":
                return [(vid, pid_wired)]
            return [(vid, pid_wireless), (vid, pid_wired)]

        # Auto across known profiles.
        pairs: list[tuple[int, int]] = []
        for profile in KNOWN_PROFILES:
            if mode != "wired":
                pairs.append((profile.vid, profile.pid_wireless))
            if mode != "wireless":
                pairs.append((profile.vid, profile.pid_wired))
        return pairs

    allowed = set(wanted_pairs())
    devices: list[dict] = []
    for info in hid.enumerate():
        pair = (info.get("vendor_id"), info.get("product_id"))
        if pair not in allowed:
            continue
        if interface is not None and info.get("interface_number") != interface:
            continue
        if usage_page is not None and info.get("usage_page") != usage_page:
            continue
        devices.append(info)

    def sort_key(item: dict):
        iface = item.get("interface_number")
        up = item.get("usage_page")
        usage = item.get("usage")
        path = format_path(item.get("path"))

        # Prefer the vendor interface (typically interface 1) and vendor usage pages.
        prefer_iface = 0 if iface == 1 else 1
        is_vendor_page = isinstance(up, int) and up >= 0xFF00
        prefer_vendor_page = 0 if is_vendor_page else 1

        # Common vendor pages on Pulsar dongles.
        # Heuristic: writes often work on ff02, and on some dongles responses arrive on ff01.
        vendor_rank = {0xFF02: 0, 0xFF01: 1, 0xFF03: 2, 0xFF04: 3}
        prefer_common_vendor = 0 if up in vendor_rank else 1
        vendor_order = vendor_rank.get(up, 99)

        # Some collections report usage=0; don't overfit, but keep deterministic order.
        prefer_usage_zero = 0 if usage in {0, None} else 1

        return (
            prefer_iface,
            prefer_vendor_page,
            prefer_common_vendor,
            vendor_order,
            prefer_usage_zero,
            path,
        )

    devices.sort(key=sort_key)
    return devices


def has_wired_device(vid: int | None = None, pid_wired: int | None = None) -> bool:
    # If explicit IDs are provided, check those. Otherwise, check across known profiles.
    if vid is not None and pid_wired is not None:
        for info in hid.enumerate():
            if info.get("vendor_id") == vid and info.get("product_id") == pid_wired:
                return True
        return False

    wired_pairs = {(p.vid, p.pid_wired) for p in KNOWN_PROFILES}
    for info in hid.enumerate():
        if (info.get("vendor_id"), info.get("product_id")) in wired_pairs:
            return True
    return False


def print_devices(devices: list[dict]) -> None:
    if not devices:
        print("No matching Pulsar devices found.")
        return

    for index, info in enumerate(devices):
        vid = info.get("vendor_id")
        pid = info.get("product_id")
        product = info.get("product_string") or ""
        interface = info.get("interface_number")
        usage_page = info.get("usage_page")
        usage = info.get("usage")
        path = format_path(info.get("path"))
        usage_page_str = "None" if usage_page is None else f"0x{usage_page:04x}"
        usage_str = "None" if usage is None else f"0x{usage:04x}"
        print(
            f"{index}: vid=0x{vid:04x} pid=0x{pid:04x} "
            f"interface={interface} usage_page={usage_page_str} "
            f"usage={usage_str} product='{product}' path={path}"
        )


def open_device(info: dict) -> HidDevice | None:
    if hasattr(hid, "device"):
        dev = hid.device()
        dev.open_path(info["path"])
        return dev
    if hasattr(hid, "Device"):
        return hid.Device(path=info["path"])
    raise RuntimeError("HID backend missing device constructor")


def drain_input(dev: HidDevice, attempts: int = 6) -> None:
    try:
        dev.set_nonblocking(1)
        for _ in range(attempts):
            data = dev.read(64)
            if not data:
                break
    except (OSError, ValueError):
        pass
    finally:
        try:
            dev.set_nonblocking(0)
        except (OSError, ValueError):
            pass


def normalize_input_report(data: bytes | list[int]) -> bytes:
    if isinstance(data, list):
        data = bytes(data)
    # Some hidapi backends omit the report ID on reads.
    # If we see a 16-byte payload that starts with a known command byte, prepend
    # the default input report ID so parsing stays aligned.
    if len(data) == 16 and data and data[0] in {0x01, 0x02, 0x03, 0x04, 0x08, 0x0E}:
        return bytes([DEFAULT_INPUT_REPORT_ID]) + data
    return data


def parse_cmd04_payload(payload: bytes) -> tuple[int, bool] | None:
    if len(payload) < 8:
        return None
    battery = payload[6]
    charging = payload[7] != 0x00
    return battery, charging


def _supports_feature_reports(dev: object) -> bool:
    return hasattr(dev, "send_feature_report")


def _send_report(dev: HidDevice, payload: bytes, transport: str) -> None:
    """Send a report buffer (payload already includes report ID as first byte)."""
    use_feature = transport == "feature" or (transport == "auto" and _supports_feature_reports(dev))
    if use_feature and hasattr(dev, "send_feature_report"):
        dev.send_feature_report(payload)
        return

    result = dev.write(payload)
    if isinstance(result, int) and result < 0:
        raise OSError("HID write failed")


def read_battery_cmd04(
    dev: HidDevice,
    debug: bool,
    transport: str = "auto",
    reader: HidDevice | None = None,
) -> tuple[int, bool] | None:
    # On Windows, the vendor HID interface can be split across multiple top-level
    # collections. In that case one HID path handles writes while another receives
    # input reports. Allow separate reader handle.
    reader = dev if reader is None else reader

    drain_input(reader)

    def read_once(max_len: int) -> bytes | list[int] | None:
        try:
            return reader.read(max_len, 250)
        except TypeError:
            # Some hid backends don't accept a timeout argument.
            try:
                return reader.read(max_len)
            except (OSError, ValueError):
                return None
        except (OSError, ValueError):
            return None

    def read_cmd(expected_cmd: int, timeout: float, log_other: bool) -> bytes | None:
        deadline = time.time() + timeout
        nonblocking_set = False
        try:
            try:
                reader.set_nonblocking(1)
                nonblocking_set = True
            except (AttributeError, OSError, ValueError):
                nonblocking_set = False

            while time.time() < deadline:
                data = read_once(64)
                if not data:
                    time.sleep(0.01)
                    continue
                payload = normalize_input_report(data)
                if len(payload) < 7 or payload[0] not in INPUT_REPORT_IDS:
                    continue
                if payload[1] != expected_cmd:
                    if debug and log_other:
                        print(
                            f"cmd04 skip cmd=0x{payload[1]:02x} data={payload.hex()}"
                        )
                    continue
                return payload

            return None
        finally:
            if nonblocking_set:
                try:
                    reader.set_nonblocking(0)
                except (OSError, ValueError):
                    pass

    def attempt_cmd04(timeout: float) -> bytes | None:
        _send_report(dev, CMD04_PACKET, transport=transport)
        time.sleep(0.02)
        return read_cmd(0x04, timeout, log_other=True)

    payload: bytes | None = None
    try:
        payload = attempt_cmd04(0.8)
    except (OSError, ValueError) as exc:
        if debug:
            print(f"cmd04 send failed err={exc}")
        payload = None

    if payload is None:
        if debug:
            print("cmd04 minimal warmup")

        for warmup_item in CMD04_WARMUP_MINIMAL:
            warmup_payload = warmup_item() if callable(warmup_item) else warmup_item
            try:
                _send_report(dev, warmup_payload, transport=transport)
            except (OSError, ValueError) as exc:
                if debug:
                    print(f"cmd04 warmup write_failed err={exc}")
                break
            time.sleep(0.01)

        try:
            payload = attempt_cmd04(1.2)
        except (OSError, ValueError) as exc:
            if debug:
                print(f"cmd04 post-warmup failed err={exc}")
            payload = None

    if payload is None:
        return None

    parsed = parse_cmd04_payload(payload)
    if parsed is None:
        if debug:
            print(f"cmd04 parse failed data={payload.hex()}")
        return None
    raw, charging = parsed
    if debug:
        print(f"cmd04 raw={raw} charging={charging} data={payload.hex()}")
    return raw, charging


def select_device(
    devices: list[dict],
    index: int | None,
    debug: bool,
    transport: str,
) -> tuple[HidDevice | None, HidDevice | None, dict | None, dict | None]:
    all_devices = list(devices)
    if not all_devices:
        return None, None, None, None

    if index is not None:
        if index < 0 or index >= len(all_devices):
            print(f"Invalid --index {index}; {len(all_devices)} device(s) available.")
            return None, None, None, None
        writer_candidates = [all_devices[index]]
    else:
        writer_candidates = list(all_devices)

    def probe_pair(writer_info: dict, reader_info: dict) -> tuple[HidDevice | None, HidDevice | None]:
        w = None
        r = None
        try:
            w = open_device(writer_info)
            r = w if writer_info.get("path") == reader_info.get("path") else open_device(reader_info)
            status = read_battery_cmd04(w, debug, transport=transport, reader=r)
            if status is None:
                return None, None
            return w, r
        except (OSError, ValueError):
            if w is not None:
                try:
                    w.close()
                except OSError:
                    pass
            if r is not None and r is not w:
                try:
                    r.close()
                except OSError:
                    pass
            return None, None

    # Build a broad reader pool for the same VID/PIDs (covers split collections).
    allowed_pairs = {(d.get("vendor_id"), d.get("product_id")) for d in all_devices}
    reader_pool = [info for info in hid.enumerate() if (info.get("vendor_id"), info.get("product_id")) in allowed_pairs]

    # Heuristic order for readers: prefer ff01, then same usage page, then other vendor pages.
    def reader_sort_key(item: dict, writer_up: int | None):
        up = item.get("usage_page")
        is_vendor = isinstance(up, int) and up >= 0xFF00
        prefer_ff01 = 0 if up == 0xFF01 else 1
        prefer_same = 0 if (writer_up is not None and up == writer_up) else 1
        prefer_vendor = 0 if is_vendor else 1
        return (prefer_ff01, prefer_same, prefer_vendor, format_path(item.get("path")))

    for writer_info in writer_candidates:
        writer_up = writer_info.get("usage_page")
        readers = sorted(reader_pool, key=lambda r: reader_sort_key(r, writer_up))

        # Try same path first.
        w, r = probe_pair(writer_info, writer_info)
        if w is not None and r is not None:
            if debug:
                print(f"selected path={format_path(writer_info.get('path'))}")
            return w, r, writer_info, writer_info

        # Then try split pairs.
        for reader_info in readers:
            if debug:
                w_up = writer_info.get("usage_page")
                r_up = reader_info.get("usage_page")
                w_up_s = "None" if w_up is None else f"0x{w_up:04x}"
                r_up_s = "None" if r_up is None else f"0x{r_up:04x}"
                print(
                    "probe_split "
                    f"writer_iface={writer_info.get('interface_number')} writer_up={w_up_s} "
                    f"reader_iface={reader_info.get('interface_number')} reader_up={r_up_s}"
                )
            w, r = probe_pair(writer_info, reader_info)
            if w is not None and r is not None:
                if debug:
                    print(
                        "selected split handles "
                        f"writer={format_path(writer_info.get('path'))} "
                        f"reader={format_path(reader_info.get('path'))}"
                    )
                return w, r, writer_info, reader_info

    return None, None, None, None


def timestamp(now_utc: bool) -> str:
    if now_utc:
        return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    return dt.datetime.now().isoformat(timespec="seconds")


def open_log(path: str):
    is_new = not os.path.exists(path) or os.path.getsize(path) == 0
    handle = open(path, "a", encoding="ascii", newline="")
    if is_new:
        handle.write("timestamp,battery_percent\n")
        handle.flush()
    return handle


def parse_int_auto(value: str) -> int:
    value = value.strip().lower()
    base = 16 if value.startswith("0x") else 10
    return int(value, base)


def run_logger(args: argparse.Namespace) -> int:
    devices = list_candidate_devices(
        args.mode,
        args.interface,
        vid=args.vid,
        pid_wireless=args.pid_wireless,
        pid_wired=args.pid_wired,
        usage_page=args.usage_page,
    )
    if args.list_devices:
        print_devices(devices)
        return 0

    log_handle = open_log(args.log_path)
    dev_write = None
    dev_read = None
    consecutive_misses = 0

    try:
        while True:
            if dev_write is None or dev_read is None:
                dev_write, dev_read, _, _ = select_device(
                    devices,
                    args.index,
                    args.debug,
                    args.transport,
                )
                if dev_write is None or dev_read is None:
                    print("No responsive device found; will retry if --once was omitted.")
                    if args.once:
                        return 1
                    time.sleep(args.interval)
                    devices = list_candidate_devices(
                        args.mode,
                        args.interface,
                        vid=args.vid,
                        pid_wireless=args.pid_wireless,
                        pid_wired=args.pid_wired,
                        usage_page=args.usage_page,
                    )
                    continue

            battery = None
            charging = None
            try:
                status = read_battery_cmd04(
                    dev_write,
                    args.debug,
                    transport=args.transport,
                    reader=dev_read,
                )
                if status is not None:
                    battery, charging = status
            except (OSError, ValueError) as exc:
                if args.debug:
                    print(f"read_failed err={exc}")
                try:
                    dev_write.close()
                except OSError:
                    pass
                if dev_read is not None and dev_read is not dev_write:
                    try:
                        dev_read.close()
                    except OSError:
                        pass
                dev_write = None
                dev_read = None

            if battery is not None and charging is not None:
                consecutive_misses = 0
                stamp = timestamp(args.utc)
                log_handle.write(f"{stamp},{battery}\n")
                log_handle.flush()
                wired_present = has_wired_device(vid=args.vid, pid_wired=args.pid_wired)
                if wired_present and not charging:
                    if args.debug:
                        print("charging override: wired device present")
                    charging = True
                charging_str = "yes" if charging else "no"
                print(f"{stamp} battery={battery}% charging={charging_str}")
                if args.once:
                    return 0
            else:
                print("Battery read failed; will retry.")
                consecutive_misses += 1
                if consecutive_misses >= 3:
                    if args.debug:
                        print("reselecting device after repeated misses")
                    try:
                        if dev_write is not None:
                            dev_write.close()
                    except OSError:
                        pass
                    try:
                        if dev_read is not None and dev_read is not dev_write:
                            dev_read.close()
                    except OSError:
                        pass
                    dev_write = None
                    dev_read = None
                    consecutive_misses = 0
                if args.once:
                    return 1

            time.sleep(args.interval)
    finally:
        if dev_write is not None:
            try:
                dev_write.close()
            except OSError:
                pass
        if dev_read is not None and dev_read is not dev_write:
            try:
                dev_read.close()
            except OSError:
                pass
        log_handle.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Log Pulsar X2 battery percentage on Windows."
    )
    parser.add_argument(
        "--vid",
        type=parse_int_auto,
        default=None,
        help="USB VID to match (default: auto; known Pulsar dongles)",
    )
    parser.add_argument(
        "--pid-wireless",
        type=parse_int_auto,
        default=None,
        help="Wireless PID to match (requires --vid; default: auto)",
    )
    parser.add_argument(
        "--pid-wired",
        type=parse_int_auto,
        default=None,
        help="Wired PID to match (requires --vid; default: auto)",
    )
    parser.add_argument(
        "--usage-page",
        type=parse_int_auto,
        default=USAGE_PAGE_VENDOR,
        help=(
            "Filter by HID usage page (hex like 0xff02). "
            "Default: no filter (probe all interfaces)."
        ),
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=60,
        help="Polling interval in seconds (default: 60)",
    )
    parser.add_argument(
        "--log-path",
        default="battery_log.csv",
        help="CSV log path (default: battery_log.csv)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Log a single reading and exit",
    )
    parser.add_argument(
        "--mode",
        choices=["auto", "wireless", "wired"],
        default="auto",
        help="Device mode preference (default: auto)",
    )
    parser.add_argument(
        "--interface",
        type=int,
        default=None,
        help="Filter by HID interface number",
    )
    parser.add_argument(
        "--index",
        type=int,
        default=None,
        help="Use the Nth device from --list-devices",
    )
    parser.add_argument(
        "--list-devices",
        action="store_true",
        help="List matching HID devices and exit",
    )
    parser.add_argument(
        "--utc",
        action="store_true",
        help="Use UTC timestamps",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print raw responses and probe errors",
    )
    parser.add_argument(
        "--transport",
        choices=["auto", "output", "feature"],
        default="auto",
        help="Send transport for cmd04: feature (preferred), output, or auto",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()

    if args.interval < 1:
        print("--interval must be >= 1")
        return 2

    return run_logger(args)


if __name__ == "__main__":
    raise SystemExit(main())
