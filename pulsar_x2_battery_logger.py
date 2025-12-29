#!/usr/bin/env python3
"""Pulsar X2 battery logger for Windows (wired or wireless).

Uses vendor HID report 0x08 command 0x04; on this user's hardware the
corresponding response is report 0x09 with battery percent at byte 6.
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


# Defaults for Pulsar X2 V1 (user hardware in this workspace).
# If these do not match your setup, override via CLI flags.
VID = 0x25A7
PID_WIRED = 0xFA7B
PID_WIRELESS = 0xFA7C
PID_WIRED_X3_LHD_CL = 0x3508  # Possibly Pulsar X3 LHD CrazyLight. Unused.

# Vendor usage page used by the battery interface.
# Different dongles/firmware expose multiple vendor collections (e.g. 0xff01..0xff04).
# Default is None to probe all; optionally pass --usage-page to narrow.
USAGE_PAGE_VENDOR: int | None = None

OUTPUT_REPORT_ID = 0x08
# The official software's cmd04 response on this hardware uses report ID 0x09.
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
# Init sequence captured from Pulsar Fusion to enable cmd04 responses.
CMD01_PACKET_A = bytes.fromhex("0801000000088e0c4d4c00000000000011")
CMD01_PACKET_B = bytes.fromhex("0801000000089505dd4b00000000000082")
CMD02_PACKET = bytes.fromhex("0802000000010100000000000000000049")
CMD04_INIT_SEQUENCE = [
    CMD01_PACKET_A,
    CMD03_PACKET,
    CMD03_PACKET,
    CMD03_PACKET,
    CMD01_PACKET_A,
    CMD03_PACKET,
    CMD03_PACKET,
    CMD01_PACKET_A,
    CMD03_PACKET,
    CMD01_PACKET_B,
    CMD03_PACKET,
    CMD03_PACKET,
    CMD03_PACKET,
    CMD02_PACKET,
    CMD03_PACKET,
    CMD03_PACKET,
    CMD04_PACKET,
    CMD04_PACKET,
]

# Minimal warmup sequence observed in the user's USB capture around cmd04.
# We prepend a generated cmd01 packet to replicate Fusion's startup behavior.
CMD04_WARMUP_MINIMAL = [
    CMD03_PACKET,
    CMD04_PACKET,
    bytes.fromhex("080e00000000000000000000000000003f"),
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
    vid = VID if vid is None else vid
    pid_wireless = PID_WIRELESS if pid_wireless is None else pid_wireless
    pid_wired = PID_WIRED if pid_wired is None else pid_wired

    allowed_pids = {pid_wireless, pid_wired}
    if mode == "wireless":
        allowed_pids = {pid_wireless}
    elif mode == "wired":
        allowed_pids = {pid_wired}

    devices = []
    for info in hid.enumerate():
        if info.get("vendor_id") != vid:
            continue
        if info.get("product_id") not in allowed_pids:
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

        # Within vendor pages, ff01..ff04 are common on Pulsar dongles.
        # Prefer the known working pairing on this machine: writes on ff02, reads on ff01.
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
    vid = VID if vid is None else vid
    pid_wired = PID_WIRED if pid_wired is None else pid_wired
    for info in hid.enumerate():
        if info.get("vendor_id") == vid and info.get("product_id") == pid_wired:
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
    return hasattr(dev, "send_feature_report") and hasattr(dev, "get_feature_report")


def _send_cmd04_output(dev: HidDevice) -> None:
    # Some dongles expose no interrupt OUT endpoint; writes then fail (often
    # returning -1). In captures, the official software uses HID class
    # SET_REPORT control transfers; on Windows/hidapi that often maps better to
    # send_feature_report than to write().
    result = dev.write(CMD04_PACKET)
    if isinstance(result, int) and result < 0:
        if _supports_feature_reports(dev):
            dev.send_feature_report(CMD04_PACKET)
            return
        raise OSError("HID write failed")


def _send_cmd04_feature(dev: HidDevice) -> None:
    # hidapi expects the report ID as the first byte in the buffer.
    dev.send_feature_report(CMD04_PACKET)


def _read_cmd04_feature_get_report(dev: HidDevice, timeout: float, debug: bool) -> bytes | None:
    """Fallback reader using GET_REPORT(feature).

    Note: On the user's Pulsar X2 V1 capture, cmd04 responses arrive on interrupt-IN
    as report ID 0x09, not via GET_REPORT. Some devices/firmware may still support
    returning the response as a feature report.
    """

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            data = dev.get_feature_report(OUTPUT_REPORT_ID, 64)
        except (OSError, ValueError) as exc:
            if debug:
                print(f"cmd04 feature read_failed err={exc}")
            return None
        if not data:
            time.sleep(0.05)
            continue
        payload = normalize_input_report(data)
        if len(payload) < 2:
            time.sleep(0.05)
            continue
        # Some backends may include report ID 0x08 or 0x09 here; accept both.
        if payload[0] not in INPUT_REPORT_IDS:
            if debug:
                print(f"cmd04 feature skip data={payload.hex()}")
            time.sleep(0.05)
            continue
        if payload[1] != 0x04:
            if debug:
                print(f"cmd04 feature skip cmd=0x{payload[1]:02x} data={payload.hex()}")
            time.sleep(0.05)
            continue
        return payload
    return None


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

    def attempt_cmd04_output(timeout: float) -> bytes | None:
        _send_cmd04_output(dev)
        # Small delay improves reliability on some dongles.
        time.sleep(0.02)
        return read_cmd(0x04, timeout, log_other=True)

    def attempt_cmd04_feature(timeout: float) -> bytes | None:
        if not _supports_feature_reports(dev):
            return None
        _send_cmd04_feature(dev)
        # Primary path: response is an interrupt-IN input report (matches USB capture).
        payload = read_cmd(0x04, timeout, log_other=True)
        if payload is not None:
            return payload

        # Do not use GET_REPORT(feature) by default.
        # On the user's Pulsar X2 V1 dongle, GET_REPORT frequently returns errors or
        # all-zero payloads and does not reflect the real interrupt-IN response path.
        return None

    payload = None
    if transport == "output":
        try:
            payload = attempt_cmd04_output(0.8)
        except (OSError, ValueError) as exc:
            if debug:
                print(f"cmd04 output failed err={exc}")
            payload = None
    elif transport == "feature":
        try:
            payload = attempt_cmd04_feature(0.8)
        except (OSError, ValueError) as exc:
            if debug:
                print(f"cmd04 feature failed err={exc}")
            payload = None
    else:
        # auto: try output first, then feature.
        try:
            payload = attempt_cmd04_output(0.6)
        except (OSError, ValueError) as exc:
            if debug:
                print(f"cmd04 output failed err={exc}")
            payload = None
        if payload is None:
            try:
                payload = attempt_cmd04_feature(0.8)
            except (OSError, ValueError) as exc:
                if debug:
                    print(f"cmd04 feature failed err={exc}")
                payload = None

    if payload is None:
        # Retry a couple times before doing any warmup.
        for _ in range(2):
            try:
                payload = attempt_cmd04_output(0.6) if transport != "feature" else attempt_cmd04_feature(0.8)
            except (OSError, ValueError):
                payload = None
            if payload is not None:
                break

    if payload is None:
        if debug:
            print("cmd04 minimal warmup")

        warmup_sequence = [build_cmd01_packet()] + CMD04_WARMUP_MINIMAL
        for warmup_payload in warmup_sequence:
            try:
                # Prefer feature reports when available (matches SET_REPORT control transfers).
                if _supports_feature_reports(dev):
                    dev.send_feature_report(warmup_payload)
                else:
                    result = dev.write(warmup_payload)
                    if isinstance(result, int) and result < 0:
                        raise OSError("HID write failed")
            except (OSError, ValueError) as exc:
                if debug:
                    print(f"cmd04 warmup write_failed err={exc}")
                break
            time.sleep(0.01)

        # Try again after minimal warmup.
        try:
            payload = attempt_cmd04_output(1.2) if transport != "feature" else attempt_cmd04_feature(1.2)
        except (OSError, ValueError) as exc:
            if debug:
                print(f"cmd04 post-warmup failed err={exc}")
            payload = None

    if payload is None:
        # Last resort: the original (project author's) full init sequence.
        if debug:
            print("cmd04 init sequence")
        for payload_init in CMD04_INIT_SEQUENCE:
            try:
                if payload_init[:2] == bytes([OUTPUT_REPORT_ID, 0x01]):
                    payload_init = build_cmd01_packet()
                if _supports_feature_reports(dev):
                    dev.send_feature_report(payload_init)
                else:
                    result = dev.write(payload_init)
                    if isinstance(result, int) and result < 0:
                        raise OSError("HID write failed")
            except (OSError, ValueError) as exc:
                if debug:
                    print(f"cmd04 init write_failed err={exc}")
                break
            time.sleep(0.01)

        try:
            payload = attempt_cmd04_output(2.0) if transport != "feature" else attempt_cmd04_feature(2.0)
        except (OSError, ValueError) as exc:
            if debug:
                print(f"cmd04 post-init failed err={exc}")
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

    writer_candidates = all_devices
    if index is not None:
        if index < 0 or index >= len(all_devices):
            print(f"Invalid --index {index}; {len(all_devices)} device(s) available.")
            return None, None, None, None
        writer_candidates = [all_devices[index]]

    # Fast-path: known working pairing on this Pulsar X2 V1 + dongle
    # (writes on usage page ff02, responses on interrupt-IN usage page ff01).
    if index is None and all_devices:
        def find_by_usage_page(items: list[dict], usage_page: int) -> dict | None:
            for it in items:
                if it.get("usage_page") == usage_page:
                    return it
            return None

        writer_info = find_by_usage_page(all_devices, 0xFF02)
        if writer_info is not None:
            # Build a broad reader pool for the same VID/PID(s)
            reader_pool = []
            try:
                vid = writer_info.get("vendor_id")
                allowed_pids = {d.get("product_id") for d in all_devices}
                for info in hid.enumerate():
                    if info.get("vendor_id") != vid:
                        continue
                    if info.get("product_id") not in allowed_pids:
                        continue
                    reader_pool.append(info)
            except Exception:
                reader_pool = list(all_devices)

            reader_info = find_by_usage_page(reader_pool, 0xFF01)
            if reader_info is not None:
                w = None
                r = None
                success = False
                try:
                    w = open_device(writer_info)
                    r = open_device(reader_info)
                    status = read_battery_cmd04(w, debug, transport=transport, reader=r)
                    if status is not None:
                        success = True
                        if debug:
                            print(
                                "selected fast-path split handles "
                                f"writer={format_path(writer_info.get('path'))} "
                                f"reader={format_path(reader_info.get('path'))}"
                            )
                        return w, r, writer_info, reader_info
                except (OSError, ValueError):
                    pass
                finally:
                    if not success:
                        if w is not None:
                            try:
                                w.close()
                            except OSError:
                                pass
                        if r is not None:
                            try:
                                r.close()
                            except OSError:
                                pass

    for info in writer_candidates:
        dev = None
        try:
            dev = open_device(info)
            status = read_battery_cmd04(dev, debug, transport=transport)
            if status is not None:
                if debug:
                    print(f"selected path={format_path(info.get('path'))}")
                return dev, dev, info, info
        except (OSError, ValueError) as exc:
            if debug:
                print(f"probe_failed path={format_path(info.get('path'))} err={exc}")
        if dev is not None:
            try:
                dev.close()
            except OSError:
                pass

    # Fallback: try split reader/writer handles across HID paths.
    # Important: on Windows, interrupt-IN reports may arrive on a different HID
    # collection than the one that accepts the vendor SET_REPORT writes.
    # Therefore, build a broad reader pool across all collections for the same
    # VID/PID(s), even if the user filtered the initial list by --interface or
    # --usage-page.

    reader_pool = list(all_devices)
    if all_devices:
        try:
            vid = all_devices[0].get("vendor_id")
            allowed_pids = {d.get("product_id") for d in all_devices}
            reader_pool = []
            for info in hid.enumerate():
                if info.get("vendor_id") != vid:
                    continue
                if info.get("product_id") not in allowed_pids:
                    continue
                reader_pool.append(info)
        except Exception:
            reader_pool = list(all_devices)

    # Prefer pairing within the same interface number first, then widen.
    for writer_info in writer_candidates:
        writer = None
        try:
            writer = open_device(writer_info)
        except (OSError, ValueError):
            continue

        writer_iface = writer_info.get("interface_number")

        def try_readers(readers: list[dict]) -> tuple[HidDevice | None, dict | None]:
            for reader_info in readers:
                reader = None
                try:
                    if debug:
                        w_up = writer_info.get("usage_page")
                        r_up = reader_info.get("usage_page")
                        w_up_s = "None" if w_up is None else f"0x{w_up:04x}"
                        r_up_s = "None" if r_up is None else f"0x{r_up:04x}"
                        print(
                            "probe_split "
                            f"writer_iface={writer_iface} writer_up={w_up_s} "
                            f"reader_iface={reader_info.get('interface_number')} reader_up={r_up_s}"
                        )

                    reader = open_device(reader_info)
                    status = read_battery_cmd04(
                        writer,
                        debug,
                        transport=transport,
                        reader=reader,
                    )
                    if status is not None:
                        return reader, reader_info
                except (OSError, ValueError) as exc:
                    if debug:
                        print(
                            "probe_failed_split "
                            f"writer={format_path(writer_info.get('path'))} "
                            f"reader={format_path(reader_info.get('path'))} err={exc}"
                        )
                finally:
                    if reader is not None:
                        try:
                            reader.close()
                        except OSError:
                            pass
            return None, None

        # Pass 1: same interface
        same_iface_readers = (
            [r for r in reader_pool if writer_iface is None or r.get("interface_number") == writer_iface]
            if reader_pool
            else []
        )
        reader_dev, reader_info = try_readers(same_iface_readers)
        if reader_dev is not None and reader_info is not None:
            # Re-open the selected reader for returning (we closed it in try_readers).
            try:
                reader_dev = open_device(reader_info)
            except (OSError, ValueError):
                reader_dev = None
            if reader_dev is not None:
                if debug:
                    print(
                        "selected split handles "
                        f"writer={format_path(writer_info.get('path'))} "
                        f"reader={format_path(reader_info.get('path'))}"
                    )
                return writer, reader_dev, writer_info, reader_info

        # Pass 2: any interface
        reader_dev, reader_info = try_readers(reader_pool)
        if reader_dev is not None and reader_info is not None:
            try:
                reader_dev = open_device(reader_info)
            except (OSError, ValueError):
                reader_dev = None
            if reader_dev is not None:
                if debug:
                    print(
                        "selected split handles "
                        f"writer={format_path(writer_info.get('path'))} "
                        f"reader={format_path(reader_info.get('path'))}"
                    )
                return writer, reader_dev, writer_info, reader_info

        if writer is not None:
            try:
                writer.close()
            except OSError:
                pass

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
        default=VID,
        help=f"USB VID to match (default: 0x{VID:04x})",
    )
    parser.add_argument(
        "--pid-wireless",
        type=parse_int_auto,
        default=PID_WIRELESS,
        help=f"Wireless PID to match (default: 0x{PID_WIRELESS:04x})",
    )
    parser.add_argument(
        "--pid-wired",
        type=parse_int_auto,
        default=PID_WIRED,
        help=f"Wired PID to match (default: 0x{PID_WIRED:04x})",
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
        help="HID transport for cmd04 (default: auto)",
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
