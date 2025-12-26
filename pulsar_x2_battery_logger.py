#!/usr/bin/env python3
"""
Pulsar X2 battery logger for Windows (wired or wireless).

Uses vendor HID output report 0x08 command 0x04; response report 0x08
contains battery percent at byte 6.
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


VID = 0x3710
PID_WIRELESS = 0x5406  # Pulsar 8K Dongle.
PID_WIRED = 0x3414  # Pulsar X2 Crazylight (wired).
PID_WIRED_X3_LHD_CL = 0x3508  # Possibly Pulsar X3 LHD CrazyLight. Unused.
USAGE_PAGE_VENDOR = 0xFF02

CMD03_PACKET = bytes([0x08, 0x03] + [0x00] * 14 + [0x4A])
CMD04_PACKET = bytes([0x08, 0x04] + [0x00] * 14 + [0x49])
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


def format_path(path) -> str:
    if isinstance(path, bytes):
        return path.hex()
    return str(path)


def list_candidate_devices(mode: str, interface: int | None) -> list[dict]:
    allowed_pids = {PID_WIRELESS, PID_WIRED}
    if mode == "wireless":
        allowed_pids = {PID_WIRELESS}
    elif mode == "wired":
        allowed_pids = {PID_WIRED}

    devices = []
    for info in hid.enumerate():
        if info.get("vendor_id") != VID:
            continue
        if info.get("product_id") not in allowed_pids:
            continue
        if interface is not None and info.get("interface_number") != interface:
            continue
        if info.get("usage_page") != USAGE_PAGE_VENDOR:
            continue
        devices.append(info)

    devices.sort(key=lambda item: format_path(item.get("path")))
    return devices


def has_wired_device() -> bool:
    for info in hid.enumerate():
        if info.get("vendor_id") == VID and info.get("product_id") == PID_WIRED:
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


def open_device(info: dict) -> hid.device | None:
    if hasattr(hid, "device"):
        dev = hid.device()
        dev.open_path(info["path"])
        return dev
    if hasattr(hid, "Device"):
        return hid.Device(path=info["path"])
    raise RuntimeError("HID backend missing device constructor")


def drain_input(dev: hid.device, attempts: int = 6) -> None:
    try:
        dev.set_nonblocking(1)
        for _ in range(attempts):
            data = dev.read(17)
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
    if len(data) == 16:
        return b"\x08" + data
    return data


def parse_cmd04_payload(payload: bytes) -> tuple[int, bool] | None:
    if len(payload) < 8:
        return None
    battery = payload[6]
    charging = payload[7] != 0x00
    return battery, charging


def read_battery_cmd04(dev: hid.device, debug: bool) -> tuple[int, bool] | None:
    drain_input(dev)

    def read_cmd(expected_cmd: int, timeout: float, log_other: bool) -> bytes | None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            data = dev.read(17, 250)
            if not data:
                continue
            payload = normalize_input_report(data)
            if len(payload) < 7 or payload[0] != 0x08:
                continue
            if payload[1] != expected_cmd:
                if debug and log_other:
                    print(f"cmd04 skip cmd=0x{payload[1]:02x} data={payload.hex()}")
                continue
            return payload
        return None

    def attempt_cmd04(timeout: float) -> bytes | None:
        dev.write(CMD04_PACKET)
        return read_cmd(0x04, timeout, log_other=True)

    payload = attempt_cmd04(0.8)
    if payload is None:
        if debug:
            print("cmd04 init sequence")
        for payload_init in CMD04_INIT_SEQUENCE:
            dev.write(payload_init)
            time.sleep(0.01)
        payload = read_cmd(0x04, 2.0, log_other=True)

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
) -> tuple[hid.device | None, dict | None]:
    if index is not None:
        if index < 0 or index >= len(devices):
            print(f"Invalid --index {index}; {len(devices)} device(s) available.")
            return None, None
        devices = [devices[index]]

    for info in devices:
        dev = None
        try:
            dev = open_device(info)
            status = read_battery_cmd04(dev, debug)
            if status is not None:
                if debug:
                    print(f"selected path={format_path(info.get('path'))}")
                return dev, info
        except (OSError, ValueError) as exc:
            if debug:
                print(f"probe_failed path={format_path(info.get('path'))} err={exc}")
        if dev is not None:
            try:
                dev.close()
            except OSError:
                pass

    return None, None


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


def run_logger(args: argparse.Namespace) -> int:
    devices = list_candidate_devices(args.mode, args.interface)
    if args.list_devices:
        print_devices(devices)
        return 0

    log_handle = open_log(args.log_path)
    dev = None

    try:
        while True:
            if dev is None:
                dev, _ = select_device(
                    devices,
                    args.index,
                    args.debug,
                )
                if dev is None:
                    print("No responsive device found; will retry if --once was omitted.")
                    if args.once:
                        return 1
                    time.sleep(args.interval)
                    devices = list_candidate_devices(args.mode, args.interface)
                    continue

            battery = None
            charging = None
            try:
                status = read_battery_cmd04(dev, args.debug)
                if status is not None:
                    battery, charging = status
            except (OSError, ValueError) as exc:
                if args.debug:
                    print(f"read_failed err={exc}")
                try:
                    dev.close()
                except OSError:
                    pass
                dev = None

            if battery is not None and charging is not None:
                stamp = timestamp(args.utc)
                log_handle.write(f"{stamp},{battery}\n")
                log_handle.flush()
                wired_present = has_wired_device()
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
                if args.once:
                    return 1

            time.sleep(args.interval)
    finally:
        if dev is not None:
            try:
                dev.close()
            except OSError:
                pass
        log_handle.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Log Pulsar X2 battery percentage on Windows."
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
    return parser


def main() -> int:
    args = build_parser().parse_args()

    if args.interval < 1:
        print("--interval must be >= 1")
        return 2

    return run_logger(args)


if __name__ == "__main__":
    raise SystemExit(main())
