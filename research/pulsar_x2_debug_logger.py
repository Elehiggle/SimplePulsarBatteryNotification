#!/usr/bin/env python3
"""
Pulsar X2 cmd04 debug logger for Windows.
Logs environment, device metadata, report descriptors, and cmd04 responses.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
import os
import platform
import sys
import time

import hid

VID = 0x3710
PIDS = {0x5406, 0x3414}
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


def setup_logger(log_path: str, console_level: int) -> logging.Logger:
    os.makedirs(os.path.dirname(log_path), exist_ok=True)

    logger = logging.getLogger("pulsar_x2_debug")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

    file_handler = logging.FileHandler(log_path, encoding="ascii")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(console_level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger


def timestamp_now() -> str:
    return dt.datetime.now().strftime("%Y%m%d_%H%M%S")


def default_log_path() -> str:
    return os.path.join("logs", f"pulsar_x2_debug_{timestamp_now()}.log")


def hex_bytes(data, limit: int | None = 256) -> str:
    if data is None:
        return "None"
    if isinstance(data, list):
        data = bytes(data)
    if not isinstance(data, (bytes, bytearray)):
        return str(data)
    if limit is not None and len(data) > limit:
        return data[:limit].hex() + f"...(len={len(data)})"
    return data.hex()


def format_path(path) -> str:
    if isinstance(path, (bytes, bytearray)):
        return path.hex()
    return str(path)


def open_device(info: dict):
    if hasattr(hid, "device"):
        dev = hid.device()
        dev.open_path(info["path"])
        return dev
    if hasattr(hid, "Device"):
        return hid.Device(path=info["path"])
    raise RuntimeError("HID backend missing device constructor")


def enumerate_devices(vendor_id: int = 0, product_id: int = 0) -> list[dict]:
    try:
        return hid.enumerate(vendor_id, product_id)
    except TypeError:
        devices = hid.enumerate()
        if vendor_id == 0 and product_id == 0:
            return devices
        filtered = []
        for info in devices:
            if vendor_id and info.get("vendor_id") != vendor_id:
                continue
            if product_id and info.get("product_id") != product_id:
                continue
            filtered.append(info)
        return filtered


def safe_call(logger, label: str, func, *args):
    try:
        return func(*args), None
    except Exception as exc:
        logger.debug("%s error=%s", label, exc)
        return None, exc


def log_environment(logger, hid_module):
    logger.info("debug_logger_start")
    logger.info("python=%s", sys.version.replace("\n", " "))
    logger.info("executable=%s", sys.executable)
    logger.info("platform=%s", platform.platform())
    logger.info("cwd=%s", os.getcwd())
    logger.info("hid_module=%s", getattr(hid_module, "__file__", "unknown"))
    logger.info("hid_version=%s", getattr(hid_module, "__version__", "unknown"))


def log_device_info(logger, info: dict):
    vid = info.get("vendor_id")
    pid = info.get("product_id")
    interface = info.get("interface_number")
    usage_page = info.get("usage_page")
    usage = info.get("usage")
    path = format_path(info.get("path"))
    logger.info(
        "device vid=0x%04x pid=0x%04x interface=%s usage_page=0x%04x usage=0x%04x path=%s",
        vid or 0,
        pid or 0,
        interface,
        usage_page or 0,
        usage or 0,
        path,
    )
    safe = dict(info)
    safe["path"] = format_path(info.get("path"))
    logger.debug("device_info=%s", json.dumps(safe, default=str, ensure_ascii=True))


def drain_input(logger, dev, attempts: int = 6) -> None:
    try:
        dev.set_nonblocking(1)
        for _ in range(attempts):
            data = dev.read(17)
            if not data:
                break
    except Exception as exc:
        logger.debug("drain_input error=%s", exc)
    finally:
        try:
            dev.set_nonblocking(0)
        except Exception:
            pass


def normalize_input_report(data: bytes | list[int]) -> bytes:
    if isinstance(data, list):
        data = bytes(data)
    if len(data) == 16:
        return b"\x08" + data
    return data


def read_cmd(
    logger, dev, expected_cmd: int, timeout: float, log_other: bool
) -> bytes | None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        data, err = safe_call(logger, "cmd04_read", dev.read, 17, 250)
        if err:
            return None
        if not data:
            continue
        payload = normalize_input_report(data)
        if len(payload) < 7 or payload[0] != 0x08:
            continue
        if payload[1] != expected_cmd:
            if log_other:
                logger.debug(
                    "cmd04 skip cmd=0x%02x data=%s", payload[1], hex_bytes(payload)
                )
            continue
        return payload
    return None


def read_cmd04(logger, dev) -> int | None:
    drain_input(logger, dev)

    safe_call(logger, "cmd04_write", dev.write, CMD04_PACKET)
    payload = read_cmd(logger, dev, 0x04, 0.8, log_other=True)
    if payload is None:
        logger.info("cmd04 init sequence")
        for packet in CMD04_INIT_SEQUENCE:
            safe_call(logger, "cmd04_init_write", dev.write, packet)
            time.sleep(0.01)
        payload = read_cmd(logger, dev, 0x04, 2.0, log_other=True)

    if payload is None:
        logger.info("cmd04 response not found")
        return None

    raw = payload[6]
    logger.info("cmd04 response raw=%d data=%s", raw, hex_bytes(payload))
    return raw


def snapshot_device(logger, info, cached_descriptors):
    log_device_info(logger, info)

    if info.get("usage_page") != USAGE_PAGE_VENDOR:
        return

    dev = None
    try:
        dev = open_device(info)

        for label, func in [
            ("manufacturer", "manufacturer"),
            ("product", "product"),
            ("serial", "serial"),
        ]:
            if hasattr(dev, func):
                value, err = safe_call(logger, label, getattr(dev, func))
                if err is None and value:
                    logger.info("%s=%s", label, value)

        if hasattr(dev, "get_report_descriptor"):
            descriptor, err = safe_call(
                logger, "report_descriptor", dev.get_report_descriptor
            )
            if descriptor is not None:
                descriptor = bytes(descriptor)
                path = format_path(info.get("path"))
                if path not in cached_descriptors:
                    cached_descriptors.add(path)
                    logger.info(
                        "report_descriptor len=%d data=%s",
                        len(descriptor),
                        hex_bytes(descriptor, 512),
                    )
            elif err:
                logger.debug("report_descriptor_error=%s", err)

        read_cmd04(logger, dev)
    except Exception as exc:
        logger.info("device_error=%s", exc)
    finally:
        if dev is not None:
            try:
                dev.close()
            except Exception:
                pass


def run(args) -> int:
    logger = setup_logger(
        args.log_path, logging.INFO if args.console else logging.WARNING
    )
    log_environment(logger, hid)

    cached_descriptors = set()

    while True:
        all_devices = enumerate_devices(VID, 0)
        devices = [
            d
            for d in all_devices
            if d.get("vendor_id") == VID and d.get("product_id") in PIDS
        ]
        logger.info(
            "scan vendor_devices_total=%d pulsar=%d", len(all_devices), len(devices)
        )

        for info in devices:
            snapshot_device(logger, info, cached_descriptors)

        if args.once:
            break
        time.sleep(args.interval)

    logger.info("debug_logger_stop")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Pulsar X2 cmd04 debug logger.")
    parser.add_argument(
        "--interval",
        type=int,
        default=60,
        help="Seconds between scans (default: 60)",
    )
    parser.add_argument(
        "--log-path",
        default=default_log_path(),
        help="Log file path (default: logs/pulsar_x2_debug_YYYYMMDD_HHMMSS.log)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single scan and exit",
    )
    parser.add_argument(
        "--console",
        action="store_true",
        help="Print info to console while logging",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.interval < 1:
        print("--interval must be >= 1")
        return 2
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
