#!/usr/bin/env python3
"""
Pulsar battery logger for Windows (X2 Crazylight + X2 V1).

Uses vendor HID report 0x08 command 0x04; response contains battery percent
at byte 6 and charging flag at byte 7.
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import time

from pulsar_devices import BACKENDS, BACKEND_ORDER


def select_backend(
    backend_name: str,
    mode: str,
    interface: int | None,
) -> tuple[object | None, list[dict]]:
    if backend_name != "auto":
        backend = BACKENDS.get(backend_name)
        if backend is None:
            raise ValueError(f"Unknown backend '{backend_name}'")
        return backend, backend.list_candidate_devices(mode, interface)

    for backend in BACKEND_ORDER:
        devices = backend.list_candidate_devices(mode, interface)
        if devices:
            return backend, devices

    return None, []


def resolve_transport(backend, transport: str) -> str:
    if transport == "auto":
        return backend.DEFAULT_TRANSPORT
    return transport


def close_devices(dev_write, dev_read) -> None:
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


def read_battery_status(
    backend_name: str = "auto",
    mode: str = "auto",
    interface: int | None = None,
    transport: str = "auto",
    debug: bool = False,
) -> tuple[int, bool] | None:
    backend, devices = select_backend(backend_name, mode, interface)
    if backend is None or not devices:
        return None

    transport = resolve_transport(backend, transport)
    dev_write = None
    dev_read = None

    try:
        dev_write, dev_read, _, _ = backend.select_device(
            devices,
            index=None,
            debug=debug,
            transport=transport,
        )
        if dev_write is None or dev_read is None:
            return None

        return backend.read_battery_cmd04(
            dev_write,
            debug=debug,
            transport=transport,
            reader=dev_read,
        )
    finally:
        close_devices(dev_write, dev_read)


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


def list_devices(backend_name: str, mode: str, interface: int | None) -> None:
    backends = BACKEND_ORDER if backend_name == "auto" else [BACKENDS[backend_name]]
    for backend in backends:
        print(f"[{backend.NAME}]")
        devices = backend.list_candidate_devices(mode, interface)
        backend.print_devices(devices)


def run_logger(args: argparse.Namespace) -> int:
    if args.list_devices:
        list_devices(args.backend, args.mode, args.interface)
        return 0

    log_handle = open_log(args.log_path)
    backend = None
    devices: list[dict] = []
    dev_write = None
    dev_read = None

    try:
        while True:
            if dev_write is None or dev_read is None:
                backend, devices = select_backend(
                    args.backend,
                    args.mode,
                    args.interface,
                )
                if backend is None or not devices:
                    print("No matching Pulsar devices found; will retry.")
                    if args.once:
                        return 1
                    time.sleep(args.interval)
                    continue

                transport = resolve_transport(backend, args.transport)
                dev_write, dev_read, _, _ = backend.select_device(
                    devices,
                    args.index,
                    args.debug,
                    transport,
                )
                if dev_write is None or dev_read is None:
                    print(
                        "No responsive device found; will retry if --once was omitted."
                    )
                    if args.once:
                        return 1
                    time.sleep(args.interval)
                    continue

            transport = resolve_transport(backend, args.transport)
            battery = None
            charging = None
            try:
                status = backend.read_battery_cmd04(
                    dev_write,
                    args.debug,
                    transport,
                    reader=dev_read,
                )
                if status is not None:
                    battery, charging = status
            except (OSError, ValueError) as exc:
                if args.debug:
                    print(f"read_failed err={exc}")
                close_devices(dev_write, dev_read)
                dev_write = None
                dev_read = None

            if battery is not None and charging is not None:
                stamp = timestamp(args.utc)
                log_handle.write(f"{stamp},{battery}\n")
                log_handle.flush()
                charging_str = "yes" if charging else "no"
                print(f"{stamp} battery={battery}% charging={charging_str}")
                if args.once:
                    return 0
            else:
                print("Battery read failed; will retry.")
                close_devices(dev_write, dev_read)
                dev_write = None
                dev_read = None
                if args.once:
                    return 1

            time.sleep(args.interval)
    finally:
        close_devices(dev_write, dev_read)
        log_handle.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Log Pulsar battery percentage on Windows."
    )
    parser.add_argument(
        "--backend",
        choices=["auto", *BACKENDS.keys()],
        default="auto",
        help="Device backend (default: auto)",
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
        help="Send transport for cmd04: feature, output, or auto",
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
