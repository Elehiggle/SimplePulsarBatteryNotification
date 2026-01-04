from __future__ import annotations

import time

from .common import enumerate_devices_cached, format_path, hid, parse_cmd04_payload

NAME = "x2cl"
DISPLAY_NAME = "Pulsar X2 Crazylight"
VID = 0x3710
PID_WIRELESS = 0x5406  # Pulsar 8K Dongle.
PID_WIRED = 0x3414  # Pulsar X2 Crazylight (wired).
PID_WIRED_X3_LHD_CL = 0x3508  # Possibly Pulsar X3 LHD CrazyLight. Unused.
USAGE_PAGE_VENDOR = 0xFF02

OUTPUT_REPORT_ID = 0x08
INPUT_REPORT_ID = 0x08
DEFAULT_TRANSPORT = "output"

CMD03_PACKET = bytes([OUTPUT_REPORT_ID, 0x03] + [0x00] * 14 + [0x4A])
CMD04_PACKET = bytes([OUTPUT_REPORT_ID, 0x04] + [0x00] * 14 + [0x49])
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


def list_candidate_devices(mode: str, interface: int | None) -> list[dict]:
    allowed_pids = {PID_WIRELESS, PID_WIRED}
    if mode == "wireless":
        allowed_pids = {PID_WIRELESS}
    elif mode == "wired":
        allowed_pids = {PID_WIRED}

    devices = []
    for info in enumerate_devices_cached(VID, 0):
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


def open_device(info: dict):
    if hasattr(hid, "device"):
        dev = hid.device()
        dev.open_path(info["path"])
        return dev
    if hasattr(hid, "Device"):
        return hid.Device(path=info["path"])
    raise RuntimeError("HID backend missing device constructor")


def drain_input(dev, attempts: int = 6) -> None:
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
        return bytes([INPUT_REPORT_ID]) + data
    return data


def _send_report(dev, payload: bytes, transport: str) -> None:
    if transport == "feature" and hasattr(dev, "send_feature_report"):
        dev.send_feature_report(payload)
        return
    dev.write(payload)


def read_battery_cmd04(
    dev,
    debug: bool,
    transport: str = DEFAULT_TRANSPORT,
    reader=None,
) -> tuple[int, bool] | None:
    reader = dev if reader is None else reader
    drain_input(reader)

    def read_cmd(expected_cmd: int, timeout: float, log_other: bool) -> bytes | None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            data = reader.read(17, 250)
            if not data:
                continue
            payload = normalize_input_report(data)
            if len(payload) < 7 or payload[0] != INPUT_REPORT_ID:
                continue
            if payload[1] != expected_cmd:
                if debug and log_other:
                    print(f"cmd04 skip cmd=0x{payload[1]:02x} data={payload.hex()}")
                continue
            return payload
        return None

    def attempt_cmd04(timeout: float) -> bytes | None:
        _send_report(dev, CMD04_PACKET, transport)
        return read_cmd(0x04, timeout, log_other=True)

    payload = attempt_cmd04(0.8)
    if payload is None:
        if debug:
            print("cmd04 init sequence")
        for payload_init in CMD04_INIT_SEQUENCE:
            _send_report(dev, payload_init, transport)
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
    transport: str = DEFAULT_TRANSPORT,
) -> tuple[object | None, object | None, dict | None, dict | None]:
    if not devices:
        return None, None, None, None
    if index is not None:
        if index < 0 or index >= len(devices):
            print(f"Invalid --index {index}; {len(devices)} device(s) available.")
            return None, None, None, None
        devices = [devices[index]]

    for info in devices:
        dev = None
        try:
            dev = open_device(info)
            status = read_battery_cmd04(dev, debug, transport=transport, reader=dev)
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

    return None, None, None, None
