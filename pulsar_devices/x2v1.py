from __future__ import annotations

import time

from .common import enumerate_devices_cached, format_path, hid, parse_cmd04_payload

NAME = "x2v1"
DISPLAY_NAME = "Pulsar X2 V1"
VID = 0x25A7
PID_WIRELESS = 0xFA7C
PID_WIRED = 0xFA7B
USAGE_PAGE_VENDOR: int | None = None

OUTPUT_REPORT_ID = 0x08
INPUT_REPORT_IDS = {0x08, 0x09}
DEFAULT_INPUT_REPORT_ID = 0x09
DEFAULT_TRANSPORT = "auto"

CMD03_PACKET = bytes([OUTPUT_REPORT_ID, 0x03] + [0x00] * 14 + [0x4A])
CMD04_PACKET = bytes([OUTPUT_REPORT_ID, 0x04] + [0x00] * 14 + [0x49])
CMD0E_PACKET = bytes.fromhex("080e00000000000000000000000000003f")

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

    body = (
        bytes([OUTPUT_REPORT_ID, 0x01, 0x00, 0x00, 0x00, 0x08])
        + nonce_bytes
        + bytes([0x00] * 6)
    )
    chk = (CMD01_TARGET_SUM - (sum(body) & 0xFF)) & 0xFF
    return body + bytes([chk])


CMD04_WARMUP_MINIMAL = [
    build_cmd01_packet,
    lambda: CMD03_PACKET,
    lambda: CMD0E_PACKET,
]


def list_candidate_devices(mode: str, interface: int | None) -> list[dict]:
    allowed_pairs = set()
    if mode != "wired":
        allowed_pairs.add((VID, PID_WIRELESS))
    if mode != "wireless":
        allowed_pairs.add((VID, PID_WIRED))

    devices = []
    for info in enumerate_devices_cached(VID, 0):
        pair = (info.get("vendor_id"), info.get("product_id"))
        if pair not in allowed_pairs:
            continue
        if interface is not None and info.get("interface_number") != interface:
            continue
        if (
            USAGE_PAGE_VENDOR is not None
            and info.get("usage_page") != USAGE_PAGE_VENDOR
        ):
            continue
        devices.append(info)

    def sort_key(item: dict):
        iface = item.get("interface_number")
        up = item.get("usage_page")
        usage = item.get("usage")
        path = format_path(item.get("path"))

        prefer_iface = 0 if iface == 1 else 1
        is_vendor_page = isinstance(up, int) and up >= 0xFF00
        prefer_vendor_page = 0 if is_vendor_page else 1

        vendor_rank = {0xFF02: 0, 0xFF01: 1, 0xFF03: 2, 0xFF04: 3}
        prefer_common_vendor = 0 if up in vendor_rank else 1
        vendor_order = vendor_rank.get(up, 99)

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
    if len(data) == 16 and data and data[0] in {0x01, 0x02, 0x03, 0x04, 0x08, 0x0E}:
        return bytes([DEFAULT_INPUT_REPORT_ID]) + data
    return data


def _supports_feature_reports(dev: object) -> bool:
    return hasattr(dev, "send_feature_report")


def _send_report(dev, payload: bytes, transport: str) -> None:
    use_feature = transport == "feature" or (
        transport == "auto" and _supports_feature_reports(dev)
    )
    if use_feature and hasattr(dev, "send_feature_report"):
        dev.send_feature_report(payload)
        return

    result = dev.write(payload)
    if isinstance(result, int) and result < 0:
        raise OSError("HID write failed")


def read_battery_cmd04(
    dev,
    debug: bool,
    transport: str = DEFAULT_TRANSPORT,
    reader=None,
) -> tuple[int, bool] | None:
    reader = dev if reader is None else reader
    drain_input(reader)

    def read_once(max_len: int):
        try:
            return reader.read(max_len, 250)
        except TypeError:
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
                        print(f"cmd04 skip cmd=0x{payload[1]:02x} data={payload.hex()}")
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

    payload: bytes | None
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
    transport: str = DEFAULT_TRANSPORT,
) -> tuple[object | None, object | None, dict | None, dict | None]:
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

    def probe_pair(writer_info: dict, reader_info: dict):
        w = None
        r = None
        try:
            w = open_device(writer_info)
            r = (
                w
                if writer_info.get("path") == reader_info.get("path")
                else open_device(reader_info)
            )
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

    allowed_pairs = {(VID, PID_WIRELESS), (VID, PID_WIRED)}
    reader_pool = [
        info
        for info in enumerate_devices_cached(VID, 0)
        if (info.get("vendor_id"), info.get("product_id")) in allowed_pairs
    ]

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

        w, r = probe_pair(writer_info, writer_info)
        if w is not None and r is not None:
            if debug:
                print(f"selected path={format_path(writer_info.get('path'))}")
            return w, r, writer_info, writer_info

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
