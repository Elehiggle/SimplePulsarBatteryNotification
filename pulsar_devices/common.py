from __future__ import annotations

import time

import hid

ENUMERATE_CACHE_TTL = 60.0

_ENUM_CACHE: dict[tuple[int, int], tuple[float, list[dict]]] = {}


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


def enumerate_devices_cached(vendor_id: int = 0, product_id: int = 0) -> list[dict]:
    now = time.monotonic()
    key = (vendor_id, product_id)
    cached = _ENUM_CACHE.get(key)
    if cached is not None:
        cached_at, cached_devices = cached
        if now - cached_at < ENUMERATE_CACHE_TTL:
            return cached_devices

    devices = enumerate_devices(vendor_id, product_id)
    _ENUM_CACHE[key] = (now, devices)
    return devices


def format_path(path) -> str:
    if isinstance(path, bytes):
        return path.hex()
    return str(path)


def parse_cmd04_payload(payload: bytes) -> tuple[int, bool] | None:
    if len(payload) < 8:
        return None
    battery = payload[6]
    charging = payload[7] != 0x00
    return battery, charging
