import argparse
import ctypes
import datetime as dt
import glob
import json
import logging
import os
import queue
import sys
import threading
import time
import tkinter as tk
import winsound

import customtkinter as ctk
import pystray
from PIL import Image, ImageDraw, ImageTk
from windows_toasts import (
    Toast,
    ToastDisplayImage,
    ToastImage,
    ToastImagePosition,
    WindowsToaster,
)

import pulsar_battery_logger as battery_logger

APP_NAME = "Simple Pulsar Battery"
TOAST_APP_NAME = APP_NAME
SETTINGS_DIR_NAME = "SimplePulsarBatteryNotification"
SETTINGS_FILENAME = "settings.json"

DEFAULT_SETTINGS = {
    "battery_level_alert_threshold": 5,
    "battery_level_alert_threshold_locked": 30,
    "refresh_interval_seconds": 5,
    "beep_enabled": True,
    "alert_cooldown_minutes": 20,
}

BATTERY_STATUS_CACHE_TTL = 60 * 10
HISTORY_MAX = 30
ALERT_COOLDOWN_SECONDS = 60 * 10

log_level_root = os.getenv("LOG_LEVEL_ROOT", "INFO").upper()
logging.basicConfig(level=log_level_root)

log_level = os.getenv("LOG_LEVEL", "INFO").upper()
logger = logging.getLogger(__name__)
logger.setLevel(log_level)

_SETTINGS_LOCK = threading.Lock()
_SETTINGS = dict(DEFAULT_SETTINGS)

_LAST_BATTERY_STATUS: tuple[float, tuple[int, bool], str, str] | None = None

_HISTORY: list[str] = []
_HISTORY_LOCK = threading.Lock()

_UI_QUEUE: "queue.Queue[tuple[str, object]]" = queue.Queue()
_TOAST_OPEN_HANDLER = None
_LAST_ALERT_AT: float | None = None


ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")


def load_settings() -> dict:
    settings = dict(DEFAULT_SETTINGS)

    preferred_path = get_settings_path(prefer_existing=False)
    if os.path.exists(preferred_path):
        try:
            with open(preferred_path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            if isinstance(data, dict):
                settings.update(data)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            logger.warning("settings load failed err=%s", exc)
        settings["beep_enabled"] = bool(settings.get("beep_enabled", True))
        settings["alert_cooldown_minutes"] = int(
            settings.get("alert_cooldown_minutes", 10)
        )
        return settings

    for directory in _settings_dir_candidates():
        candidate = os.path.join(directory, SETTINGS_FILENAME)
        if candidate == preferred_path:
            continue
        if os.path.exists(candidate):
            try:
                with open(candidate, "r", encoding="utf-8") as handle:
                    data = json.load(handle)
                if isinstance(data, dict):
                    settings.update(data)
                settings["beep_enabled"] = bool(settings.get("beep_enabled", True))
                save_settings(settings)
            except (OSError, json.JSONDecodeError, ValueError) as exc:
                logger.warning("settings load failed err=%s", exc)
            return settings

    env_unlocked = os.getenv("BATTERY_LEVEL_ALERT_THRESHOLD")
    env_locked = os.getenv("BATTERY_LEVEL_ALERT_THRESHOLD_LOCKED")
    if env_unlocked is not None:
        try:
            settings["battery_level_alert_threshold"] = int(env_unlocked)
        except ValueError:
            pass
    if env_locked is not None:
        try:
            settings["battery_level_alert_threshold_locked"] = int(env_locked)
        except ValueError:
            pass
    settings["alert_cooldown_minutes"] = int(settings.get("alert_cooldown_minutes", 10))
    return settings


def save_settings(settings: dict) -> None:
    settings_path = get_settings_path(prefer_existing=False)
    os.makedirs(os.path.dirname(settings_path), exist_ok=True)
    with open(settings_path, "w", encoding="utf-8") as handle:
        json.dump(settings, handle, indent=2, ensure_ascii=True)


def get_thresholds() -> tuple[int, int]:
    with _SETTINGS_LOCK:
        return (
            _SETTINGS["battery_level_alert_threshold"],
            _SETTINGS["battery_level_alert_threshold_locked"],
        )


def get_refresh_interval() -> int:
    with _SETTINGS_LOCK:
        return int(_SETTINGS.get("refresh_interval_seconds", 5))


def update_settings(unlocked: int, locked: int, refresh_interval: int) -> None:
    with _SETTINGS_LOCK:
        _SETTINGS["battery_level_alert_threshold"] = unlocked
        _SETTINGS["battery_level_alert_threshold_locked"] = locked
        _SETTINGS["refresh_interval_seconds"] = refresh_interval
        _SETTINGS["beep_enabled"] = bool(_SETTINGS.get("beep_enabled", True))
        _SETTINGS["alert_cooldown_minutes"] = int(
            _SETTINGS.get("alert_cooldown_minutes", 10)
        )
    save_settings(_SETTINGS)


def update_settings_with_beep(
    unlocked: int,
    locked: int,
    refresh_interval: int,
    beep_enabled: bool,
    alert_cooldown_minutes: int,
) -> None:
    with _SETTINGS_LOCK:
        _SETTINGS["battery_level_alert_threshold"] = unlocked
        _SETTINGS["battery_level_alert_threshold_locked"] = locked
        _SETTINGS["refresh_interval_seconds"] = refresh_interval
        _SETTINGS["beep_enabled"] = bool(beep_enabled)
        _SETTINGS["alert_cooldown_minutes"] = int(alert_cooldown_minutes)
    save_settings(_SETTINGS)


def get_beep_enabled() -> bool:
    with _SETTINGS_LOCK:
        return bool(_SETTINGS.get("beep_enabled", True))


def get_alert_cooldown_seconds() -> int:
    with _SETTINGS_LOCK:
        minutes = int(_SETTINGS.get("alert_cooldown_minutes", 10))
    minutes = max(0, min(minutes, 120))
    return minutes * 60


def get_foreground_window():
    return ctypes.windll.user32.GetForegroundWindow()


def _store_python_package_id() -> str | None:
    exe = os.path.normpath(sys.executable)
    if "WindowsApps" not in exe:
        return None
    for part in exe.split(os.sep):
        if part.startswith("PythonSoftwareFoundation.Python."):
            return part
    return None


def _settings_dir_candidates() -> list[str]:
    candidates: list[str] = []
    appdata = os.getenv("APPDATA") or os.path.expanduser("~")
    local_appdata = os.getenv("LOCALAPPDATA")

    if local_appdata:
        package_id = _store_python_package_id()
        if package_id:
            candidates.append(
                os.path.join(
                    local_appdata,
                    "Packages",
                    package_id,
                    "LocalCache",
                    "Roaming",
                    SETTINGS_DIR_NAME,
                )
            )
        else:
            pattern = os.path.join(
                local_appdata,
                "Packages",
                "PythonSoftwareFoundation.Python.*",
                "LocalCache",
                "Roaming",
                SETTINGS_DIR_NAME,
            )
            candidates.extend(glob.glob(pattern))

    candidates.append(os.path.join(appdata, SETTINGS_DIR_NAME))
    return list(dict.fromkeys(candidates))


def get_settings_path(prefer_existing: bool = True) -> str:
    candidates = _settings_dir_candidates()
    if prefer_existing:
        for directory in candidates:
            candidate = os.path.join(directory, SETTINGS_FILENAME)
            if os.path.exists(candidate):
                return candidate
    if candidates:
        return os.path.join(candidates[0], SETTINGS_FILENAME)
    return os.path.join(os.path.expanduser("~"), SETTINGS_FILENAME)


def _resource_path(filename: str) -> str:
    base = getattr(sys, "_MEIPASS", None)
    if base:
        return os.path.join(base, filename)
    return os.path.join(os.path.dirname(__file__), filename)


def _set_window_icon(root: ctk.CTk) -> None:
    icon_ico = _resource_path("icon.ico")
    icon_png = _resource_path("icon.png")
    try:
        if os.path.exists(icon_ico):
            root.iconbitmap(icon_ico)
        if os.path.exists(icon_png):
            image = Image.open(icon_png)
            icons = []
            for size in (16, 24, 32, 48, 64):
                resized = image.resize((size, size), Image.LANCZOS)
                icons.append(ImageTk.PhotoImage(resized))
            root._app_icons = icons  # keep references
            root.iconphoto(True, *icons)
    except Exception as exc:
        logger.debug("window icon set failed err=%s", exc)


def _set_taskbar_icon(root: ctk.CTk) -> None:
    icon_path = _resource_path("icon.ico")
    if not os.path.exists(icon_path):
        return
    try:
        root.update_idletasks()
        hwnd = root.winfo_id()
        if not hwnd:
            return
        IMAGE_ICON = 1
        LR_LOADFROMFILE = 0x0010
        LR_DEFAULTSIZE = 0x0040
        WM_SETICON = 0x0080
        ICON_SMALL = 0
        ICON_BIG = 1

        hicon = ctypes.windll.user32.LoadImageW(
            None,
            icon_path,
            IMAGE_ICON,
            0,
            0,
            LR_LOADFROMFILE | LR_DEFAULTSIZE,
        )
        if not hicon:
            return
        ctypes.windll.user32.SendMessageW(hwnd, WM_SETICON, ICON_SMALL, hicon)
        ctypes.windll.user32.SendMessageW(hwnd, WM_SETICON, ICON_BIG, hicon)
        root._win_taskbar_icon = hicon
    except Exception as exc:
        logger.debug("taskbar icon set failed err=%s", exc)


def _set_app_user_model_id(app_id: str) -> None:
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(app_id)
    except Exception as exc:
        logger.debug("app user model id failed err=%s", exc)


def _add_toast_icon(toast: Toast) -> None:
    icon_path = _resource_path("icon.png")
    if not os.path.exists(icon_path):
        return
    try:
        toast.AddImage(
            ToastDisplayImage(
                ToastImage(icon_path),
                position=ToastImagePosition.AppLogo,
            )
        )
    except Exception as exc:
        logger.debug("toast icon attach failed path=%s err=%s", icon_path, exc)


def show_toast(text_fields, beep: bool) -> None:
    toast = Toast()
    toast.text_fields = text_fields
    toast.on_activated = None
    _add_toast_icon(toast)

    logger.info("toast send start fields=%s", text_fields)
    max_retries = 3
    for attempt in range(max_retries):
        try:
            toaster = WindowsToaster(TOAST_APP_NAME)
            toaster.show_toast(toast)
            # If successful, break out of the loop and beep as normal
            if beep and get_beep_enabled():
                winsound.Beep(200, 200)
                winsound.Beep(200, 200)
                winsound.Beep(200, 200)
            logger.info("toast sent attempt=%d", attempt + 1)
            return
        except ImportError:
            # This exception can occur extremely rarely
            if attempt == max_retries - 1:
                error_message = (
                    "An error occurred loading required modules.\n\n"
                    "The application will now be restarted to resolve this issue."
                )
                ctypes.windll.user32.MessageBoxW(None, error_message, "Error", 0)

                # Restart the exe
                # If running as a PyInstaller-built exe, sys.executable should be the path to it.
                exe_path = sys.executable
                # On Windows, re-run the executable with the same arguments.
                os.execv(exe_path, [exe_path] + sys.argv)
            time.sleep(1)
        except Exception as exc:
            logger.warning("toast send failed err=%s attempt=%d", exc, attempt + 1)
            time.sleep(0.2)


def dispatch_toast(text_fields, beep: bool) -> None:
    if _TOAST_OPEN_HANDLER is None:
        show_toast(text_fields, beep)
        return
    logger.info("toast queued fields=%s", text_fields)
    _UI_QUEUE.put(("toast", (text_fields, beep)))


def send_alert(battery_level):
    dispatch_toast([f"Battery: {battery_level}%"], beep=True)


def send_status_toast(battery_level: int, is_charging: bool) -> None:
    charging_text = "yes" if is_charging else "no"
    dispatch_toast(
        [
            f"Battery: {battery_level}%",
            f"Charging: {charging_text}",
        ],
        beep=False,
    )


def read_battery_status() -> tuple[
    tuple[int, bool] | None,
    bool,
    str | None,
    str | None,
]:
    global _LAST_BATTERY_STATUS

    status_info = battery_logger.read_battery_status_info()
    if status_info is not None:
        status, device_name = status_info
        timestamp = dt.datetime.now().isoformat(timespec="seconds")
        _LAST_BATTERY_STATUS = (time.monotonic(), status, timestamp, device_name)
        return status, False, timestamp, device_name

    if _LAST_BATTERY_STATUS is None:
        return None, False, None, None

    cached_at, cached_status, cached_timestamp, cached_device = _LAST_BATTERY_STATUS
    if time.monotonic() - cached_at <= BATTERY_STATUS_CACHE_TTL:
        logger.debug("using cached battery status")
        return cached_status, True, cached_timestamp, cached_device

    return None, False, None, None


def append_history(line: str) -> None:
    with _HISTORY_LOCK:
        _HISTORY.insert(0, line)
        if len(_HISTORY) > HISTORY_MAX:
            _HISTORY.pop()
    _UI_QUEUE.put(("history", None))


def get_history() -> list[str]:
    with _HISTORY_LOCK:
        return list(_HISTORY)


def enqueue_status(
    battery: int | None,
    charging: bool | None,
    timestamp: str | None,
    cached: bool,
    device_name: str | None,
) -> None:
    _UI_QUEUE.put(("status", (battery, charging, timestamp, cached, device_name)))


def enqueue_busy(is_busy: bool) -> None:
    _UI_QUEUE.put(("busy", is_busy))


def should_send_alert() -> bool:
    global _LAST_ALERT_AT
    now = time.monotonic()
    cooldown = get_alert_cooldown_seconds()
    if cooldown <= 0:
        return True
    if _LAST_ALERT_AT is None or now - _LAST_ALERT_AT >= cooldown:
        _LAST_ALERT_AT = now
        return True
    return False


def check_battery_is_low(battery_alert_threshold: int, allow_alerts: bool) -> None:
    enqueue_busy(True)
    try:
        status, cached, timestamp, device_name = read_battery_status()
    finally:
        enqueue_busy(False)
    if status is None:
        logger.error("Battery status not available")
        append_history(f"{dt.datetime.now().isoformat(timespec='seconds')} read failed")
        enqueue_status(None, None, None, False, None)
        return

    battery_percentage, is_charging = status
    enqueue_status(battery_percentage, is_charging, timestamp, cached, device_name)

    cached_suffix = " (cached)" if cached else ""
    charging_text = "yes" if is_charging else "no"
    append_history(
        f"{timestamp} battery={battery_percentage}% charging={charging_text}{cached_suffix}"
    )

    if not is_charging:
        logger.debug(
            "Battery: NotCharging %d%%, threshold: %d",
            battery_percentage,
            battery_alert_threshold,
        )
        if battery_percentage < battery_alert_threshold:
            logger.info("Warning: Battery level is below threshold and not charging!")
            if allow_alerts and should_send_alert():
                send_alert(battery_percentage)
            elif allow_alerts:
                logger.info("Alert suppressed due to cooldown")
        else:
            logger.info("Battery is not charging, but the battery level is sufficient")
    else:
        logger.info("Battery state is charging or above the threshold")


def monitor_loop(stop_event: threading.Event, check_now_event: threading.Event) -> None:
    last_time_windows_was_unlocked = 0
    last_check = 0
    next_refresh = 0.0

    unlocked_threshold, _ = get_thresholds()
    check_battery_is_low(unlocked_threshold, allow_alerts=True)

    while not stop_event.is_set():
        if check_now_event.is_set():
            check_now_event.clear()
            unlocked_threshold, _ = get_thresholds()
            check_battery_is_low(unlocked_threshold, allow_alerts=False)

        now = time.time()
        refresh_interval = max(1, get_refresh_interval())
        if now >= next_refresh:
            unlocked_threshold, _ = get_thresholds()
            check_battery_is_low(unlocked_threshold, allow_alerts=True)
            next_refresh = now + refresh_interval

        is_pc_locked = get_foreground_window() == 0
        if stop_event.wait(2):
            break
        is_pc_locked = is_pc_locked and get_foreground_window() == 0

        unlocked_threshold, locked_threshold = get_thresholds()

        if is_pc_locked:
            if now - last_time_windows_was_unlocked < 10:  # Check if we just locked windows within last 10 seconds
                logger.debug("PC is locked, time to check")
                check_battery_is_low(locked_threshold, allow_alerts=True)
        else:
            last_time_windows_was_unlocked = now
            if now - last_check > 60 * 20:  # Check every 20 minutes
                last_check = now
                last_time_windows_was_unlocked = now
                check_battery_is_low(unlocked_threshold, allow_alerts=True)

        if stop_event.wait(0.5):
            break


def create_tray_image() -> Image.Image:
    for name in ("icon.ico", "icon.png"):
        icon_path = _resource_path(name)
        if os.path.exists(icon_path):
            try:
                image = Image.open(icon_path).convert("RGBA")
                return image.resize((64, 64), Image.LANCZOS)
            except OSError:
                pass
    width = 64
    height = 64
    image = Image.new("RGB", (width, height), "black")
    draw = ImageDraw.Draw(image)
    draw.rectangle((width // 2, 0, width, height // 2), fill="white")
    draw.rectangle((0, height // 2, width // 2, height), fill="white")
    return image


def format_relative_time(source: dt.datetime | None) -> str:
    if source is None:
        return "n/a"
    delta = dt.datetime.now() - source
    seconds = int(delta.total_seconds())
    if seconds < 10:
        return "just now"
    if seconds < 60:
        return f"{seconds} sec ago"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes} min ago"
    hours = minutes // 60
    return f"{hours} hr ago"


def battery_percent_color(percent: int) -> str:
    clamped = max(0, min(100, percent))
    t = clamped / 100.0
    red = (231, 76, 60)
    green = (46, 204, 113)
    r = int(round(red[0] + (green[0] - red[0]) * t))
    g = int(round(red[1] + (green[1] - red[1]) * t))
    b = int(round(red[2] + (green[2] - red[2]) * t))
    return f"#{r:02x}{g:02x}{b:02x}"


class CollapsibleSection(ctk.CTkFrame):
    def __init__(
        self,
        master,
        title: str,
        default_open: bool = True,
        on_toggle=None,
    ):
        super().__init__(master)
        self._title = title
        self._is_open = default_open
        self._on_toggle = on_toggle

        self.grid_columnconfigure(0, weight=1)

        self.header_button = ctk.CTkButton(
            self,
            text=self._header_text(),
            command=self.toggle,
            anchor="w",
            fg_color=("#343434", "#2f2f2f"),
            hover_color=("#3f3f3f", "#3a3a3a"),
            corner_radius=8,
            height=32,
        )
        self.header_button.grid(row=0, column=0, sticky="ew", padx=8, pady=(8, 4))

        self.body = ctk.CTkFrame(self)
        self.body.grid(row=1, column=0, sticky="ew", padx=8, pady=(0, 8))
        if not self._is_open:
            self.body.grid_remove()

    def _header_text(self) -> str:
        return self._title

    def toggle(self) -> None:
        self._is_open = not self._is_open
        if self._is_open:
            self.body.grid()
        else:
            self.body.grid_remove()
        self.header_button.configure(text=self._header_text())
        if self._on_toggle is not None:
            self._on_toggle(self._is_open)
        self._resize_root()

    def _resize_root(self) -> None:
        root = self.winfo_toplevel()
        try:
            root.update_idletasks()
            width = max(root.winfo_width(), root.winfo_reqwidth())
            target_height = root.winfo_reqheight()
            current_height = root.winfo_height()
            steps = 6
            if steps <= 0:
                root.geometry(f"{width}x{target_height}")
                return
            delta = (target_height - current_height) / steps
            for step in range(1, steps + 1):
                height = int(current_height + delta * step)
                root.after(
                    step * 15,
                    lambda h=height: root.geometry(f"{width}x{h}"),
                )
        except Exception:
            pass


class AppUI:
    def __init__(self, root: ctk.CTk, settings: dict, on_save, on_check_now):
        self.root = root
        self.on_save = on_save
        self.on_check_now = on_check_now
        self.last_update_dt: dt.datetime | None = None

        root.title(APP_NAME)
        root.geometry("520x260")
        root.minsize(460, 240)
        root.resizable(False, False)
        root.protocol("WM_DELETE_WINDOW", self.hide)
        _set_window_icon(root)
        _set_taskbar_icon(root)

        root.grid_columnconfigure(0, weight=1)
        root.grid_rowconfigure(2, weight=0)

        label_font = ctk.CTkFont(size=14, weight="bold")
        value_font = ctk.CTkFont(size=16, weight="bold")
        accent_font = ctk.CTkFont(size=28, weight="bold")
        title_font = ctk.CTkFont(size=18, weight="bold")
        small_font = ctk.CTkFont(size=13)

        status_frame = ctk.CTkFrame(root)
        status_frame.grid(row=0, column=0, padx=12, pady=(12, 6), sticky="ew")
        status_frame.grid_columnconfigure(0, weight=1)

        self.device_value = ctk.CTkLabel(
            status_frame,
            text="n/a",
            font=title_font,
            anchor="center",
            justify="center",
        )
        self.device_value.grid(row=0, column=0, sticky="ew", padx=12, pady=(14, 6))

        battery_row = ctk.CTkFrame(status_frame, fg_color="transparent")
        battery_row.grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 8))
        battery_row.grid_columnconfigure(0, minsize=48)
        battery_row.grid_columnconfigure(1, weight=1)
        battery_row.grid_columnconfigure(2, minsize=48)

        self.battery_spacer = ctk.CTkLabel(battery_row, text="", width=48)
        self.battery_spacer.grid(row=0, column=0)

        self.battery_value = ctk.CTkLabel(
            battery_row,
            text="n/a",
            font=accent_font,
            anchor="center",
            justify="center",
        )
        self.battery_value.grid(row=0, column=1, sticky="ew")
        self.battery_default_color = self.battery_value.cget("text_color")

        self.refresh_button = ctk.CTkButton(
            battery_row,
            text="⟳",
            width=48,
            height=38,
            font=ctk.CTkFont(size=20, weight="bold"),
            command=self.on_check_now,
        )
        self.refresh_button.grid(row=0, column=2, sticky="e")

        self.busy_bar = ctk.CTkProgressBar(status_frame, mode="indeterminate")
        self.busy_bar.grid(row=2, column=0, sticky="ew", padx=12, pady=(0, 12))
        self.busy_bar.grid_remove()

        settings_section = CollapsibleSection(
            root,
            title="Settings",
            default_open=False,
        )
        settings_section.grid(row=1, column=0, padx=12, pady=6, sticky="ew")
        settings_section.grid_columnconfigure(0, weight=1)
        self.settings_section = settings_section

        thresholds_frame = settings_section.body
        thresholds_frame.grid_columnconfigure(0, weight=0)
        thresholds_frame.grid_columnconfigure(1, weight=1)
        thresholds_frame.grid_columnconfigure(2, weight=0)

        ctk.CTkLabel(thresholds_frame, text="Threshold (unlocked)", font=label_font).grid(
            row=0, column=0, sticky="w", padx=(12, 8), pady=(12, 8)
        )
        self.unlocked_slider = ctk.CTkSlider(
            thresholds_frame,
            from_=0,
            to=100,
            number_of_steps=100,
            command=self._on_unlocked_slider,
        )
        self.unlocked_slider.set(settings["battery_level_alert_threshold"])
        self.unlocked_slider.grid(row=0, column=1, padx=(0, 8), pady=(12, 8), sticky="ew")
        self.unlocked_value = ctk.CTkLabel(
            thresholds_frame,
            text=f"{settings['battery_level_alert_threshold']}%",
            font=value_font,
        )
        self.unlocked_value.grid(row=0, column=2, sticky="e", padx=(0, 12), pady=(12, 8))

        ctk.CTkLabel(thresholds_frame, text="Threshold (locked)", font=label_font).grid(
            row=1, column=0, sticky="w", padx=(12, 8), pady=8
        )
        self.locked_slider = ctk.CTkSlider(
            thresholds_frame,
            from_=0,
            to=100,
            number_of_steps=100,
            command=self._on_locked_slider,
        )
        self.locked_slider.set(settings["battery_level_alert_threshold_locked"])
        self.locked_slider.grid(row=1, column=1, padx=(0, 8), pady=8, sticky="ew")
        self.locked_value = ctk.CTkLabel(
            thresholds_frame,
            text=f"{settings['battery_level_alert_threshold_locked']}%",
            font=value_font,
        )
        self.locked_value.grid(row=1, column=2, sticky="e", padx=(0, 12), pady=8)

        refresh_value = int(settings.get("refresh_interval_seconds", 5))
        refresh_value = max(5, min(refresh_value, 300))
        ctk.CTkLabel(thresholds_frame, text="Refresh interval (sec)", font=label_font).grid(
            row=2, column=0, sticky="w", padx=(12, 8), pady=8
        )
        self.refresh_slider = ctk.CTkSlider(
            thresholds_frame,
            from_=5,
            to=300,
            number_of_steps=295,
            command=self._on_refresh_slider,
        )
        self.refresh_slider.set(refresh_value)
        self.refresh_slider.grid(row=2, column=1, padx=(0, 8), pady=8, sticky="ew")
        self.refresh_value = ctk.CTkLabel(
            thresholds_frame,
            text=f"{refresh_value}s",
            font=value_font,
        )
        self.refresh_value.grid(row=2, column=2, sticky="e", padx=(0, 12), pady=8)

        ctk.CTkLabel(thresholds_frame, text="Beeps", font=label_font).grid(
            row=3, column=0, sticky="w", padx=(12, 8), pady=8
        )
        self.beep_switch = ctk.CTkSwitch(
            thresholds_frame,
            text="",
        )
        if settings.get("beep_enabled", True):
            self.beep_switch.select()
        else:
            self.beep_switch.deselect()
        self.beep_switch.grid(row=3, column=1, sticky="w", padx=(0, 8), pady=8)

        cooldown_value = int(settings.get("alert_cooldown_minutes", 10))
        cooldown_value = max(0, min(cooldown_value, 120))
        ctk.CTkLabel(thresholds_frame, text="Alert cooldown (min)", font=label_font).grid(
            row=4, column=0, sticky="w", padx=(12, 8), pady=8
        )
        self.cooldown_slider = ctk.CTkSlider(
            thresholds_frame,
            from_=0,
            to=120,
            number_of_steps=120,
            command=self._on_cooldown_slider,
        )
        self.cooldown_slider.set(cooldown_value)
        self.cooldown_slider.grid(row=4, column=1, padx=(0, 8), pady=8, sticky="ew")
        self.cooldown_value = ctk.CTkLabel(
            thresholds_frame,
            text=f"{cooldown_value}m",
            font=value_font,
        )
        self.cooldown_value.grid(row=4, column=2, sticky="e", padx=(0, 12), pady=8)

        buttons_frame = ctk.CTkFrame(thresholds_frame, fg_color="transparent")
        buttons_frame.grid(row=5, column=0, columnspan=3, pady=(6, 10))

        ctk.CTkButton(
            buttons_frame,
            text="Save settings",
            command=self.handle_save,
            width=140,
        ).grid(row=0, column=0, padx=6)

        ctk.CTkButton(
            buttons_frame,
            text="Open config file",
            command=self.open_config_file,
            width=160,
        ).grid(row=0, column=1, padx=6)

        self.message_label = ctk.CTkLabel(thresholds_frame, text="", font=small_font)
        self.message_label.grid(row=6, column=0, columnspan=3, pady=(0, 8))

        details_section = CollapsibleSection(
            root,
            title="History & more",
            default_open=False,
            on_toggle=lambda is_open: root.grid_rowconfigure(2, weight=1 if is_open else 0),
        )
        details_section.grid(row=2, column=0, padx=12, pady=(6, 12), sticky="nsew")
        details_section.grid_columnconfigure(0, weight=1)
        self.details_section = details_section

        details_body = details_section.body
        details_body.grid_columnconfigure(0, weight=1)
        details_body.grid_rowconfigure(1, weight=1)

        self.last_update_label = ctk.CTkLabel(
            details_body,
            text="Last update: n/a",
            font=small_font,
        )
        self.last_update_label.grid(row=0, column=0, padx=12, pady=(12, 4), sticky="w")

        self.log_text = ctk.CTkTextbox(details_body, height=160, font=small_font)
        self.log_text.grid(row=1, column=0, padx=12, pady=(0, 8), sticky="nsew")
        self.log_text.configure(state="disabled")

        about_frame = ctk.CTkFrame(details_body)
        about_frame.grid(row=2, column=0, padx=12, pady=(0, 12), sticky="ew")
        about_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(about_frame, text="License: MIT", font=small_font).grid(
            row=0, column=0, sticky="w", padx=12, pady=(10, 4)
        )
        ctk.CTkLabel(
            about_frame,
            text="Contributors: Elehiggle, darthsoup",
            font=small_font,
            wraplength=460,
            justify="left",
        ).grid(row=1, column=0, sticky="w", padx=12, pady=(0, 12))

        self.resize_to_fit()
        root.withdraw()

    def handle_save(self) -> None:
        try:
            unlocked = int(round(self.unlocked_slider.get()))
            locked = int(round(self.locked_slider.get()))
            refresh_interval = int(round(self.refresh_slider.get()))
            beep_enabled = bool(self.beep_switch.get())
            cooldown_minutes = int(round(self.cooldown_slider.get()))
            if not 0 <= unlocked <= 100 or not 0 <= locked <= 100:
                raise ValueError("Thresholds must be between 0 and 100")
            if not 5 <= refresh_interval <= 300:
                raise ValueError("Refresh interval must be between 5 and 300 seconds")
            if not 0 <= cooldown_minutes <= 120:
                raise ValueError("Alert cooldown must be between 0 and 120 minutes")
        except ValueError as exc:
            self.set_message(str(exc))
            return

        self.on_save(unlocked, locked, refresh_interval, beep_enabled, cooldown_minutes)
        self.set_message("Settings saved")

    def _on_unlocked_slider(self, value: float) -> None:
        self.unlocked_value.configure(text=f"{int(round(value))}%")

    def _on_locked_slider(self, value: float) -> None:
        self.locked_value.configure(text=f"{int(round(value))}%")

    def _on_refresh_slider(self, value: float) -> None:
        self.refresh_value.configure(text=f"{int(round(value))}s")

    def _on_cooldown_slider(self, value: float) -> None:
        self.cooldown_value.configure(text=f"{int(round(value))}m")

    def set_message(self, text: str) -> None:
        self.message_label.configure(text=text)

    def show(self) -> None:
        self.root.deiconify()
        self.root.after(10, self.resize_to_fit)
        self.root.lift()
        self.root.focus_force()

    def hide(self) -> None:
        self.root.withdraw()

    def update_status(
        self,
        battery: int | None,
        charging: bool | None,
        timestamp: str | None,
        cached: bool,
        device_name: str | None,
    ) -> None:
        if battery is None or charging is None or timestamp is None:
            self.device_value.configure(text="n/a")
            self.battery_value.configure(text="n/a")
            self.battery_value.configure(text_color=self.battery_default_color)
            self.last_update_dt = None
            self.refresh_relative_time()
            return

        cached_suffix = " (cached)" if cached else ""
        lightning = " ⚡" if charging else ""
        self.device_value.configure(text=device_name or "n/a")
        self.battery_value.configure(text=f"{battery}%{lightning}{cached_suffix}")
        self.battery_value.configure(text_color=battery_percent_color(battery))
        try:
            self.last_update_dt = dt.datetime.fromisoformat(timestamp)
        except ValueError:
            self.last_update_dt = None
        self.refresh_relative_time()

    def update_history(self, lines: list[str]) -> None:
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.insert("end", "\n".join(lines))
        self.log_text.configure(state="disabled")

    def set_busy(self, is_busy: bool) -> None:
        if is_busy:
            self.busy_bar.grid()
            self.busy_bar.start()
            self.refresh_button.configure(state="disabled")
            return
        self.busy_bar.stop()
        self.busy_bar.grid_remove()
        self.refresh_button.configure(state="normal")

    def refresh_relative_time(self) -> None:
        relative = format_relative_time(self.last_update_dt)
        self.last_update_label.configure(text=f"Last update: {relative}")

    def resize_to_fit(self) -> None:
        try:
            self.root.update_idletasks()
            width = max(self.root.winfo_width(), self.root.winfo_reqwidth())
            height = self.root.winfo_reqheight()
            self.root.geometry(f"{width}x{height}")
        except Exception:
            pass

    def open_config_file(self) -> None:
        try:
            with _SETTINGS_LOCK:
                settings = dict(_SETTINGS)
            settings_path = get_settings_path(prefer_existing=False)
            if not os.path.exists(settings_path):
                save_settings(settings)
            os.startfile(settings_path)
        except OSError as exc:
            self.set_message(f"Open config failed: {exc}")


def process_ui_queue(root: ctk.CTk, ui: AppUI) -> None:
    while True:
        try:
            event, payload = _UI_QUEUE.get_nowait()
        except queue.Empty:
            break

        if event == "status":
            battery, charging, timestamp, cached, device_name = payload
            ui.update_status(battery, charging, timestamp, cached, device_name)
        elif event == "history":
            ui.update_history(get_history())
        elif event == "busy":
            ui.set_busy(bool(payload))
        elif event == "toast":
            text_fields, beep = payload
            show_toast(text_fields, bool(beep))

    ui.refresh_relative_time()
    root.after(500, lambda: process_ui_queue(root, ui))


def run_tray_icon(icon: pystray.Icon) -> None:
    icon.run()


def main() -> None:
    global _SETTINGS

    parser = argparse.ArgumentParser(
        description="Pulsar battery notifier",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Send a one-off toast with current battery and charging status.",
    )
    args = parser.parse_args()

    _SETTINGS = load_settings()

    _set_app_user_model_id(TOAST_APP_NAME)

    if args.once:
        status, _, _, _ = read_battery_status()
        if status is None:
            logger.error("Battery status not available")
            return
        battery_percentage, is_charging = status
        send_status_toast(battery_percentage, is_charging)
        return

    stop_event = threading.Event()
    check_now_event = threading.Event()

    root = ctk.CTk()
    ui = AppUI(
        root,
        _SETTINGS,
        on_save=update_settings_with_beep,
        on_check_now=check_now_event.set,
    )

    def on_open(_icon=None, _item=None):
        root.after(0, ui.show)

    def on_exit(_icon=None, _item=None):
        stop_event.set()
        icon.stop()
        root.after(0, root.destroy)

    global _TOAST_OPEN_HANDLER
    _TOAST_OPEN_HANDLER = lambda: root.after(0, ui.show)

    menu = pystray.Menu(
        pystray.MenuItem("Open", on_open, default=True),
        pystray.MenuItem("Exit", on_exit),
    )
    icon = pystray.Icon(
        "SimplePulsarBatteryNotification",
        create_tray_image(),
        APP_NAME,
        menu=menu,
    )

    tray_thread = threading.Thread(target=run_tray_icon, args=(icon,), daemon=True)
    tray_thread.start()

    monitor_thread = threading.Thread(
        target=monitor_loop,
        args=(stop_event, check_now_event),
        daemon=True,
    )
    monitor_thread.start()

    process_ui_queue(root, ui)
    root.mainloop()


if __name__ == "__main__":
    main()
