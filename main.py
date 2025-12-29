import argparse
import ctypes
import logging
import os
import sys
import time
import winsound

from windows_toasts import Toast, ToastDisplayImage, ToastImage, ToastImagePosition

import pulsar_x2_battery_logger as battery_logger

log_level_root = os.getenv("LOG_LEVEL_ROOT", "INFO").upper()
logging.basicConfig(level=log_level_root)

log_level = os.getenv("LOG_LEVEL", "INFO").upper()
logger = logging.getLogger(__name__)
logger.setLevel(log_level)

battery_level_alert_threshold = int(os.getenv("BATTERY_LEVEL_ALERT_THRESHOLD", "5"))
battery_level_alert_threshold_locked = int(
    os.getenv("BATTERY_LEVEL_ALERT_THRESHOLD_LOCKED", "30")
)
BATTERY_STATUS_CACHE_TTL = 60 * 10

_LAST_BATTERY_STATUS: tuple[float, tuple[int, bool]] | None = None


def get_foreground_window():
    return ctypes.windll.user32.GetForegroundWindow()


def _resource_path(filename: str) -> str:
    base = getattr(sys, "_MEIPASS", None)
    if base:
        return os.path.join(base, filename)
    return os.path.join(os.path.dirname(__file__), filename)


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
    _add_toast_icon(toast)
    max_retries = 5
    retries = 0

    while retries < max_retries:
        try:
            WindowsToaster("Pulsar X2 Battery").show_toast(toast)
            # If successful, break out of the loop and beep as normal
            if beep:
                winsound.Beep(200, 200)
                winsound.Beep(200, 200)
                winsound.Beep(200, 200)
            break
        except ImportError:
            # This exception can occur extremely rarely
            retries += 1
            if retries >= max_retries:
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
            # If not reached max retries, sleep and try again
            time.sleep(1)


def send_alert(battery_level):
    show_toast([f"Battery: {battery_level}%"], beep=True)


def send_status_toast(battery_level: int, is_charging: bool) -> None:
    charging_text = "yes" if is_charging else "no"
    show_toast(
        [
            f"Battery: {battery_level}%",
            f"Charging: {charging_text}",
        ],
        beep=False,
    )


def read_battery_status():
    global _LAST_BATTERY_STATUS

    status = battery_logger.read_battery_status()
    if status is not None:
        _LAST_BATTERY_STATUS = (time.monotonic(), status)
        return status

    if _LAST_BATTERY_STATUS is None:
        return None

    cached_at, cached_status = _LAST_BATTERY_STATUS
    if time.monotonic() - cached_at <= BATTERY_STATUS_CACHE_TTL:
        logger.debug("using cached battery status")
        return cached_status

    return None


def check_battery_is_low(battery_alert_threshold):
    status = read_battery_status()
    if status is None:
        logger.error("Battery status not available")
        return

    battery_percentage, is_charging = status
    if not is_charging:
        logger.debug(
            "Battery: NotCharging %d%%, threshold: %d",
            battery_percentage,
            battery_alert_threshold,
        )
        if battery_percentage < battery_alert_threshold:
            logger.info("Warning: Battery level is below threshold and not charging!")
            send_alert(battery_percentage)
        else:
            logger.info("Battery is not charging, but the battery level is sufficient")
    else:
        logger.info("Battery state is charging or above the threshold")


def main():
    parser = argparse.ArgumentParser(
        description="Pulsar battery notifier",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Send a one-off toast with current battery and charging status.",
    )
    args = parser.parse_args()

    if args.once:
        status = read_battery_status()
        if status is None:
            logger.error("Battery status not available")
            return
        battery_percentage, is_charging = status
        send_status_toast(battery_percentage, is_charging)
        return

    last_time_windows_was_unlocked = 0
    last_check = 0

    while True:
        is_pc_locked = get_foreground_window() == 0
        time.sleep(2)  # Sleep for 2 seconds
        is_pc_locked = is_pc_locked and get_foreground_window() == 0  # Recheck, as this method is not perfect

        if is_pc_locked:
            if time.time() - last_time_windows_was_unlocked < 10:  # Check if we just locked windows within last 10 seconds
                logger.debug("PC is locked, time to check")
                check_battery_is_low(battery_level_alert_threshold_locked)
        else:
            last_time_windows_was_unlocked = time.time()
            if time.time() - last_check > 60 * 20:  # Check every 20 minutes
                last_check = time.time()
                last_time_windows_was_unlocked = time.time()
                check_battery_is_low(battery_level_alert_threshold)

        time.sleep(5)


if __name__ == "__main__":
    main()
