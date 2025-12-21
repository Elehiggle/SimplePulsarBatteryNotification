import ctypes
import logging
import os
import sys
import time
import winsound

from windows_toasts import Toast, WindowsToaster

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


def get_foreground_window():
    return ctypes.windll.user32.GetForegroundWindow()


def send_alert(battery_level):
    toast = Toast()
    toast.text_fields = [f"Battery: {battery_level}%"]
    max_retries = 5
    retries = 0

    while retries < max_retries:
        try:
            WindowsToaster("Pulsar X2 Battery").show_toast(toast)
            winsound.Beep(200, 200)
            winsound.Beep(200, 200)
            winsound.Beep(200, 200)
            break
        except ImportError:
            retries += 1
            if retries >= max_retries:
                error_message = (
                    "An error occurred loading required modules.\n\n"
                    "The application will now be restarted to resolve this issue."
                )
                ctypes.windll.user32.MessageBoxW(None, error_message, "Error", 0)
                exe_path = sys.executable
                os.execv(exe_path, [exe_path] + sys.argv)
            time.sleep(1)


def read_battery_status():
    devices = battery_logger.list_candidate_devices("auto", None)
    if not devices:
        return None

    for info in devices:
        dev = None
        try:
            dev = battery_logger.open_device(info)
            status = battery_logger.read_battery_cmd04(dev, False)
            if status is None:
                continue
            battery, charging = status
            if battery_logger.has_wired_device() and not charging:
                charging = True
            return battery, charging
        except (OSError, ValueError) as exc:
            logger.debug("battery read failed err=%s", exc)
        finally:
            if dev is not None:
                try:
                    dev.close()
                except OSError:
                    pass

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
    last_time_windows_was_unlocked = 0
    last_check = 0

    while True:
        is_pc_locked = get_foreground_window() == 0
        time.sleep(2)
        is_pc_locked = is_pc_locked and get_foreground_window() == 0

        if is_pc_locked:
            if time.time() - last_time_windows_was_unlocked < 10:
                logger.debug("PC is locked, time to check")
                check_battery_is_low(battery_level_alert_threshold_locked)
        else:
            last_time_windows_was_unlocked = time.time()
            if time.time() - last_check > 60 * 20:
                last_check = time.time()
                last_time_windows_was_unlocked = time.time()
                check_battery_is_low(battery_level_alert_threshold)

        time.sleep(5)


if __name__ == "__main__":
    main()
