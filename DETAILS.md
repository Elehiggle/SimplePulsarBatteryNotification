# Pulsar X2 Battery Logger (Windows)

This document contains the technical details for the Pulsar X2 battery logger
and the notification tool (`main.py`). The primary user-facing entrypoint is
`main.py`, which uses `pulsar_x2_battery_logger.py` under the hood. For the
short usage guide, see `README.md`.

## Requirements

- Python 3.8+
- `hidapi` (installs the `hid` module on Windows)
- `Windows-Toasts` (for notifications)

Install the dependencies:

```powershell
pip install -r requirements.txt
```

## Usage

Log once to confirm the value:

```powershell
python .\pulsar_x2_battery_logger.py --once
```

Log every 60 seconds to `battery_log.csv`:

```powershell
python .\pulsar_x2_battery_logger.py
```

## Notifications

`main.py` runs in the background and shows a Windows toast + beep when the
battery is low and **not charging**. It checks every 20 minutes while the
PC is unlocked and uses a higher threshold shortly after the PC is locked.
If the dongle stops responding (mouse idle/sleep), the notifier reuses the
last successful reading for up to 10 minutes.

Environment variables:

| Parameter                              | Description                                               |
| -------------------------------------- | --------------------------------------------------------- |
| `BATTERY_LEVEL_ALERT_THRESHOLD`        | Battery % threshold when unlocked (default: `5`)          |
| `BATTERY_LEVEL_ALERT_THRESHOLD_LOCKED` | Battery % threshold shortly after locking (default: `30`) |
| `LOG_LEVEL_ROOT`                       | Root logging level (default: `INFO`)                      |
| `LOG_LEVEL`                            | App logging level (default: `INFO`)                       |

Run the notifier:

```powershell
python .\main.py
```

For an auto-start setup, place a shortcut to `main.py` in your Startup folder.

List HID devices to find the right interface or index:

```powershell
python .\pulsar_x2_battery_logger.py --list-devices
python .\pulsar_x2_battery_logger.py --index 0 --once
```

Force wireless or wired IDs:

```powershell
python .\pulsar_x2_battery_logger.py --mode wireless
python .\pulsar_x2_battery_logger.py --mode wired
```

## Device backends

The logger is split into per-device modules under `pulsar_devices`:

- `pulsar_devices\x2cl.py` for the X2 Crazylight dongle (VID `0x3710`)
- `pulsar_devices\x2v1.py` for the X2 V1 dongle (VID `0x25a7`)

By default `pulsar_x2_battery_logger.py` auto-detects which backend to use.
To force one:

```powershell
python .\pulsar_x2_battery_logger.py --backend x2cl --once
python .\pulsar_x2_battery_logger.py --backend x2v1 --once
```

If X2 V1 does not respond to output reports, try:

```powershell
python .\pulsar_x2_battery_logger.py --backend x2v1 --transport feature --once
```

## Notes on cmd04 and warmup

The logger sends cmd04 directly. In recent re-tests on this machine, cmd04
responded immediately without any warmup sequence. Earlier in development we
observed cases where cmd04 did not respond until after the vendor interface
had been exercised (for example, after the official software communicated).
If you ever see intermittent cmd04 failures, you can capture USB traffic and
compare whether a warmup sequence is present.

## Debugging and protocol discovery

We derived the cmd04 battery read by capturing USB traffic from the official
Pulsar software and inspecting USB HID transactions.

Tools and workflow:

- **USBPcap** (driver + `USBPcapCMD.exe`) to capture USB traffic on Windows. (e.g. & "C:\Program Files\USBPcap\USBPcapCMD.exe" -d \\.\USBPcap1 -o logs\capture.pcap -A --inject-descriptors - but check the correct USBPcap device number, one could do that by running USBPcapCMD.exe without arguments, then you'll see a device list, and to keep captured files small, its recommended to directly plug the mouse/dongle into the PC, no hub in between)
- **Wireshark / tshark** to inspect the capture. We used:
  - `tshark` to locate `SET_REPORT` control transfers (`URB_FUNCTION_CLASS_INTERFACE`)
    with report ID `0x08` and to find the `HID Data` responses containing the
    battery value.
  - `usb.data_fragment` for outbound `SET_REPORT` payloads.
  - `usbhid.data` for inbound interrupt report payloads.
- **hidapi** (Python) to replay the captured reports and verify the battery
  byte position in live responses.

Key findings:

- **Outbound cmd04** is a HID class `SET_REPORT` to interface 1:
  `0804000000000000000000000000000049`
- **Inbound cmd04 response** is an interrupt IN report:
  `08040000000223...` where byte 6 (`0x23`) is the battery percent (35% in
  the capture).
- **Charging flag** lives at byte 7: `0x00` when idle, `0x01` when charging
  (confirmed by comparing wireless idle vs. wireless charging captures).
- The battery response lives on the vendor usage page `0xff02`, endpoint `0x82`.

How we matched the right device:

- Used `hid.enumerate()` and `--list-devices` to list HID interfaces for
  VID `0x3710` and PID `0x5406` (wireless) / `0x3414` (wired).
- The correct interface was the vendor usage page `0xff02` on interface 1
  (the same interface used by the `SET_REPORT` cmd04 traffic in the capture).

## X2 V1 fork findings

The `feature/x2v1` fork (https://github.com/darthsoup/SimplePulsarBatteryNotification)
adds support for the older X2 V1 dongle and documents these observations:

- X2 V1 uses VID `0x25a7` with PIDs `0xfa7c` (wireless) and `0xfa7b` (wired).
- cmd04 responses can arrive as report ID `0x09` (not `0x08`).
- Battery percent and charging flag stay at byte 6 and byte 7.
- The response may show up on a different vendor usage page than the writer
  handle (writes on `0xff02`, reads on `0xff01`), so separate reader/writer
  handles can be required.
- A minimal warmup sequence was observed around the first cmd04 response:
  cmd01 (with checksum sum==0x55), cmd03, and cmd0e. The fork generates cmd01
  dynamically and retries cmd04 after this warmup.
- Some dongles prefer `send_feature_report` instead of `write`, so the fork
  exposes a transport setting.

## Differences vs. the Pulsar X3 reference project

The reference X3 project uses a different protocol and transport:

- **Device IDs**: X3 uses `0x3710:0x3410` (wired) / `0x3710:0x5403` (wireless),
  while X2 uses `0x3710:0x3414` / `0x3710:0x5406`.
- **Transport**: X3 uses libusb control transfers on Linux; this X2 logger
  uses hidapi on Windows.
- **Command**: X3 sends `08 81 01` and reads the response from the same
  control transfer (feature report, report ID `0x00`).
- **X2 cmd04**: X2 sends output report `0x08` with command `0x04` and reads
  the response on the interrupt IN endpoint (report `0x08`, battery at byte 6).

## Notes

- X2 Crazylight IDs: wireless `0x3710:0x5406`, wired `0x3710:0x3414`
- X2 V1 IDs: wireless `0x25a7:0xfa7c`, wired `0x25a7:0xfa7b`
- If `--once` prints "Battery read failed", run with `--list-devices` and
  try `--index` or `--interface` to target the vendor HID interface
  (usage page `0xff02`).
- When the mouse is plugged in, the dongle can stop returning cmd04 responses
  because the mouse switches to the wired interface. In that state, `--mode wireless`
  may fail while `--mode wired` succeeds.
- While charging over USB, the reported percent can move quickly (voltage-based),
  so wired readings may differ from the last wireless reading.
- On X2 V1, cmd04 responses may arrive on report ID `0x09` and a different vendor
  usage page than the writer handle, so the logger pairs separate reader/writer
  handles during auto-detection.

## Logs

The CSV log format is:

```
timestamp,battery_percent
2025-12-20T05:12:34,39
```
