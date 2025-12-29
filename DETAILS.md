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

Environment variables:

| Parameter                              | Description                                                        |
|----------------------------------------|--------------------------------------------------------------------|
| `BATTERY_LEVEL_ALERT_THRESHOLD`        | Battery % threshold when unlocked (default: `5`)                   |
| `BATTERY_LEVEL_ALERT_THRESHOLD_LOCKED` | Battery % threshold shortly after locking (default: `30`)          |
| `LOG_LEVEL_ROOT`                       | Root logging level (default: `INFO`)                                |
| `LOG_LEVEL`                            | App logging level (default: `INFO`)                                 |

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

- **USBPcap** (driver + `USBPcapCMD.exe`) to capture USB traffic on Windows.
- **Wireshark / tshark** to inspect the capture. We used:
  - `tshark` to locate `SET_REPORT` control transfers (`URB_FUNCTION_CLASS_INTERFACE`)
    with report ID `0x08` and to find the `HID Data` responses containing the
    battery value.
  - `usb.data_fragment` for outbound `SET_REPORT` payloads.
  - `usbhid.data` for inbound interrupt report payloads.
- **hidapi** (Python) to replay the captured reports and verify the battery
  byte position in live responses.

Key findings:

- **Outbound cmd04** is a HID class `SET_REPORT`:
  `0804000000000000000000000000000049`
- **Inbound cmd04 response** on the X2 V1 + dongle in this workspace uses report ID `0x09`:
  `0904000000025a...` where byte 6 (`0x5a`) is the battery percent (90% in
  the capture).
- **Charging flag** lives at byte 7: `0x00` when idle, `0x01` when charging
  (confirmed by comparing wireless idle vs. wireless charging captures).
- The battery response lives on a vendor usage page collection (varies by device/firmware), endpoint `0x82`.

## Warmup / initialization observations (X2 V1 + dongle)

In `logs/usbcap_wireless.pcap`, the official software sends additional commands
around the first successful cmd04 response:

- `0803...4a` (cmd03) with an interrupt-IN response `0903...`
- `080e...3f` (cmd0e) with an interrupt-IN response `090e...`
- A cmd01 packet `0801000000083c31275b...55` whose middle bytes vary.
  The structure appears to be:

  - Prefix: `080100000008`
  - 4-byte session/nonce value
  - 6 bytes of `00`
  - 1-byte check byte such that `(sum(packet_bytes) & 0xFF) == 0x55`

  This means cmd01 can be generated dynamically (pick any 4-byte nonce and set
  the last byte to make the sum equal `0x55`).

The logger therefore sends a generated cmd01 before the minimal warmup and then
retries cmd04.

How we matched the right device:

- Used `hid.enumerate()` and `--list-devices` to list HID interfaces.
- For the Pulsar X2 V1 hardware tested in this workspace:
  - VID `0x25a7`
  - PID `0xfa7c` (wireless)
  - PID `0xfa7b` (wired)
  - Multiple vendor usage pages exist on interface 1 (`0xff01`..`0xff04`, etc.).
  - The cmd04 traffic was observed on a vendor usage page interface; the logger can probe all vendor pages by default.

Live confirmation on this machine (Fusion closed):

- cmd04 writes succeeded on usage page `0xff02`
- cmd04 interrupt-IN responses (report ID `0x09`) arrived on usage page `0xff01`

## Capture results (X2 V1 wireless, 0x25a7:0xfa7c)

Using `logs/usbcap_wireless.pcap`:

- **Outbound cmd04** payload observed:
  `0804000000000000000000000000000049`
- **Inbound cmd04 response** observed on interrupt IN endpoint `0x82`:
  `0904000000025a00...`
  - Response report ID is `0x09` (not `0x08`)
  - Battery percent is still at byte 6 (`0x5a` = 90%)
  - Charging flag is still at byte 7 (`0x00` idle, `0x01` charging)

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

- Wireless dongle ID: `0x3710:0x5406`
- Wired ID: `0x3710:0x3414`
- If `--once` prints "Battery read failed", run with `--list-devices` and
  try `--index` or `--interface` to target the vendor HID interface
  (usage page `0xff02`).
- When the mouse is plugged in, the dongle can stop returning cmd04 responses
  because the mouse switches to the wired interface. In that state, `--mode wireless`
  may fail while `--mode wired` succeeds.
- While charging over USB, the reported percent can move quickly (voltage-based),
  so wired readings may differ from the last wireless reading.
- The logger treats the presence of the wired PID (`0x3414`) as charging and
  will output `charging=yes` even if the cmd04 flag says otherwise.
- If you see "Unable to load the HID backend", uninstall the pure-python
  `hid` package and reinstall:

```powershell
pip uninstall hid
pip install hidapi
```

## Logs

The CSV log format is:

```
timestamp,battery_percent
2025-12-20T05:12:34,39
```
