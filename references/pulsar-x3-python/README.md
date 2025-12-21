# Pulsar X3 Linux Control

Control your Pulsar X3 gaming mouse on Linux without needing the Windows Pulsar Fusion app. Works with both wired and wireless modes.

> **Disclaimer**: This is an unofficial, community-developed tool. It is not affiliated with, endorsed by, or supported by Pulsar Gaming Gears. Use at your own risk.

## Features

| Feature | Read | Write | Notes |
|---------|------|-------|-------|
| Firmware Version | ✅ | - | Mouse and dongle versions |
| DPI | ✅ | ✅ | 50-26000 DPI |
| DPI Stage | ✅ | ✅ | Switch between stages 1-6 |
| Battery | ✅ | - | Real-time percentage |
| Motion Sync | ✅ | ✅ | On/Off |
| Lift-off Distance | ✅ | ✅ | 0.7mm, 1mm, 2mm |
| Angle Snapping | ✅ | ✅ | On/Off |
| Ripple Control | ✅ | ✅ | On/Off |
| Debounce | ✅ | ✅ | Time in ms |
| Polling Rate | ⚠️ | ❌ | Read unreliable, write not working |

## Requirements

- Python 3.6+
- PyUSB library
- GTK4 and Libadwaita (for GUI)

## Installation

### Arch Linux (AUR)

```bash
yay -S pulsar-x3-python
```

### Manual Installation

```bash
# Install PyUSB
pip install pyusb

# Setup udev rules for non-root access
sudo tee /etc/udev/rules.d/99-pulsar-mouse.rules << 'EOF'
SUBSYSTEM=="usb", ATTRS{idVendor}=="3710", ATTRS{idProduct}=="3410", MODE="0666"
SUBSYSTEM=="usb", ATTRS{idVendor}=="3710", ATTRS{idProduct}=="5403", MODE="0666"
EOF

sudo udevadm control --reload-rules
sudo udevadm trigger

# Reconnect mouse after adding rules
```

## Usage

### GUI

```bash
pulsar-x3-gui
```

The GUI provides a graphical interface for all mouse settings with real-time feedback.

### CLI

```bash
# Show all info
pulsar-x3 --info

# Set DPI directly
pulsar-x3 --dpi 800

# Switch DPI stage (like pressing the button on mouse)
pulsar-x3 --stage 2

# Check battery
pulsar-x3 --battery

# Motion sync
pulsar-x3 --motion-sync on
pulsar-x3 --motion-sync off

# Lift-off distance
pulsar-x3 --lod 0.7
pulsar-x3 --lod 1
pulsar-x3 --lod 2

# Angle snapping
pulsar-x3 --angle-snap on
pulsar-x3 --angle-snap off

# Ripple control
pulsar-x3 --ripple-control on
pulsar-x3 --ripple-control off

# Debounce time
pulsar-x3 --debounce 3
```

## Example Output

```
$ pulsar-x3 --info
✓ Found: Pulsar X3 (wireless mode)
======================================================================
Pulsar X3 Mouse Information
======================================================================

Dongle Firmware: 0123
Mouse Firmware: 00.00.10.16

DPI: 1600 (stage 3)
Motion Sync: OFF
Lift-off Distance: 1mm
Angle Snapping: OFF
Ripple Control: OFF
Debounce: 3ms
Battery: 80%
Polling Rate: 1000Hz (unreliable)
======================================================================
```

## Device Information

- **Vendor ID**: `0x3710` (Pulsar)
- **Product ID (Wired)**: `0x3410`
- **Product ID (Wireless)**: `0x5403`
- **Interface**: 3 (HID Feature Reports)

## Troubleshooting

### Permission denied
Make sure udev rules are installed and you've reconnected the mouse.

### Device not found
```bash
lsusb | grep 3710
```

### Polling rate
Polling rate read/write is not working correctly. Use the Windows Pulsar Fusion app to change polling rate.

### Settings reset after opening Windows Pulsar Fusion
It appears the Pulsar Fusion app syncs its saved data to the mouse on launch, overwriting any changes made on Linux.
