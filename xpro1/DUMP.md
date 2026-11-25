# Reading X-Pro 1 RAM over USB (read-only, no flashing)

A live RAM dump is the most useful input for analysis: it captures every code
region at its true runtime address, including the resident boot/kernel ROM that
the firmware update file does not contain. It is read-only and carries no brick
risk as long as you use only the read commands below. Jig mode is left by simply
power-cycling the camera.

This uses this repo's `ff80` jig-mode tool (`fffw/ff80`), which needs `libusb`
and the `usb1` (python-libusb1) Python binding.

## Enter jig mode

1. Power the camera OFF.
2. Connect USB.
3. Power ON while holding the **Shutter + Up** buttons.
4. Confirm the device enumerated:
   - Linux: `lsusb -d 04cb:ff80` -> `04cb:ff80 Fuji Photo Film Co., Ltd`
   - macOS: `system_profiler SPUSBDataType | grep -i -A3 fuji`

## Dump (read-only)

```sh
python3 ff80 info
python3 ff80 ram dump 0 -s 0x2000000 -o xpro1_ram_0-32M.bin
# bootrom is model-specific and not defined for the X-Pro 1 ("not supported");
# the ram dump from 0 already covers the low resident code.
```

## Setup notes

- **Linux:** `apt install libusb-1.0-0`, `pip3 install usb1`. Optionally install
  `ff80/60-fujig.rules` into `/etc/udev/rules.d/` to run without `sudo`.
- **macOS (Intel or Apple Silicon), no Homebrew needed if the Command Line Tools
  are present:** build libusb from source
  (`./configure && make && sudo make install`, which lands in `/usr/local/lib`),
  then `python3 -m pip install --user usb1`. The `usb1` package searches its own
  package directory for `libusb-1.0.dylib`, so the reliable fix is to copy the
  built library there:
  ```sh
  cp /usr/local/lib/libusb-1.0.0.dylib \
     "$(python3 -c 'import usb1,os;print(os.path.dirname(usb1.__file__))')/libusb-1.0.dylib"
  ```
  Old Intel macOS tends to allow the raw USB access this needs; newer/locked-down
  setups may block it, in which case use Linux.

## Safety

Read-only (OK): `info`, `ram dump`, `ram read`, `syslog`.
Never run (these write to the camera and can brick it): `ram write`,
`cfgdata write` / `cfgdata save`, `rtc write`.
A RAM dump is personal data (it contains your camera's serial and live state):
keep it local, never commit or upload it.
