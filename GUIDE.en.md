# Guide

A step-by-step walkthrough of the Laufbursche NAVEE Tool. The page talks to your NAVEE scooter over Web Bluetooth, entirely on your device. Nothing is sent to any server.

## What you need

- A NAVEE scooter (the kick-scooter line, for example the XT5). Turn it on and keep it within a few meters.
- A browser with Web Bluetooth: **Chrome** or **Edge** on Android or desktop, or **Bluefy** on iPhone/iPad. Safari and Firefox do not support Web Bluetooth.
- Bluetooth switched on. On Android, location permission has to be granted to the browser for a Bluetooth scan.

## Which devices it works with

**Unlocking works only with these models:** NAVEE XT5 Ultra, XT5 Pro/Max, UT5 Ultra X and E45/E60 Pro. On every other model (for example the NT5) the cap sits firmly in the firmware - there it needs a firmware patch flashed to the scooter.

Otherwise the tool speaks the standard NAVEE scooter protocol, the same one the official app uses for the whole scooter line. The authentication keys are shared across these scooters, so the tool talks to any of them (not only the XT5) and shows status, the switches and the immobilizer there too. Only the speed lever stays limited to the models listed above. NAVEE e-bikes and the Exo line use different Bluetooth protocols and are **not** covered.

## One time: find your NAVEE account userId

Your scooter is bound to a NAVEE account. To connect, the tool needs the **numeric account userId** of that account. A bound scooter rejects any other id with **error 255**, before it even answers.

Important:

- This is **not** the Navee ID from the account screen (that one is alphanumeric and often 13 digits). What is needed is a plain number of **at most 10 digits**.
- The app never shows this number, you read it once. After that the tool remembers it in the browser, so you only ever do this a single time.
- The number **never changes**. Only a different NAVEE account has a different number.

You are looking for the field userId, a plain number, in the response of the login call.

### iPhone (easiest, no computer at all)

The NAVEE app has no cert pinning and iOS trusts a self-installed certificate.

1. Install an on-device HTTPS capture app from the App Store, for example Http Catcher or Stream.
2. Install its certificate profile under Settings -> General -> VPN & Device Management, then set it to full trust under Settings -> General -> About -> Certificate Trust Settings.
3. Start the capture, then open the NAVEE app and log in (if needed, log out and log back in once).
4. Open the call to lj.naveetech.com named login and read the field userId in its response.
5. Enter the number in the tool at the top in the NAVEE account userId field. Tip: you can also paste the whole copied response text here, the tool extracts the userId automatically.

### Android

**Easiest: upload the Bluetooth log (no PC, no Wireshark).** The page reads your Android device's Bluetooth log and pulls the userId out itself. Nothing is uploaded, everything stays local on your device.

1. Open Developer options (Settings -> About phone -> tap the build number 7 times).
2. Turn on the **Bluetooth HCI snoop log** in Developer options.
3. Switch Bluetooth off and on once so logging starts.
4. Connect to the scooter once with the real NAVEE app, wait a moment.
5. Create a bug report: Developer options -> **Take bug report** -> Interactive report. Android packs the log file into a ZIP you can save or share.
6. On the page expand the section **"Android: use an auth frame / btsnoop_hci.log instead of the userId"** and drop the bug-report ZIP (or the `btsnoop_hci.log` directly, if your file manager can see it) into the upload field.
7. Done - the page recognizes the login and Connect is ready. The userId stays local in your browser's local storage, so you only do this once.

**Alternative: read the plain number with a PC (HTTP Toolkit).** If you prefer the number itself and have a PC: install the free HTTP Toolkit, choose "Android device via ADB", let it set up the proxy and certificate, log in to the NAVEE app, filter for `lj.naveetech.com`, open the login POST and read the `userId` field in the response. Enter that number in the userId field above.

## Step by step

1. **Open the page** in a supported browser.
2. **Enter userId and connect.** Enter your numeric account userId at the top (see the section above), then *Connect* becomes available. Press *Connect* and pick your scooter from the chooser. It appears by name (NAVEE...), exactly as in the official app. If it is not listed, tick *Show all Bluetooth devices* and look for it there. The tool authenticates automatically right after connecting.
3. **Values appear automatically.** Right after connecting the tool reads the status and shows the region, SKU, max speed, limit, the serial number and the telemetry. The raw frames are also written to the log as hex.
4. **Functions (immobilizer, cruise control, zero-start).** The page detects your model from the serial and, in the *Functions* card, shows only what this model's firmware can set:
   - **Immobilizer** (0x51) - on every model.
   - **Cruise control** (0x52) - where the firmware supports it.
   - **Zero-start** levels 0 to 5 (0x6A) - where supported; level 0 is the true zero-start.
   The manufacturer app hides cruise control on EU units and offers zero-start only in the USA version - here both work where the model supports them. An unrecognized model shows cruise and zero-start as *unverified*; sending does no harm, a model without the function ignores the command.
5. **Unlock the speed (four families only).** The speed card appears only for the models with a proven flash-free gear lever: XT5 Ultra/Pro/Max, UT5 Ultra X and E45/E60 Pro. *Unlock speed* sends the gear-4 command (BLE 0x58 = 4); the meter commands the firmware-possible top speed and the firmware clamps it to the unit SKU and region. The note in the card gives the per-model range (XT5 Ultra 40.5 to 50.8 depending on SKU; UT5 Ultra X up to 60; E45/E60 Pro up to about 32.5). *Reset* restores the normal mode (gear 3). There is no input field because the value is not freely settable.
   - Behaviour on the device: the display stays in D and the boost button does nothing. Switching to mode S or a reboot cancels the trick, so resend each ride.
   - On every other model the speed card does not appear at all, because no flash-free path exists: the cap sits in the flash/SKU firmware or the controller is torque-controlled with no speed setpoint.
6. **Read status again** to confirm what the scooter now reports.

## How far does it go

The flash-free gear lever was verified across the whole firmware chain (meter and controller read line by line, each finding adversarially checked). It works on four families only, and the achieved value depends on the SKU and region of the actual unit:

- **XT5 Ultra**: 40.5 to 50.8 km/h depending on the SKU byte. The 50.8 is code-proven but not confirmed by a measured ride.
- **XT5 Pro/Max**: about 50 km/h (SKU 8 up to ~65), depending on the internal gear mapping.
- **UT5 Ultra X**: up to 60 km/h on an unrestricted SKU. The 70 the app offers is not proven.
- **E45/E60 Pro**: up to about 32.5 km/h on a permissive region, otherwise limited.

On every other model no flash-free path exists: the real cap sits in the flash/SKU firmware, or the controller is torque-controlled with no km/h setpoint. The app's own max-speed function (command 0x6E) was also checked and refuted as flash-ineffective, so the page offers no free setting - it would otherwise promise a number the firmware does not hold.

## Is it permanent

No, and that is the upside: the gear lever changes one RAM byte, not flash. Switching to mode S or a reboot restores the normal state, so press *Unlock speed* again each ride. No brick risk, no flashing.

## Troubleshooting

- **The scooter is not in the chooser.** Make sure it is on and close, Bluetooth is on, and on Android the browser has location permission. Then tick *Show all Bluetooth devices*.
- **Error 255 in the log.** The scooter rejects the account id. Most likely the alphanumeric Navee ID was entered instead of the numeric userId. See the section *One time: find your NAVEE account userId*.
- **Connects but no values.** Check the log for RX frames. If authentication failed (error 255), the log says so.
- **Unlock does not add speed.** Then it is not an XT5 Ultra/Pro/Max. On other models the controller re-clamps the gear-4 command to its region limit, so the trick has no effect there.

## Privacy and legal

Everything runs locally over Bluetooth. See [Privacy](PRIVACY.md). Raising the speed removes the throttle limit, so the road approval lapses and public-road use is not allowed. Use only on your own vehicle on private ground. See the [Disclaimer](#) in the footer.
