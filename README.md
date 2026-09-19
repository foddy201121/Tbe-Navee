# Tbe Navee

A static web page that talks to NAVEE scooters over Web Bluetooth. Connect to your scooter, it authenticates itself, reads the status, detects your model from the serial and shows the drive functions that model's firmware supports: immobilizer, cruise control and zero-start. On four families it also lifts the top speed with a flash-free gear lever (no firmware flashing). Nothing to install: no app store, no signing, no developer account. It runs in **Bluefy** on iOS and in **Chrome** on Android or desktop. The page is bilingual (German/English, switch in the header).

> **This is a feasibility study.** It exists to show what NAVEE's Bluetooth protocol makes possible, not to be a finished product. The protocol was reconstructed from the official app (com.navee.ucaret 2.1.6) and is documented byte for byte. Error-free operation is not promised and there is no warranty of any kind. Whatever you do with it, you do at your own risk.

**Open the web app: [laufbursche42.github.io/nv-unlock](https://laufbursche42.github.io/nv-unlock/)**

**On Android?** There is a native Android app that does the same over Bluetooth, without a browser: **[nv-lb-edition](https://github.com/Laufbursche42/nv-lb-edition)**. It sidesteps the Web Bluetooth quirks - some phones, for example Samsung with Auto Blocker on, block the browser connection. This web page is the way in on iOS.

Or run it yourself, no build step, no dependencies: clone the repo and serve the folder over a local HTTP server. Opening `index.html` directly as a `file://` URL will not work, the page fetches its own documents and browsers block that over `file://`.

```
git clone https://github.com/Laufbursche42/nv-unlock.git
cd nv-unlock
python -m http.server 8000
```

Any static server works. With Node installed, this does the same job:

```
npx serve .
```

Then open the printed address in a browser that supports Web Bluetooth.

**Guide: [Deutsch](GUIDE.de.md) | [English](GUIDE.en.md)** covers everything step by step, from the first connect to setting the speed.

## Which devices it works with

The page speaks the standard NAVEE scooter protocol, the one the official app uses for the whole kick-scooter line (GATT service `0000d0ff-...`, `55 AA` frames). The connection matches the scooter by its advertised name (NAVEE...), exactly like the official app, and the five authentication keys are shared across these scooters, so the tool talks to any of them, not only the XT5 (pids 2416/2443/2529).

Not covered: NAVEE e-bikes (pid 27361 and 27391) and the Exo line (27681). Those use different Bluetooth services and protocols and are out of scope for this page.

Not every model exposes every function over Bluetooth. The page detects your model from the serial (the pid, characters 2 to 5) and shows the immobilizer, cruise control and zero-start where that model's firmware supports them, plus the app-style switches the scooter reports in its own parameter block. The immobilizer works on every model; an unrecognized model shows cruise and zero-start marked as unverified (harmless to try, an unsupported model ignores the command).

The **speed lever** is narrower than the rest of the tool and is shown only for the four families where a flash-free gear lever is proven end to end (meter and controller read line by line, then adversarially verified):

- **XT5 Ultra**: 40.5 to 50.8 km/h depending on the unit SKU. The 50.8 is code-proven but not confirmed by a measured ride.
- **XT5 Pro/Max**: about 50 km/h (SKU 8 up to ~65), depending on the internal gear mapping.
- **UT5 Ultra X**: up to 60 km/h on an unrestricted SKU (the 70 the app offers is not proven).
- **E45/E60 Pro**: up to about 32.5 km/h on a permissive region, otherwise region-limited.

The achieved value is clamped by the firmware to the unit's own SKU and region, so it is a range, not a settable number. On every other model no flash-free path exists (the cap sits in the flash/SKU firmware, or the controller is torque-controlled with no speed setpoint), so the lever is not offered there. Status, the switches and the immobilizer still work across the whole line.

## What it does

- **Connect by name and authenticate automatically.** The scooter shows up by its advertised name, the page runs the challenge-response auth (five built-in AES keys) and reads the status by itself.
- **Model detection and drive functions.** From the serial pid the page shows the immobilizer lock (0x51, every model), cruise control (0x52) and zero-start / start speed (0x6A) where the model's firmware supports them. The manufacturer app hides cruise on EU units and offers zero-start only in the USA version; this page shows both where the firmware supports them, which is the point of a tool of your own.
- **Flash-free speed lever, one button, only where proven.** Where the connected model is one of the four with a verified lever, Unlock sends the gear-4 command (opcode 0x58 = 4); the meter then commands the SKU top speed and the controller allows it up to the unit's own SKU/region cap. It changes one RAM byte, no flashing, no persistence, no brick risk; Reset sends gear 3 to revert. The reachable speed depends on the unit SKU/region (the card shows the per-model range), it is not a free value. Free max-speed setting is intentionally not offered: the 0x6E max-speed write was verified to be flash-ineffective, so it would only promise a number the firmware does not honour.
- **App-style switches** where the scooter reports them: overspeed control OSC (0x82), traction control TCS (0x5F), slope assist (0x81), long-range mode (0x6F/7), tail light (0x54), auto light (0x57), turn-signal sound (0x60), unit km/mph (0x55), proximity key (0x61) and more. Each row appears only if the model reports that field.
- **Read the telemetry** the scooter sends back (region, SKU, max and limit speed, serial) and keep the raw notifications in an on-screen diagnostic log as plain hex.
- **Help on every card** via the question-mark button, and a full guide in both languages.

## Encryption and authentication

The session is protected by a challenge-response handshake, byte-exact from the app:

- The app sends an auth-init frame (opcode 0x30) with a randomly chosen key index (0 to 4) and a packed user id.
- The scooter answers with a 16-byte challenge.
- The page encrypts the challenge with the selected key using **AES-128-ECB** and sends it back (opcode 0x31). On a zero error code the session is authenticated.

The five AES-128 keys are built into the app and are identical in 2.1.6; they are the same for every scooter of this line, not per device. The control commands themselves (speed, region, the switches) are framed in plain `55 AA` frames with an 8-bit checksum; the authentication gates the session, it does not encrypt each command. An AES self-test runs on load and is written to the diagnostic log.

## Browser support

- **iOS:** the **Bluefy** browser. Safari and every other iOS browser run on the Safari engine, which has no Web Bluetooth at all.
- **Android or desktop:** **Chrome** or another Chromium browser. Web Bluetooth is built in.

There is no OTA firmware flashing here; this page only controls the scooter. To patch and flash the switchable speed firmware (the lock/unlock you drive here needs it on capped models), use the companion patcher: [nv-fw](https://laufbursche42.github.io/nv-fw/) in Bluefy on iOS or Chrome on desktop, or the [nv-lb-edition](https://github.com/Laufbursche42/nv-lb-edition) Android app, which patches, flashes and controls in one. The official app updates firmware over Bluetooth (YModem); this page does not.

## Project structure

```
index.html                - the single page: cards, dialogs, the settings
app.js                    - all logic: AES-128-ECB auth, frame builders, connect,
                            decode, the report-gated settings and the diagnostic log
i18n.js                   - the German and English string table
styles.css                - theme and layout
GUIDE.de.md, GUIDE.en.md  - the step-by-step guide
scripts/                  - check-i18n.js and security-scan.py (run in CI and the git hooks)
.github/workflows/        - CI (JS lint plus security scan) and CodeQL
.githooks/                - pre-commit and pre-push checks
```

## How it works

- The page matches the scooter by its advertised name (`namePrefix: 'NAVEE'`) and declares the GATT service as optional, because the scooter does not advertise the 128-bit service UUID. A fallback switch lists all Bluetooth devices.
- After connecting it enables notifications, runs the 0x30/0x31 auth and reads the 0x70 parameter report automatically.
- Each per-model setting is bound to its offset in that report and is shown only when the scooter reports the byte, preset to the current value. So each model shows only the options it has.
- The full byte-level protocol and the reverse-engineering notes are in the analysis document that ships with the project.

## Development

No build step and no dependencies. Edit the files and reload the page. Serve locally, Web Bluetooth needs `https` or `localhost`:

```
python -m http.server 8000
```

Run the same checks as the CI and the hooks:

```
node scripts/check-i18n.js
python scripts/security-scan.py
```

Enable the git hooks with `git config core.hooksPath .githooks`. New user-facing strings go into both languages in `i18n.js`; `check-i18n.js` fails on a missing or unused key.

## Reporting

Found a problem or want to confirm what works on a real scooter? Send a DM to
[Laufbursche on escooter-stammtisch](https://www.escooter-stammtisch.de/index.php?user/6497-laufbursche/)
or open a [GitHub issue](https://github.com/Laufbursche42/nv-unlock/issues). The copy button under the log gives you the full diagnostic transcript to paste in.

## Legal

Raising the maximum speed lifts the factory limit. The operating permit (Betriebserlaubnis, ABE) is then void and riding the scooter in public traffic is no longer allowed, with the corresponding insurance and registration consequences. Use it on your own vehicle only. Everything you do with this page is at your own risk.

## License

Creative Commons Attribution-NonCommercial-NoDerivatives 4.0 (CC BY-NC-ND 4.0), in full in [LICENSE.md](LICENSE.md).

## Privacy

Nothing leaves your device but the page load itself. The details are in [PRIVACY.md](PRIVACY.md).

## Trademarks

An independent project, not affiliated with NAVEE. "NAVEE" and other product names are trademarks of their respective owners and are used here only to say which scooters this page works with. See [TRADEMARKS.md](TRADEMARKS.md).
