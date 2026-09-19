# Privacy Policy

This web app is built to keep your data on your device. This policy explains exactly what it does and does not do with your data.

## The short version

The app collects nothing. There are no accounts, no analytics, no telemetry, no tracking, no ads, no cookies and no third-party scripts. Nothing is ever sent to the developer or to any manufacturer backend.

## What data the app handles - and where it stays

All of the following stays on your device and is never uploaded anywhere:

- Live scooter data read over Bluetooth LE (region, max/limit speed, serial number and status).
- Anything you type into the page (the account id used for the auth handshake, and the country value). It lives only in the open page for the session, is not persisted and is not uploaded.
- The on-screen log. It exists only in the open page during your session, is never stored and is never uploaded.

## The only network connection

The app makes a network connection in exactly one case: **loading the page.** When you open or reload it, your browser fetches the static files (`index.html`, `app.js`, `styles.css`) from the host (for example GitHub Pages). The host sees only your **IP address** and which file you requested - the normal web-server logs every website has. It **never** sees any scooter data, the account id or the serial - that data never reaches any server at all; it exists only on your phone and travels only over the local Bluetooth link.

## Bluetooth LE to your scooter

A local radio link to your scooter over Web Bluetooth. This is not an internet connection - no data leaves your phone over the network for this. The status reads, the auth handshake and the region write travel only between your browser and the scooter.

## No developer or manufacturer backend

Nothing is ever sent to the developer or to any manufacturer backend. There is no cloud account and no server operated by this project that receives your data. For comparison: the official NAVEE app signs in to a cloud backend and exchanges account, compliance and firmware data with it - this app does none of that and talks to no server at all beyond fetching its own static files.

## Contact

For privacy questions, contact the author (Tbe Navee) on GitHub: https://github.com/Tbe Navee42
