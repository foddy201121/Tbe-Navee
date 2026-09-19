# Datenschutz

Diese Web-App ist so gebaut, dass deine Daten auf deinem Gerät bleiben. Dieser Text erklärt genau, was sie mit deinen Daten tut und was nicht.

## Kurzfassung

Die App sammelt nichts. Es gibt keine Konten, keine Analyse, keine Telemetrie, kein Tracking, keine Werbung, keine Cookies und keine Skripte von Dritten. Nichts wird jemals an den Entwickler oder an ein Hersteller-Backend gesendet.

## Welche Daten die App verarbeitet und wo sie bleiben

Alles Folgende bleibt auf deinem Gerät und wird nirgends hochgeladen:

- Live-Scooter-Daten, die über Bluetooth LE gelesen werden (Region, Max-/Limit-Geschwindigkeit, Seriennummer sowie Status).
- Alles, was du in die Seite tippst (die Konto-ID für den Auth-Handshake und der Ländercode). Es lebt nur in der offenen Seite während der Sitzung, wird nicht gespeichert und nicht hochgeladen.
- Das Log auf dem Bildschirm. Es existiert nur in der offenen Seite während deiner Sitzung, wird nie gespeichert und nie hochgeladen.

## Die einzige Netzwerkverbindung

Die App stellt in genau einem Fall eine Netzwerkverbindung her: **beim Laden der Seite.** Beim Öffnen oder Neuladen holt dein Browser die statischen Dateien (`index.html`, `app.js`, `styles.css`) vom Host (zum Beispiel GitHub Pages). Der Host sieht nur deine **IP-Adresse** und welche Datei du angefragt hast, also die normalen Web-Server-Logs, die jede Website hat. Er sieht **nie** Scooter-Daten, die Konto-ID oder die Seriennummer. Diese Daten erreichen gar keinen Server, sie liegen nur auf deinem Telefon und laufen nur über die lokale Bluetooth-Verbindung.

## Bluetooth LE zum Scooter

Eine lokale Funkverbindung zu deinem Scooter über Web Bluetooth. Das ist keine Internetverbindung, dafür verlassen keine Daten dein Telefon über das Netz. Die Status-Lesevorgänge, der Auth-Handshake und das Region-Schreiben laufen nur zwischen deinem Browser und dem Scooter.

## Kein Entwickler- oder Hersteller-Backend

Nichts wird jemals an den Entwickler oder an ein Hersteller-Backend gesendet. Es gibt kein Cloud-Konto und keinen von diesem Projekt betriebenen Server, der deine Daten empfängt. Zum Vergleich: Die offizielle NAVEE-App meldet sich an einem Cloud-Backend an und tauscht Konto-, Compliance- und Firmware-Daten mit ihm aus. Diese App tut nichts davon und spricht mit keinem Server, außer ihre eigenen statischen Dateien zu laden.

## Kontakt

Bei Datenschutzfragen den Autor (Tbe Navee) auf GitHub kontaktieren: https://github.com/Tbe Navee42
