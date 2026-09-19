# Anleitung

Schritt für Schritt durch das Laufbursche NAVEE Tool. Die Seite spricht über Web Bluetooth mit deinem NAVEE-Scooter, komplett auf deinem Gerät. Es werden keine Daten an einen Server gesendet.

## Was du brauchst

- Einen NAVEE-Scooter (die Tretroller-Linie, zum Beispiel die XT5). Einschalten und in wenigen Metern Reichweite halten.
- Einen Browser mit Web Bluetooth: **Chrome** oder **Edge** auf Android bzw. Desktop. Auf iPhone/iPad **Bluefy**. Safari und Firefox unterstützen Web Bluetooth nicht.
- Bluetooth eingeschaltet. Auf Android braucht der Browser die Standortfreigabe für den Bluetooth-Scan.

## Mit welchen Geräten es funktioniert

**Zum Entsperren funktioniert diese Seite nur mit diesen Modellen:** NAVEE XT5 Ultra, XT5 Pro/Max, UT5 Ultra X sowie E45/E60 Pro. Bei allen anderen Modellen (etwa dem NT5) sitzt die Drossel fest in der Firmware - dort ist ein Firmware-Patch nötig, der auf den Scooter geflasht werden muss.

Ansonsten spricht das Tool das Standard-Scooter-Protokoll von NAVEE, dasselbe, das die offizielle App für die ganze Scooter-Linie nutzt. Die Auth-Schlüssel sind über diese Scooter hinweg gleich, deshalb redet das Tool mit jedem davon (nicht nur mit der XT5) und zeigt Status, Schalter und die Wegfahrsperre auch dort. Nur der Speed-Hebel bleibt den oben genannten Modellen vorbehalten. Die NAVEE-E-Bikes und die Exo-Linie nutzen andere Bluetooth-Protokolle und werden **nicht** unterstützt.

## Die numerische Konto-userId ermitteln (jeder an ein Konto gebundene Roller)

### Worum es geht und warum es oft schiefgeht

Das Tool authentifiziert sich gegenüber dem Roller mit deiner **numerischen Konto-userId**. Diese Zahl ist Teil des Login-/Session-Paars, das die App beim Anmelden vom Server bekommt. In der App steckt sie im Feld `UserSession.userId` - einem echten Integer (Ganzzahl).

Die App zeigt dir auf dem Konto-Bildschirm aber eine **ganz andere** Kennung an: die sogenannte **NaveeID**. Das ist ein alphanumerischer String (Buchstaben und Ziffern gemischt) von rund 13 Zeichen Länge. Intern liegt sie im Feld `UserInfo.naveeId` - einer eigenen Klasse, die gar kein numerisches ID-Feld besitzt.

Kurz gesagt sitzen die beiden IDs auf zwei verschiedenen Objekten:

| Merkmal | Numerische userId | NaveeID |
|---|---|---|
| Klasse/Feld | `UserSession.userId` | `UserInfo.naveeId` |
| Typ | Integer (reine Zahl) | String (Buchstaben und Ziffern) |
| Länge | bis maximal 10 Ziffern | rund 13 Zeichen |
| Herkunft | Login-/Auth-Antwort (Token und userId als Session-Paar) | Nutzerprofil, Anzeige auf dem Konto-Bildschirm |
| Für das Tool | **das hier brauchst du** | **NICHT verwenden** |

> **Merksatz:** Was du in der App ablesen kannst, ist die **falsche** ID. Die richtige steht nirgends in der Oberfläche - sie kommt nur aus der Login-Antwort des Servers und muss aus dem Netzwerkverkehr oder dem BLE-Verkehr geholt werden.

Wenn du versehentlich die NaveeID (den ~13-stelligen Mischcode) einträgst, quittiert das Tool das mit **Fehler 255**. Details zu diesem Fehlerbild stehen in der Gesamtanalyse.

---

### Route A - iOS (Mitschnitt direkt auf dem iPhone)

Auf dem iPhone geht es ohne PC mit einer HTTPS-Mitschnitt-App wie **Http Catcher** oder **Stream** aus dem App Store.

1. **App installieren.** Http Catcher (oder Stream) aus dem App Store laden und öffnen.
2. **VPN-Profil erlauben.** Beim ersten Start richtet die App ein lokales VPN-Profil ein, über das der Verkehr läuft. Bestätige die Nachfrage mit "Erlauben" und deinem Code/Face ID.
3. **Root-Zertifikat installieren.** Die App bietet an, ihr CA-Zertifikat zu installieren. Folge dem Assistenten: `Einstellungen -> Profil geladen -> Installieren`.
4. **Zertifikat als vertrauenswürdig markieren (wichtig, sonst kein HTTPS-Klartext):** `Einstellungen -> Allgemein -> Info -> Zertifikatsvertrauens-Einstellungen` und dort den Schalter für das Zertifikat der Mitschnitt-App aktivieren.
5. **HTTPS-Entschlüsselung (SSL) in der App einschalten.** In Http Catcher unter den Einstellungen "SSL Proxying" (oder "HTTPS decryption") aktivieren.
6. **Mitschnitt starten.** In der Mitschnitt-App auf Aufnahme/Record tippen (rundes Symbol).
7. **NAVEE-App neu anmelden.** Die NAVEE-App öffnen und dich **komplett neu einloggen** (bei Bedarf vorher abmelden). Genau dieser Login erzeugt die Antwort mit der userId.
8. **Login-Aufruf finden.** Zurück in der Mitschnitt-App die Liste filtern nach dem Host **`lj.naveetech.com`**. Suche den POST-Aufruf, der zum Login/zur Anmeldung gehört (Pfad enthält typischerweise `login`, `auth` oder `token`).
9. **userId ablesen.** Diesen Eintrag antippen und zur **Response** (Antwort-Body, JSON) wechseln. Dort das Feld **`userId`** suchen - eine reine Zahl mit bis zu 10 Ziffern. Direkt daneben steht meist das Token. Diese Zahl ist dein Wert für das Tool.

---

### Route B - Android

#### B1) Am einfachsten: Bluetooth-Log hochladen (ganz ohne PC, ohne Wireshark)

Die Seite liest das Bluetooth-Log deines Android-Geräts und holt die userId selbst heraus. Nichts wird hochgeladen, alles bleibt lokal auf deinem Gerät.

1. **Entwickleroptionen öffnen** (`Einstellungen -> Über das Telefon -> 7x auf die Build-Nummer tippen`).
2. In den Entwickleroptionen das **Bluetooth-HCI-Snoop-Log** einschalten.
3. **Bluetooth aus- und wieder einschalten**, damit das Mitschreiben startet.
4. Einmal mit der **echten NAVEE-App** mit dem Roller verbinden, kurz warten, bis die Verbindung steht.
5. Einen **Fehlerbericht** erstellen: Entwickleroptionen -> **Fehlerbericht** -> Interaktiver Bericht. Android packt die Log-Datei in ein ZIP, das du speichern oder teilen kannst.
6. Auf der Seite unten den Bereich **"Android: Auth-Frame / btsnoop_hci.log statt userId"** aufklappen und das Fehlerbericht-ZIP (oder direkt die `btsnoop_hci.log`, falls dein Datei-Manager sie sieht) in das Upload-Feld ablegen.
7. Fertig - die Seite erkennt die Anmeldung, Verbinden ist frei. Die userId bleibt lokal im Browser-Speicher (localStorage) deines Geräts, du machst das nur einmal.

#### B2) Alternative: die reine Zahl per PC auslesen (HTTP Toolkit)

Wer lieber die Zahl selbst haben will und einen PC nutzt: mit dem kostenlosen **HTTP Toolkit**.

1. HTTP Toolkit auf dem PC installieren und starten, dann die Kachel **"Android device via ADB"** wählen (Telefon per USB, USB-Debugging aktiv).
2. HTTP Toolkit richtet Proxy und Zertifikat automatisch ein. Am Telefon die Nachfragen bestätigen.
3. Die NAVEE-App öffnen und dich **neu einloggen**.
4. Nach dem Host **`lj.naveetech.com`** filtern, den Login-POST anklicken und im **Response-Body** das Feld **`userId`** ablesen (Zahl, bis 10 Ziffern). Diese Zahl oben ins userId-Feld eintragen.

---

### Verifikation - habe ich die richtige ID

Prüfe die eingetragene ID an diesen Merkmalen, bevor du das Tool startest:

- Sie besteht **ausschließlich aus Ziffern** - keine Buchstaben, kein Bindestrich, kein Doppelpunkt.
- Sie ist **höchstens 10 Ziffern** lang.
- Sie stammt aus dem **Response-Body** des Login-Aufrufs an `lj.naveetech.com` (Feld `userId`), **nicht** vom Konto-Bildschirm.

Zeigt das Tool **Fehler 255**, hast du mit hoher Wahrscheinlichkeit die falsche Kennung erwischt - meist die alphanumerische ~13-stellige **NaveeID** vom Konto-Bildschirm statt der reinen Zahl aus der Login-Antwort. Trage in dem Fall die numerische `userId` ein und wiederhole den Versuch.

## Schritt für Schritt

1. **Seite öffnen** in einem unterstützten Browser.
2. **userId eintragen und Verbinden.** Trage oben deine numerische Konto-userId ein (siehe Abschnitt davor), dann wird *Verbinden* frei. Auf *Verbinden* tippen und deinen Scooter im Dialog auswählen. Er erscheint unter seinem Namen (NAVEE...), genau wie in der offiziellen App. Falls er nicht auftaucht, den Haken *Alle Bluetooth-Geräte zeigen* setzen und dort suchen. Das Tool authentifiziert sich direkt nach dem Verbinden automatisch.
3. **Werte erscheinen automatisch.** Gleich nach dem Verbinden liest das Tool den Status und zeigt Region, SKU, Max-Speed, Limit, die Seriennummer und die Telemetrie. Die rohen Frames stehen zusätzlich als Hex im Log.
4. **Funktionen (Wegfahrsperre, Tempomat, Zero-Start).** Die Seite erkennt dein Modell an der Seriennummer und zeigt in der Karte *Funktionen* nur, was die Firmware dieses Modells setzen kann:
   - **Wegfahrsperre** (0x51) - bei jedem Modell.
   - **Tempomat** (0x52) - wo firmwareseitig belegt.
   - **Zero-Start** Stufen 0 bis 5 (0x6A) - wo belegt; Stufe 0 ist der echte Zero-Start.
   Die Hersteller-App blendet Tempomat auf EU-Geräten aus und bietet Zero-Start nur in der USA-Version - hier geht beides, wo das Modell es kann. Ein nicht erkanntes Modell zeigt Tempomat und Zero-Start als *unbestätigt*; ein Senden schadet nicht, ein Modell ohne die Funktion ignoriert den Befehl.
5. **Geschwindigkeit freischalten (nur vier Familien).** Die Speed-Karte erscheint nur bei den Modellen mit belegtem flash-freien Gang-Hebel: XT5 Ultra/Pro/Max, UT5 Ultra X sowie E45/E60 Pro. *Speed freischalten* sendet den Gang-4-Befehl (BLE 0x58 = 4); der Meter kommandiert die firmwareseitig mögliche Höchstgeschwindigkeit, die Firmware kappt sie auf SKU und Region des Geräts. Der Hinweis in der Karte nennt den Bereich je Modell (XT5 Ultra 40,5 bis 50,8 je nach SKU; UT5 Ultra X bis 60; E45/E60 Pro bis etwa 32,5). *Zurücksetzen* stellt den Normalmodus wieder her (Gang 3). Es gibt kein Eingabefeld, weil der Wert nicht frei setzbar ist.
   - Verhalten am Gerät: Das Display bleibt in D, die Boost-Taste ist ohne Funktion. Ein Wechsel in Modus S oder ein Neustart hebt den Trick auf, also je Fahrt neu senden.
   - Bei allen anderen Modellen erscheint die Speed-Karte gar nicht, weil kein flash-freier Weg belegt ist: der Cap sitzt in der Flash-/SKU-Firmware oder der Controller ist drehmomentgeregelt ohne Speed-Sollwert.
6. **Erneut Status lesen** und prüfen, was der Scooter jetzt meldet.

## Wie weit geht es

Der flash-freie Gang-Hebel ist über die ganze Firmware-Kette geprüft (Meter plus Controller zeile-für-zeile, jeder Fund adversarisch gegengeprüft). Er wirkt nur bei vier Familien und der erreichte Wert hängt an SKU sowie Region des konkreten Geräts:

- **XT5 Ultra**: 40,5 bis 50,8 km/h je nach SKU-Byte. Die 50,8 sind im Code belegt, aber nicht per Messfahrt bestätigt.
- **XT5 Pro/Max**: rund 50 km/h (SKU 8 bis etwa 65), abhängig von der internen Gang-Zuordnung.
- **UT5 Ultra X**: bis 60 km/h auf unbeschränkter SKU. Die 70 aus der App sind nicht belegt.
- **E45/E60 Pro**: bis etwa 32,5 km/h auf freizügiger Region, sonst gedrosselt.

Bei allen anderen Modellen gibt es keinen flash-freien Weg: der echte Cap sitzt in der Flash-/SKU-Firmware oder der Controller ist drehmomentgeregelt ohne km/h-Sollwert. Auch die App-eigene Max-Speed-Funktion (Befehl 0x6E) wurde geprüft und als flash-frei wirkungslos widerlegt, deshalb bietet die Seite kein freies Setzen an - sie würde sonst eine Zahl versprechen, die die Firmware nicht hält.

## Ist es dauerhaft

Nein - das ist sogar der Vorteil: der Gang-4-Trick ändert nur ein RAM-Byte, kein Flash. Ein Wechsel in Modus S oder ein Neustart stellt den Normalzustand wieder her, also je Fahrt neu *Entsperren* drücken. Kein Brick-Risiko, kein Flashen.

## Fehlersuche

- **Der Scooter fehlt im Dialog.** Sicherstellen, dass er an und nah ist, Bluetooth aktiv ist und der Browser auf Android die Standortfreigabe hat. Dann *Alle Bluetooth-Geräte zeigen* anhaken.
- **Fehler 255 im Log.** Der Scooter lehnt die Konto-ID ab. Meist wurde die alphanumerische Navee-ID statt der numerischen userId eingetragen. Siehe den Abschnitt *Einmalig: deine NAVEE Konto-userId finden*.
- **Verbindet, aber keine Werte.** Im Log auf RX-Frames achten. Wenn die Authentifizierung scheitert (Fehler 255), steht das im Log.
- **Die Speed-Karte fehlt.** Dann ist das Modell keines der vier mit belegtem Hebel (XT5 Ultra/Pro/Max, UT5 Ultra X, E45/E60 Pro). Bei allen anderen gibt es keinen flash-freien Speed-Weg, deshalb wird die Karte gar nicht angezeigt.
- **Freischalten bringt weniger als erhofft.** Der erreichte Wert wird von der Firmware auf SKU und Region deines Geräts begrenzt - siehe den Bereich im Hinweis der Speed-Karte.

## Datenschutz und Recht

Alles läuft lokal über Bluetooth. Siehe [Datenschutz](PRIVACY.de.md). Das Anheben der Geschwindigkeit hebt die Drossel auf, damit erlischt die ABE und der Betrieb auf öffentlichen Wegen ist nicht erlaubt. Nutzung nur am eigenen Fahrzeug auf privatem Gelände. Siehe den [Haftungsausschluss](#) im Fuß der Seite.
