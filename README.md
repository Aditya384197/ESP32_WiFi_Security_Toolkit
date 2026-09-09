# ESP32 Wi-Fi Security Toolkit

This version is a **passive, authorized network-observation toolkit** for
ESP32. It includes:

- Wi-Fi network scanning
- Probe-request observation with vendor hints
- Passive 802.11 frame statistics
- EAPOL frame counting without extracting credential material
- Channel hopping and serial-console diagnostics

The original archive contained active deauthentication, fake-beacon, rogue-AP,
credential-capture, and PMKID-extraction code. Those modules were removed from
this fixed build rather than making disruptive or credential-theft behavior
workable.

## Build locally

Install Arduino IDE 2.x with the Espressif ESP32 core **3.0.7**, then open
`ESP32_WiFi_Security_Toolkit.ino` and select an ESP32 board.

The GitHub Actions workflow at `.github/workflows/build.yml` installs the same
core and compiles the sketch automatically on pushes and pull requests.

## Serial menu

Use 115200 baud:

1. Wi-Fi scanner
2. Probe-request sniffer
3. Passive packet analyzer
4. Channel hopper

Press `s` to stop a running operation.