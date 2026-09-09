/*
 * scanner.h — Wi-Fi Network Scanner  [v3]
 * ═════════════════════════════════════════
 * v3 changes:
 *   ✅ CFG_SCAN_MAX_NETWORKS now actually used to cap results
 *   ✅ Output table uses min(n, CFG_SCAN_MAX_NETWORKS)
 */

#pragma once
#include "utils.h"
#include <algorithm>

#define TAG_SCAN "SCAN"

static const char* signalBar(int rssi) {
  if (rssi >= -50) return "[████████] Excellent";
  if (rssi >= -60) return "[██████░░] Good";
  if (rssi >= -70) return "[████░░░░] Fair";
  if (rssi >= -80) return "[██░░░░░░] Weak";
  return                  "[░░░░░░░░] Very Weak";
}

void wifiScanner() {
  LOG_I(TAG_SCAN, "Starting Wi-Fi scan (hidden SSIDs included)...");

  WiFi.mode(WIFI_STA);
  WiFi.disconnect(true);
  delay(120);

  int n = WiFi.scanNetworks(false, CFG_SCAN_SHOW_HIDDEN);

  if (n == WIFI_SCAN_FAILED) {
    LOG_E(TAG_SCAN, "Scan failed — is Wi-Fi hardware available?");
    return;
  }
  if (n == 0) {
    LOG_I(TAG_SCAN, "No networks found.");
    return;
  }

  // ── Cap to configured maximum ────────────────────────────
  int display = (n > CFG_SCAN_MAX_NETWORKS) ? CFG_SCAN_MAX_NETWORKS : n;

  // ── Sort by RSSI descending ───────────────────────────────
  int idx[n];
  for (int i = 0; i < n; i++) idx[i] = i;
  std::sort(idx, idx + n, [](int a, int b) {
    return WiFi.RSSI(a) > WiFi.RSSI(b);
  });

  // ── Header ───────────────────────────────────────────────
  Serial.println();
  Serial.println(F("╔══╦══════════════════════════════╦═══╦══════╦═══════════╦═══════════════════╦════════════════════════╗"));
  Serial.printf ("║  ║ %-28s ║Ch ║ RSSI ║ Security  ║ BSSID             ║ Signal                 ║\n", "SSID");
  Serial.println(F("╠══╬══════════════════════════════╬═══╬══════╬═══════════╬═══════════════════╬════════════════════════╣"));

  int cntOpen=0, cntWEP=0, cntWPA=0, cntWPA2=0, cntWPA3=0, cntOther=0;

  for (int i = 0; i < display; i++) {
    int j = idx[i];

    String ssid = WiFi.SSID(j);
    if (ssid.length() == 0)  ssid = F("(hidden)");
    if (ssid.length() > 28)  ssid = ssid.substring(0, 27) + "…";

    char bssidStr[18];
    macToStr(WiFi.BSSID(j), bssidStr);

    const char* enc = encryptionStr(WiFi.encryptionType(j));

    switch (WiFi.encryptionType(j)) {
      case WIFI_AUTH_OPEN:             cntOpen++;  break;
      case WIFI_AUTH_WEP:              cntWEP++;   break;
      case WIFI_AUTH_WPA_PSK:          cntWPA++;   break;
      case WIFI_AUTH_WPA2_PSK:
      case WIFI_AUTH_WPA2_ENTERPRISE:  cntWPA2++;  break;
      case WIFI_AUTH_WPA3_PSK:
      case WIFI_AUTH_WPA2_WPA3_PSK:    cntWPA3++;  break;
      default:                         cntOther++; break;
    }

    Serial.printf("║%2d║ %-28s ║%3d║ %4d ║ %-9s ║ %-17s ║ %s\n",
      i + 1,
      ssid.c_str(),
      WiFi.channel(j),
      WiFi.RSSI(j),
      enc,
      bssidStr,
      signalBar(WiFi.RSSI(j))
    );
  }

  Serial.println(F("╚══╩══════════════════════════════╩═══╩══════╩═══════════╩═══════════════════╩════════════════════════╝"));

  if (n > display)
    Serial.printf("  (Showing %d of %d found; raise CFG_SCAN_MAX_NETWORKS to see more.)\n", display, n);

  // ── Summary ──────────────────────────────────────────────
  Serial.println(F("\n  ┌─── Encryption Summary ──────────────────────────────────┐"));
  Serial.printf ("  │  Total: %-3d  OPEN: %-3d  WEP: %-3d  WPA: %-3d              │\n",
    n, cntOpen, cntWEP, cntWPA);
  Serial.printf ("  │  WPA2:  %-3d  WPA3: %-3d  Other: %-3d                       │\n",
    cntWPA2, cntWPA3, cntOther);
  if (cntOpen > 0)
    Serial.println(F("  │  ⚠️  Open networks detected — possible security risk!     │"));
  if (cntWEP > 0)
    Serial.println(F("  │  ⚠️  WEP networks detected — extremely weak encryption!   │"));
  Serial.println(F("  └────────────────────────────────────────────────────────┘"));

  WiFi.scanDelete();
  LOG_I(TAG_SCAN, "Scan complete. %d network(s) found.", n);
}
