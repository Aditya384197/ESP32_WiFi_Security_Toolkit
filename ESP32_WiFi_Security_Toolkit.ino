/*
 * ╔══════════════════════════════════════════════════════════════╗
 * ║   ESP32 Wi-Fi Security Testing Toolkit  [v3 — Next Level]   ║
 * ║   Platform : ESP32 (Arduino IDE 2.3.1)                      ║
 * ║   Board    : esp32 by Espressif Systems v3.0.7              ║
 * ╠══════════════════════════════════════════════════════════════╣
 * ║  FILES (same sketch folder):                                 ║
 * ║    ESP32_WiFi_Security_Toolkit.ino  ← this file             ║
 * ║    config.h          — all tunable constants                 ║
 * ║    utils.h           — logger, I/O, ring buffer, TX retry   ║
 * ║    scanner.h         — Wi-Fi network scanner                 ║
 * ║    sniffer.h         — probe sniffer + OUI vendor lookup     ║
 * ║    packet_analyzer.h — passive 802.11 analyzer               ║
 * ╠══════════════════════════════════════════════════════════════╣
 * ║  v3 Changes (vs v2):                                         ║
 * ║   • Serial.setTimeout() in setup() — no more input timeouts  ║
 * ║   • CFG_SCAN_MAX_NETWORKS actually enforced                   ║
 * ║   • Passive EAPOL frame counting in Packet Analyzer          ║
 * ║   • Sniffer: OUI vendor hints, deauth rate limiter,          ║
 * ║     wildcard/targeted probe split, sorted device table       ║
 * ╠══════════════════════════════════════════════════════════════╣
 * ║  ⚠️  LEGAL DISCLAIMER                                        ║
 * ║  Use ONLY on networks you own or have written permission to  ║
 * ║  test. Unauthorized use is illegal in most jurisdictions.    ║
 * ╚══════════════════════════════════════════════════════════════╝
 *
 * SERIAL MONITOR: 115200 baud, line ending "Both NL & CR"
 *
 * MENU KEYS (type key + Enter):
 *   [1] Wi-Fi Scanner
 *   [2] Probe Request Sniffer
 *   [3] Passive Packet Analyzer
 *   [4] Channel Hopper
 *   [i] System / Heap Info
 *   [v] Set Log Verbosity
 *   [s] STOP current operation
 *   [m] Show main menu
 *   [r] Restart ESP32
 */

// ── Includes (config first, utils second — order matters) ─────
#include "config.h"
#include "utils.h"
#include "scanner.h"
#include "sniffer.h"
#include "packet_analyzer.h"

// ── Global stop flag ──────────────────────────────────────────
// All running tools poll this. Set to true to interrupt anything.
volatile bool g_stop = false;

// ═════════════════════════════════════════════════════════════
// BANNER
// ═════════════════════════════════════════════════════════════
static void printBanner() {
  Serial.println(F("\r\n"));
  Serial.println(F("╔══════════════════════════════════════════════════════════╗"));
  Serial.println(F("║   ESP32 Wi-Fi Security Testing Toolkit   v3.0            ║"));
  Serial.println(F("║   For Authorized Penetration Testing ONLY                ║"));
  Serial.println(F("╠══════════════════════════════════════════════════════════╣"));
  Serial.printf ("║   Chip  : %-16s  Cores: %u   Rev: %u             ║\n",
    ESP.getChipModel(), ESP.getChipCores(), ESP.getChipRevision());
  Serial.printf ("║   Flash : %4u MB   PSRAM: %4u KB   CPU: %3u MHz          ║\n",
    (uint32_t)(ESP.getFlashChipSize() / 1048576UL),
    (uint32_t)(ESP.getPsramSize()     /    1024UL),
    ESP.getCpuFreqMHz());
  Serial.printf ("║   Heap  : %6u B free / %6u B total                    ║\n",
    ESP.getFreeHeap(), ESP.getHeapSize());
  Serial.println(F("╚══════════════════════════════════════════════════════════╝"));
}

// ═════════════════════════════════════════════════════════════
// MENU
// ═════════════════════════════════════════════════════════════
static void printMenu() {
  Serial.println(F("\r\n╔══════════════════════ MAIN MENU ═══════════════════════╗"));
  Serial.println(F("║  [1]  Wi-Fi Network Scanner                            ║"));
  Serial.println(F("║  [2]  Probe Request Sniffer  (OUI + vendor hints)      ║"));
  Serial.println(F("║  [3]  Passive Packet Analyzer  (802.11 + EAPOL)        ║"));
  Serial.println(F("║  [4]  Channel Hopper                                   ║"));
  Serial.println(F("╠════════════════════════════════════════════════════════╣"));
  Serial.println(F("║  [i] System Info  [v] Verbosity  [s] STOP  [r] Restart ║"));
  Serial.println(F("║  [m] This menu                                         ║"));
  Serial.println(F("╚════════════════════════════════════════════════════════╝"));
  Serial.print(F("Choice: "));
}

// ═════════════════════════════════════════════════════════════
// CHANNEL HOPPER  (standalone, no FreeRTOS task needed)
// ═════════════════════════════════════════════════════════════
static void channelHopper(uint32_t dwellMs) {
  LOG_I("HOP", "Channel Hopper. Dwell: %u ms. Send 's' to stop.", dwellMs);
  WiFi.mode(WIFI_STA);
  WiFi.disconnect(true);
  delay(80);

  if (!enablePromiscuous(WIFI_PROMIS_FILTER_MASK_MGMT, nullptr)) {
    LOG_E("HOP", "Failed to enable promiscuous!");
    return;
  }

  uint8_t ch = CFG_CHANNEL_MIN;

  while (!g_stop) {
    setChannel(ch);
    Serial.printf("[HOP] → Ch %2u\n", ch);
    ch = (uint8_t)((ch % CFG_CHANNEL_MAX) + 1);

    uint32_t t = millis();
    while (millis() - t < dwellMs && !g_stop) {
      checkStopSerial(&g_stop);
      vTaskDelay(CFG_WDT_YIELD_TICKS);
    }
  }

  disablePromiscuous();
  LOG_I("HOP", "Stopped.");
}

// ═════════════════════════════════════════════════════════════
// SYSTEM INFO
// ═════════════════════════════════════════════════════════════
static void printSysInfo() {
  Serial.println(F("\n╔════════════════════ System Info ════════════════════╗"));
  Serial.printf ("║  Chip Model   : %-16s  Rev: %u             ║\n",
    ESP.getChipModel(), ESP.getChipRevision());
  Serial.printf ("║  CPU Freq     : %3u MHz   Cores: %u                   ║\n",
    ESP.getCpuFreqMHz(), ESP.getChipCores());
  Serial.printf ("║  Flash Size   : %4u MB   Speed: %u MHz               ║\n",
    (uint32_t)(ESP.getFlashChipSize() / 1048576UL),
    ESP.getFlashChipSpeed() / 1000000UL);
  Serial.printf ("║  PSRAM        : %4u KB                                ║\n",
    (uint32_t)(ESP.getPsramSize() / 1024UL));
  Serial.printf ("║  Heap Free    : %6u B   Heap Total: %6u B        ║\n",
    ESP.getFreeHeap(), ESP.getHeapSize());
  Serial.printf ("║  Min Free Heap: %6u B (since boot)                  ║\n",
    ESP.getMinFreeHeap());
  Serial.printf ("║  Sketch Size  : %6u B   Free: %6u B              ║\n",
    ESP.getSketchSize(), ESP.getFreeSketchSpace());
  Serial.printf ("║  Uptime       : %lu s                               ║\n",
    millis() / 1000UL);

  Serial.println(F("╠════════════════════════════════════════════════════╣"));
  Serial.println(F("║  Mode          : passive capture only             ║"));
  Serial.println(F("╚════════════════════════════════════════════════════╝"));
}

// ═════════════════════════════════════════════════════════════
// TOOL DISPATCHERS
// ═════════════════════════════════════════════════════════════

// ── [1] Scanner ───────────────────────────────────────────────
static void runScanner() {
  g_stop = false;
  wifiScanner();
}

// ── [2] Probe Sniffer ─────────────────────────────────────────
static void runSniffer() {
  Serial.print(F("  Duration seconds (0 = until 's'): "));
  uint32_t dur = (uint32_t)readIntFromSerial(&g_stop);

  g_stop = false;
  probeSniffer(dur, &g_stop);
}

// ── [3] Passive Packet Analyzer ───────────────────────────────
static void runPacketAnalyzer() {
  Serial.print(F("  Channel (1-13): "));
  int ch = readIntFromSerial(&g_stop);
  if (ch < CFG_CHANNEL_MIN || ch > CFG_CHANNEL_MAX) ch = 6;

  Serial.print(F("  Duration seconds (0 = until 's'): "));
  uint32_t dur = (uint32_t)readIntFromSerial(&g_stop);

  Serial.println(F("\n  TIP: During capture, type '0'-'3' to change verbosity."));
  Serial.println(F("  Passive mode: frame statistics and EAPOL counts only.\n"));

  g_stop = false;
  packetAnalyzer((uint8_t)ch, dur, &g_stop);
}

// ── [4] Channel Hopper ────────────────────────────────────────
static void runChannelHopper() {
  Serial.print(F("  Dwell ms per channel (0 = default 500): "));
  int dwell = readIntFromSerial(&g_stop);
  if (dwell <= 0) dwell = 500;

  g_stop = false;
  channelHopper((uint32_t)dwell);
}

// ═════════════════════════════════════════════════════════════
// SETUP
// ═════════════════════════════════════════════════════════════
void setup() {
  Serial.begin(CFG_SERIAL_BAUD);

  // ── v3: Set Serial timeout so parseInt() / readStringUntil()
  //   don't time out at the default 1000 ms when the user takes
  //   a moment to type. CFG_SERIAL_TIMEOUT_MS = 15000 ms.
  Serial.setTimeout(CFG_SERIAL_TIMEOUT_MS);

  delay(500);

  // Initial Wi-Fi state: STA, disconnected, max TX power
  WiFi.mode(WIFI_STA);
  WiFi.disconnect(true);
  setTxPower(CFG_TX_POWER);
  delay(100);

  printBanner();
  LOG_I("MAIN", "v3.0 ready. All systems nominal.");
  LOG_I("MAIN", "Free heap: %u B", ESP.getFreeHeap());
  delay(200);
  printMenu();
}

// ═════════════════════════════════════════════════════════════
// LOOP — single-character menu dispatch
// Runs on Core 1 (loopTask, priority 1).
// Passive capture tools yield every tick so the watchdog stays serviced.
// ═════════════════════════════════════════════════════════════
void loop() {
  if (!Serial.available()) {
    vTaskDelay(CFG_WDT_YIELD_TICKS);
    return;
  }

  char choice = (char)Serial.read();
  serialFlush();   // Discard trailing CR/LF

  // Ignore bare whitespace / newlines
  if (choice == '\r' || choice == '\n' || choice == ' ') return;

  Serial.println(choice);  // Echo back

  bool showMenuAfter = true;

  switch (choice) {
    case '1': runScanner();        break;
    case '2': runSniffer();        break;
    case '3': runPacketAnalyzer(); break;
    case '4': runChannelHopper();  break;

    // ── STOP ───────────────────────────────────────────────
    case 's': case 'S':
      g_stop = true;
      LOG_I("MAIN", "Stop signal sent to current operation.");
      showMenuAfter = false;
      break;

    // ── MENU ───────────────────────────────────────────────
    case 'm': case 'M':
      showMenuAfter = true;
      break;

    // ── SYSTEM INFO ────────────────────────────────────────
    case 'i': case 'I':
      printSysInfo();
      showMenuAfter = false;
      break;

    // ── VERBOSITY ──────────────────────────────────────────
    case 'v': case 'V': {
      Serial.println(F("  Verbosity: 0=Error  1=Info  2=Debug"));
      Serial.print(F("  Enter level: "));
      int lvl = readIntFromSerial(nullptr);
      if (lvl >= 0 && lvl <= 2) {
        setLogLevel((LogLevel)lvl);
        LOG_I("MAIN", "Log level → %d", lvl);
      } else {
        LOG_W("MAIN", "Invalid level (0-2 only).");
      }
      showMenuAfter = false;
      break;
    }

    // ── RESTART ────────────────────────────────────────────
    case 'r': case 'R':
      LOG_I("MAIN", "Restarting ESP32 in 500 ms...");
      delay(500);
      ESP.restart();
      break;

    default:
      // Silently ignore unknown input
      showMenuAfter = false;
      break;
  }

  if (showMenuAfter) {
    delay(300);
    printMenu();
  }
}
