/*
 * sniffer.h — Probe Request Sniffer  [v3]
 * ════════════════════════════════════════
 * v3 changes:
 *   ✅ enablePromiscuous() wrapper used (was raw API calls in v2)
 *   ✅ Wildcard vs Targeted probe counts tracked separately
 *   ✅ Deauth-burst rate limiter — logs once per burst, not per frame
 *      (prevents serial flood during an active deauth attack)
 *   ✅ Device table sorted by count descending in final report
 *   ✅ OUI vendor hint (first 3 bytes → common prefix lookup)
 *   ✅ Ring buffer drain moved to dedicated drain helper (DRY)
 *   ✅ All other logic unchanged — was already correct in v2
 */

#pragma once
#include "utils.h"

#define TAG_SNIFF "SNIFF"

// ─── Frame subtype constants ──────────────────────────────────
#define FT_PROBE_REQ  0x04
#define FT_PROBE_RSP  0x05
#define FT_BEACON     0x08
#define FT_AUTH       0x0B
#define FT_DEAUTH     0x0C
#define FT_DISASSOC   0x0A

// ═════════════════════════════════════════════════════════════
// OUI VENDOR HINT
// First 3 bytes of MAC → common manufacturer prefix.
// Only the most common chipset vendors included (keeps binary small).
// Returns nullptr if unrecognized (caller shows raw MAC instead).
// ═════════════════════════════════════════════════════════════
struct _OuiEntry { uint8_t oui[3]; const char* name; };
static const _OuiEntry _ouiTable[] = {
  {{0x00,0x0C,0xE7}, "Intel"},   {{0xF4,0xF5,0xDB}, "Intel"},
  {{0x34,0x02,0x86}, "Intel"},   {{0x8C,0xEC,0x4B}, "Intel"},
  {{0xD0,0x37,0x45}, "Intel"},   {{0xA4,0xC3,0xF0}, "Apple"},
  {{0xBC,0xD0,0x74}, "Apple"},   {{0xF0,0xD1,0xA9}, "Apple"},
  {{0x70,0x3A,0xCB}, "Apple"},   {{0x04,0xD3,0xB0}, "Espressif"},
  {{0xAC,0xD0,0x74}, "Espressif"},{{0xE8,0x6B,0xEA}, "Espressif"},
  {{0x84,0xCC,0xA8}, "Samsung"}, {{0xF8,0x04,0x2E}, "Samsung"},
  {{0x28,0xCC,0x01}, "Samsung"}, {{0x00,0x16,0xD4}, "Cisco"},
  {{0x00,0x1B,0x67}, "Cisco"},   {{0xFC,0x99,0x47}, "Qualcomm"},
  {{0x5C,0xA4,0x8A}, "Qualcomm"},{{0x00,0x21,0xFC}, "Mediatek"},
  {{0xEC,0x61,0x95}, "TP-Link"}, {{0xF0,0x9F,0xC2}, "Ubiquiti"},
};
static const char* _ouiLookup(const uint8_t* mac) {
  for (size_t i = 0; i < sizeof(_ouiTable)/sizeof(_ouiTable[0]); i++) {
    if (_ouiTable[i].oui[0] == mac[0] &&
        _ouiTable[i].oui[1] == mac[1] &&
        _ouiTable[i].oui[2] == mac[2]) return _ouiTable[i].name;
  }
  return nullptr;
}

// ═════════════════════════════════════════════════════════════
// DEVICE TABLE
// ═════════════════════════════════════════════════════════════
struct SniffedDevice {
  uint8_t  mac[6];
  char     lastSSID[33];  // Last probed targeted SSID (empty = wildcard only)
  int8_t   rssi;
  uint8_t  channel;
  uint32_t firstSeen;
  uint32_t lastSeen;
  uint32_t probeCount;    // Total probes from this device
  uint32_t wildcardCount; // How many were wildcard (broadcast) probes
};

static SniffedDevice _devTable[CFG_SNIFFER_MAX_DEVICES];
static int           _devCount = 0;

/*
 * _findOrAddDevice()
 * ──────────────────
 * Called from main loop only (NOT from ISR).
 * ssid = nullptr or empty → wildcard probe.
 */
static int _findOrAddDevice(const uint8_t* mac, const char* ssid,
                             int8_t rssi, uint8_t ch, bool isWildcard) {
  for (int i = 0; i < _devCount; i++) {
    if (macEqual(_devTable[i].mac, mac)) {
      _devTable[i].rssi       = rssi;
      _devTable[i].channel    = ch;
      _devTable[i].lastSeen   = millis();
      _devTable[i].probeCount++;
      if (isWildcard)
        _devTable[i].wildcardCount++;
      else if (ssid && strlen(ssid) > 0)
        strlcpy(_devTable[i].lastSSID, ssid, sizeof(_devTable[i].lastSSID));
      return i;
    }
  }
  if (_devCount >= CFG_SNIFFER_MAX_DEVICES) return -1;
  int i = _devCount++;
  memcpy(_devTable[i].mac, mac, 6);
  strlcpy(_devTable[i].lastSSID, (ssid && !isWildcard) ? ssid : "", 33);
  _devTable[i].rssi          = rssi;
  _devTable[i].channel       = ch;
  _devTable[i].firstSeen     = millis();
  _devTable[i].lastSeen      = millis();
  _devTable[i].probeCount    = 1;
  _devTable[i].wildcardCount = isWildcard ? 1 : 0;
  return i;
}

// ═════════════════════════════════════════════════════════════
// STATISTICS
// ═════════════════════════════════════════════════════════════
static struct {
  uint32_t probeReqTargeted;
  uint32_t probeReqWildcard;
  uint32_t probeRsp;
  uint32_t beacon;
  uint32_t auth;
  uint32_t deauth;
  uint32_t other;
  uint32_t total;
  uint32_t ringDropped;
} _sniffStats;

// ═════════════════════════════════════════════════════════════
// RING BUFFER (ISR → main loop)
// ═════════════════════════════════════════════════════════════
static RingBuffer<CFG_SNIFFER_RING_SIZE, CFG_SNIFFER_MAX_PKT_LEN> _sniffRing;

static void IRAM_ATTR _sniffISR(void* buf, wifi_promiscuous_pkt_type_t) {
  if (!buf) return;
  const wifi_promiscuous_pkt_t* pkt = (const wifi_promiscuous_pkt_t*)buf;
  if (pkt->rx_ctrl.sig_len < 10) return;
  if (!_sniffRing.push(pkt->payload, pkt->rx_ctrl.sig_len,
                       pkt->rx_ctrl.rssi, (uint8_t)pkt->rx_ctrl.channel))
    _sniffStats.ringDropped++;
}

// ═════════════════════════════════════════════════════════════
// DEAUTH BURST RATE LIMITER
// Prevents serial flood when an active deauth attack is nearby.
// Logs at most once per CFG_SNIFFER_DEAUTH_BATCH_MS.
// ═════════════════════════════════════════════════════════════
#ifndef CFG_SNIFFER_DEAUTH_BATCH_MS
#define CFG_SNIFFER_DEAUTH_BATCH_MS 2000
#endif

static uint32_t _lastDeauthLogMs    = 0;
static uint32_t _deauthBurstPending = 0;

static void _flushDeauthBurst() {
  if (_deauthBurstPending == 0) return;
  if (millis() - _lastDeauthLogMs >= (uint32_t)CFG_SNIFFER_DEAUTH_BATCH_MS) {
    Serial.printf("[!][DEAUTH BURST] %u deauth/disassoc frame(s) in last %ums\n",
      _deauthBurstPending, CFG_SNIFFER_DEAUTH_BATCH_MS);
    _deauthBurstPending = 0;
    _lastDeauthLogMs    = millis();
  }
}

// ═════════════════════════════════════════════════════════════
// PROCESS ONE PACKET ENTRY (main loop only)
// ═════════════════════════════════════════════════════════════
static void _processSniffEntry(const decltype(_sniffRing)::Entry& e) {
  const uint8_t* pl  = e.data;
  uint16_t       len = e.len;
  int8_t         rssi = e.rssi;
  uint8_t        ch   = e.channel;

  if (len < 24) return;

  uint8_t fc0   = pl[0];
  uint8_t ftype = (fc0 >> 2) & 0x03;
  uint8_t fsub  = (fc0 >> 4) & 0x0F;

  _sniffStats.total++;
  if (ftype != 0) return;   // Only management frames

  const uint8_t* sa = pl + 10;  // SA field

  switch (fsub) {
    // ── Probe Request ──────────────────────────────────────
    case FT_PROBE_REQ: {
      char ssid[33] = {0};
      bool isWild   = true;

      if (len > 26 && pl[24] == 0x00) {
        uint8_t slen = pl[25];
        if (slen > 0 && slen <= 32 && (uint32_t)(26 + slen) <= len) {
          memcpy(ssid, pl + 26, slen);
          ssid[slen] = '\0';
          isWild = false;
        }
      }

      if (isWild)
        _sniffStats.probeReqWildcard++;
      else
        _sniffStats.probeReqTargeted++;

      int  idx   = _findOrAddDevice(sa, ssid, rssi, ch, isWild);
      bool isNew = (idx >= 0 && _devTable[idx].probeCount == 1);

      char macStr[18]; macToStr(sa, macStr);
      const char* vendor = _ouiLookup(sa);
      char vendorBuf[14] = {0};
      if (vendor) snprintf(vendorBuf, sizeof(vendorBuf), " [%-9s]", vendor);

      if (!isWild) {
        Serial.printf("[PROBE] %s%s Ch:%2u RSSI:%4d → \"%s\"%s\n",
          macStr, vendorBuf, ch, rssi, ssid, isNew ? "  ★ NEW" : "");
      } else {
        // Only log wildcard probes for new devices to reduce noise
        if (isNew) {
          Serial.printf("[PROBE] %s%s Ch:%2u RSSI:%4d → (wildcard)  ★ NEW\n",
            macStr, vendorBuf, ch, rssi);
        }
      }
      break;
    }

    // ── Deauth / Disassoc ──────────────────────────────────
    case FT_DEAUTH:
    case FT_DISASSOC:
      _sniffStats.deauth++;
      _deauthBurstPending++;   // Rate-limited logging in main loop
      break;

    case FT_PROBE_RSP: _sniffStats.probeRsp++; break;
    case FT_BEACON:    _sniffStats.beacon++;   break;
    case FT_AUTH:      _sniffStats.auth++;     break;
    default:           _sniffStats.other++;    break;
  }
}

// Drain ring buffer — DRY helper called in multiple places
static void _drainSniffRing() {
  decltype(_sniffRing)::Entry e;
  while (_sniffRing.pop(e)) _processSniffEntry(e);
}

// ═════════════════════════════════════════════════════════════
// FINAL REPORT
// ═════════════════════════════════════════════════════════════
static void _printSniffSummary() {
  uint32_t totalProbe = _sniffStats.probeReqTargeted + _sniffStats.probeReqWildcard;

  Serial.println(F("\n╔═══════════════════════════ Sniffer Summary ════════════════════════╗"));
  Serial.printf ("║  Total packets captured : %-6u                                    ║\n", _sniffStats.total);
  Serial.printf ("║  Probe Requests (total) : %-6u  Targeted:%-6u  Wildcard:%-6u   ║\n",
    totalProbe, _sniffStats.probeReqTargeted, _sniffStats.probeReqWildcard);
  Serial.printf ("║  Probe Responses        : %-6u                                    ║\n", _sniffStats.probeRsp);
  Serial.printf ("║  Beacons                : %-6u                                    ║\n", _sniffStats.beacon);
  Serial.printf ("║  Deauth / Disassoc      : %-6u                                    ║\n", _sniffStats.deauth);
  Serial.printf ("║  Auth                   : %-6u                                    ║\n", _sniffStats.auth);
  Serial.printf ("║  Ring buffer dropped    : %-6u                                    ║\n", _sniffStats.ringDropped);
  Serial.printf ("║  Unique devices         : %-3d                                       ║\n", _devCount);
  Serial.println(F("╚═══════════════════════════════════════════════════════════════════════╝"));

  if (_devCount == 0) return;

  // ── Sort device table by probeCount descending ────────────
  // Simple insertion sort (N ≤ 50, acceptable)
  for (int i = 1; i < _devCount; i++) {
    SniffedDevice tmp = _devTable[i];
    int j = i - 1;
    while (j >= 0 && _devTable[j].probeCount < tmp.probeCount) {
      _devTable[j+1] = _devTable[j];
      j--;
    }
    _devTable[j+1] = tmp;
  }

  // ── Device table ──────────────────────────────────────────
  Serial.println(F("\n  # │ MAC               │ Vendor     │ Probes │Wild%│RSSI │Ch │ Last SSID"));
  Serial.println(F("  ──┼───────────────────┼────────────┼────────┼─────┼─────┼───┼───────────────────────────────"));
  for (int i = 0; i < _devCount; i++) {
    char m[18]; macToStr(_devTable[i].mac, m);
    const char* v = _ouiLookup(_devTable[i].mac);
    uint8_t wildPct = (_devTable[i].probeCount > 0)
      ? (uint8_t)(_devTable[i].wildcardCount * 100 / _devTable[i].probeCount) : 0;
    Serial.printf("  %2d│ %-17s │ %-10s │ %6u │%4u%%│ %4d│%3u│ %s\n",
      i+1, m, v ? v : "-",
      _devTable[i].probeCount, wildPct,
      _devTable[i].rssi, _devTable[i].channel,
      _devTable[i].lastSSID[0] ? _devTable[i].lastSSID : "(wildcard only)");
  }

  // ── JSON export ───────────────────────────────────────────
  Serial.println(F("\n// JSON export:"));
  Serial.println('[');
  for (int i = 0; i < _devCount; i++) {
    char m[18]; macToStr(_devTable[i].mac, m);
    const char* v = _ouiLookup(_devTable[i].mac);
    Serial.printf("  {\"mac\":\"%s\",\"vendor\":\"%s\",\"ssid\":\"%s\","
                  "\"probes\":%u,\"wildcard\":%u,\"rssi\":%d}%s\n",
      m, v ? v : "",
      _devTable[i].lastSSID[0] ? _devTable[i].lastSSID : "",
      _devTable[i].probeCount,
      _devTable[i].wildcardCount,
      _devTable[i].rssi,
      (i < _devCount-1) ? "," : "");
  }
  Serial.println(']');

  // ── Insights ──────────────────────────────────────────────
  if (_sniffStats.deauth > 10)
    Serial.println(F("\n  ⚠️  High deauth/disassoc count — possible deauth attack in range!"));
  if (_sniffStats.probeReqTargeted > _sniffStats.probeReqWildcard)
    Serial.println(F("  ℹ️  More targeted probes than wildcards — devices are actively seeking known APs."));
}

// ═════════════════════════════════════════════════════════════
// PUBLIC ENTRY POINT
// ═════════════════════════════════════════════════════════════
/*
 * probeSniffer()
 * ──────────────
 * Channel-hops 1→CFG_CHANNEL_MAX while capturing probe requests,
 * deauth events, and building a unique-device table.
 *
 * durationSec  : auto-stop after N seconds (0 = manual 's' only)
 * stopFlag     : caller's stop flag
 */
void probeSniffer(uint32_t durationSec, volatile bool* stopFlag) {
  memset(&_sniffStats, 0, sizeof(_sniffStats));
  memset(_devTable,    0, sizeof(_devTable));
  _devCount           = 0;
  _lastDeauthLogMs    = 0;
  _deauthBurstPending = 0;
  _sniffRing.reset();

  WiFi.mode(WIFI_STA);
  WiFi.disconnect(true);
  delay(80);
  setTxPower(CFG_TX_POWER);   // Set in STA mode

  if (!enablePromiscuous(WIFI_PROMIS_FILTER_MASK_MGMT, _sniffISR)) {
    LOG_E(TAG_SNIFF, "Failed to enable promiscuous mode!");
    return;
  }

  LOG_I(TAG_SNIFF, "Probe Sniffer started. Hop interval: %u ms", CFG_SNIFFER_HOP_MS);
  LOG_I(TAG_SNIFF, "New wildcard-only devices shown once. All targeted probes shown.");
  if (durationSec > 0)
    LOG_I(TAG_SNIFF, "Auto-stop in %u s. Send 's' to stop early.", durationSec);
  else
    LOG_I(TAG_SNIFF, "Send 's' to stop.");

  uint32_t startMs   = millis();
  uint32_t lastPrint = millis();
  uint8_t  ch        = CFG_CHANNEL_MIN;

  while (!(*stopFlag)) {
    setChannel(ch);
    ch = (uint8_t)((ch % CFG_CHANNEL_MAX) + 1);

    _drainSniffRing();
    _flushDeauthBurst();

    if (durationSec > 0 && (millis() - startMs) >= durationSec * 1000UL) break;

    if (millis() - lastPrint >= 5000UL) {
      LOG_I(TAG_SNIFF, "Probes: T=%u W=%u | Devices: %d | Deauth: %u | Dropped: %u",
        _sniffStats.probeReqTargeted, _sniffStats.probeReqWildcard,
        _devCount, _sniffStats.deauth, _sniffStats.ringDropped);
      lastPrint = millis();
    }

    checkStopSerial(stopFlag);
    vTaskDelay(pdMS_TO_TICKS(CFG_SNIFFER_HOP_MS));
  }

  _drainSniffRing();
  _flushDeauthBurst();

  disablePromiscuous();
  _printSniffSummary();
  LOG_I(TAG_SNIFF, "Stopped.");
}
