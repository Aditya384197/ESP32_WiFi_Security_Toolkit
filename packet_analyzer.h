/*
 * packet_analyzer.h — Passive 802.11 Packet Analyzer  [v3.1]
 * ══════════════════════════════════════════════════════════════════
 * v3.1 changes:
 *   ✅ Passive EAPOL frame counting only
 *   ✅ No credential, PMKID, or handshake material is extracted/exported
 *   ✅ RSSI extrema are initialized correctly
 *   ✅ Ring-buffer bounds are checked before parsing
 */

#pragma once
#include "utils.h"

#define TAG_PA "PKTANAL"

// ─── Verbosity ────────────────────────────────────────────────
// 0 = silent (stats only), 1 = Management [default],
// 2 = Mgmt+Data, 3 = All frames
static uint8_t _paVerbosity = 1;

// ─── Frame subtype name tables ────────────────────────────────
static const char* const _mgmtSubNames[16] = {
  "Assoc-Req", "Assoc-Rsp", "ReAssoc-Req", "ReAssoc-Rsp",
  "Probe-Req", "Probe-Rsp", "Rsrv-6",      "Rsrv-7",
  "Beacon",    "ATIM",      "Disassoc",    "Auth",
  "Deauth",    "Action",    "Rsrv-14",     "Rsrv-15"
};
static const char* const _ctrlSubNames[16] = {
  "Rsrv-0",  "Rsrv-1",  "Rsrv-2",  "Rsrv-3",
  "Rsrv-4",  "Rsrv-5",  "Rsrv-6",  "Rsrv-7",
  "BA-Req",  "BlockAck","PS-Poll",  "RTS",
  "CTS",     "ACK",     "CF-End",   "CF-End+CF-Ack"
};
static const char* const _dataSubNames[16] = {
  "Data",      "Data+CF-Ack", "Data+CF-Poll", "Data+CF-Ack+Poll",
  "Null",      "CF-Ack",      "CF-Poll",       "CF-Ack+Poll",
  "QoS-Data",  "QoS+CF-Ack",  "QoS+CF-Poll",  "QoS+CF-Ack+Poll",
  "QoS-Null",  "Rsrv-13",     "QoS-CF-Poll",  "Rsrv-15"
};

static inline const char* _subName(uint8_t ft, uint8_t fs) {
  switch(ft) { case 0:return _mgmtSubNames[fs&0x0F]; case 1:return _ctrlSubNames[fs&0x0F]; case 2:return _dataSubNames[fs&0x0F]; default:return "Ext"; }
}
static inline const char* _typeName(uint8_t ft) {
  switch(ft) { case 0:return "MGMT"; case 1:return "CTRL"; case 2:return "DATA"; default:return "EXT "; }
}

// ─── Statistics ───────────────────────────────────────────────
static struct {
  uint32_t total, mgmt, ctrl, data, ext;
  uint32_t mgmtSubtype[16];
  uint32_t perChannel[14];
  int32_t  rssiSum;
  int8_t   rssiMin, rssiMax;
  uint32_t ringDropped;
  uint32_t eapolFrames;
} _paStats;

// ─── Ring buffer ──────────────────────────────────────────────
static RingBuffer<CFG_PA_RING_SIZE, CFG_PA_MAX_PKT_LEN> _paRing;

static void IRAM_ATTR _paISR(void* buf, wifi_promiscuous_pkt_type_t) {
  if (!buf) return;
  const wifi_promiscuous_pkt_t* pkt = (const wifi_promiscuous_pkt_t*)buf;
  if (pkt->rx_ctrl.sig_len < 4) return;
  if (!_paRing.push(pkt->payload, pkt->rx_ctrl.sig_len,
                    pkt->rx_ctrl.rssi, (uint8_t)pkt->rx_ctrl.channel))
    _paStats.ringDropped++;
}

// ══════════════════════════════════════════════════════════════
// EAPOL / PMKID PARSER
// ══════════════════════════════════════════════════════════════

/*
 * _parseEAPOL()
 * ─────────────
 * Called when an EAPOL frame is detected inside a Data frame.
 *
 * PMKID attack (Jens Steube, 2018):
 *   PMKID = HMAC-SHA1-128(PMK, "PMK Name" || AP_MAC || Client_MAC)
 *   It is transmitted by the AP in EAPOL Message 1 (Key Info: Pairwise,
 *   Ack, no MIC, no Secure) inside an RSN IE in the Key Data field.
 *
 * hashcat mode 22000 format:
 *   WPA*01*<PMKID>*<AP_MAC>*<STA_MAC>*<SSID_HEX>***
 */
#if 0
static void _parseEAPOL(const uint8_t* pl, uint16_t len,
                         uint16_t eapolOff) {
  // EAPOL Header: Version(1) Type(1) Length(2)
  if (len < eapolOff + 4) return;
  uint8_t  eType = pl[eapolOff + 1];
  if (eType != 3) return;           // 3 = EAPOL-Key (not EAP, Start, etc.)

  uint16_t kOff = eapolOff + 4;    // Start of EAPOL-Key body

  // EAPOL-Key body layout (RSN, Descriptor Type 2):
  //  DescType(1) KeyInfo(2) KeyLen(2) Replay(8) Nonce(32)
  //  IV(16) RSC(8) ID(8) MIC(16) DataLen(2) = 95 bytes before KeyData
  if (len < kOff + 99) return;

  uint8_t  descType = pl[kOff];
  if (descType != 2 && descType != 254) return; // 2=RSN, 254=WPA

  uint16_t keyInfo  = ((uint16_t)pl[kOff+1] << 8) | pl[kOff+2];
  bool     pairwise = (keyInfo >> 3) & 1;
  bool     install  = (keyInfo >> 6) & 1;
  bool     ack      = (keyInfo >> 7) & 1;
  bool     mic      = (keyInfo >> 8) & 1;
  bool     secure   = (keyInfo >> 9) & 1;

  uint16_t keyDataLen = ((uint16_t)pl[kOff+97] << 8) | pl[kOff+98];
  uint16_t kdOff      = kOff + 99;

  // ── Message 2: STA→AP, MIC=1, Ack=0, Pairwise=1, Secure=0 ──
  if (pairwise && !ack && mic && !secure) {
    _paStats.handshakeMsg2++;
    const uint8_t* staMac = pl + 10; // SA
    const uint8_t* apMac  = pl + 4;  // DA
    char sStr[18], aStr[18];
    macToStr(staMac, sStr);
    macToStr(apMac,  aStr);
    Serial.printf("[EAPOL] Msg2 (Handshake) STA:%s → AP:%s\n", sStr, aStr);
    return;
  }

  // ── Message 1: AP→STA, Pairwise=1, Ack=1, MIC=0, Secure=0 ──
  if (!(pairwise && ack && !mic && !secure)) return;
  if (keyDataLen == 0 || len < kdOff + keyDataLen) return;

  const uint8_t* apMac  = pl + 10; // SA (AP sent Msg1)
  const uint8_t* staMac = pl + 4;  // DA (STA receives Msg1)
  char aStr[18], sStr[18];
  macToStr(apMac,  aStr);
  macToStr(staMac, sStr);

  // ── Parse Key Data for RSN IE (Tag 0x30) ─────────────────
  uint16_t i = kdOff;
  while (i < kdOff + keyDataLen - 2) {
    uint8_t  tag  = pl[i];
    uint8_t  tLen = pl[i+1];
    uint16_t end  = i + 2 + tLen;

    if (tag == 0xDD && tLen >= 4) {
      // Vendor Specific: skip gracefully
    }

    if (tag == 0x30 && tLen >= 20 && end <= kdOff + keyDataLen) {
      // RSN IE found — parse PMKID List
      uint16_t p = i + 2;              // Points to RSN body start

      // Version(2)
      if (p + 2 > end) goto next_ie;
      p += 2;

      // Group Cipher Suite(4)
      if (p + 4 > end) goto next_ie;
      p += 4;

      // Pairwise Cipher Suite Count(2) + Suites
      if (p + 2 > end) goto next_ie;
      uint16_t pwCnt = (uint16_t)pl[p] | ((uint16_t)pl[p+1] << 8);
      p += 2 + pwCnt * 4;

      // AKM Suite Count(2) + Suites
      if (p + 2 > end) goto next_ie;
      uint16_t akmCnt = (uint16_t)pl[p] | ((uint16_t)pl[p+1] << 8);
      p += 2 + akmCnt * 4;

      // RSN Capabilities(2)
      if (p + 2 > end) goto next_ie;
      p += 2;

      // PMKID Count(2)
      if (p + 2 > end) goto next_ie;
      uint16_t pmkidCnt = (uint16_t)pl[p] | ((uint16_t)pl[p+1] << 8);
      p += 2;

      if (pmkidCnt > 0 && p + 16 <= end) {
        // ★ PMKID found ★
        _paStats.pmkidFound++;

        // Strip colons from MAC for hashcat
        char aHex[13], sHex[13];
        snprintf(aHex, 13, "%02X%02X%02X%02X%02X%02X",
          apMac[0],apMac[1],apMac[2],apMac[3],apMac[4],apMac[5]);
        snprintf(sHex, 13, "%02X%02X%02X%02X%02X%02X",
          staMac[0],staMac[1],staMac[2],staMac[3],staMac[4],staMac[5]);

        Serial.println(F("\n╔══════════════════════════════════════════════════════╗"));
        Serial.println(F("║   ★★★  PMKID CAPTURED  ★★★                          ║"));
        Serial.println(F("╠══════════════════════════════════════════════════════╣"));
        Serial.printf ("║  AP  : %s                          ║\n", aStr);
        Serial.printf ("║  STA : %s                          ║\n", sStr);
        Serial.print  (F("║  PMKID: "));
        for (int k = 0; k < 16; k++) Serial.printf("%02X", pl[p+k]);
        Serial.println(F("  ║"));
        Serial.println(F("╠══════════════════════════════════════════════════════╣"));
        Serial.println(F("║  hashcat -m 22000 hash.hc22000 wordlist.txt          ║"));
        Serial.print  (F("║  WPA*01*"));
        for (int k = 0; k < 16; k++) Serial.printf("%02x", pl[p+k]);
        Serial.printf("*%s*%s***\n", aHex, sHex);
        Serial.println(F("╚══════════════════════════════════════════════════════╝\n"));
        goto done;
      }
    }

    next_ie:
    if (tLen == 0) break;           // Prevent infinite loop on malformed IE
    i = end;
  }
  done:;
}

#endif

// ─── EAPOL detection inside 802.11 Data frames ────────────────
static void _checkForEAPOL(const uint8_t* pl, uint16_t len, uint8_t fsub) {
  // 802.11 Data frame header length:
  //   Basic: 24 bytes, +4 for 4-address, +2 for QoS
  bool toDS   = (pl[1] >> 0) & 1;
  bool fromDS = (pl[1] >> 1) & 1;
  uint16_t hdrLen = 24;
  if (toDS && fromDS) hdrLen += 4;           // 4-address frame (WDS)
  if ((fsub & 0x08) && !(fsub & 0x04))       // QoS subtype (not null)
    hdrLen += 2;

  // Minimum: header + LLC/SNAP(8) + EAPOL-header(4)
  if (len < hdrLen + 12) return;

  // LLC/SNAP: AA AA 03 00 00 00 88 8E
  const uint8_t* llc = pl + hdrLen;
  if (llc[0] != 0xAA || llc[1] != 0xAA ||
      llc[2] != 0x03 ||
      llc[3] != 0x00 || llc[4] != 0x00 || llc[5] != 0x00 ||
      llc[6] != 0x88 || llc[7] != 0x8E) return;

  _paStats.eapolFrames++;
  // Count EAPOL frames only. Do not parse or export credential material.
}

// ─── Process one ring-buffer entry ───────────────────────────
static void _processPaEntry(const decltype(_paRing)::Entry& e) {
  const uint8_t* pl  = e.data;
  uint16_t       len = e.len;
  int8_t         rssi = e.rssi;
  uint8_t        ch   = e.channel;

  if (len < 4) return;

  uint8_t fc0   = pl[0];
  uint8_t ftype = (fc0 >> 2) & 0x03;
  uint8_t fsub  = (fc0 >> 4) & 0x0F;

  // ── Stats ─────────────────────────────────────────────────
  _paStats.total++;
  _paStats.rssiSum += rssi;
  if (rssi < _paStats.rssiMin) _paStats.rssiMin = rssi;
  if (rssi > _paStats.rssiMax) _paStats.rssiMax = rssi;
  if (ch >= 1 && ch <= 13)    _paStats.perChannel[ch]++;

  switch (ftype) {
    case 0: _paStats.mgmt++; _paStats.mgmtSubtype[fsub & 0x0F]++; break;
    case 1: _paStats.ctrl++; break;
    case 2:
      _paStats.data++;
      // ── EAPOL check — always, regardless of verbosity ────
      _checkForEAPOL(pl, len, fsub);
      break;
    default: _paStats.ext++; break;
  }

  // ── Verbosity filter ─────────────────────────────────────
  if (_paVerbosity == 0) return;
  if (_paVerbosity == 1 && ftype != 0) return;
  if (_paVerbosity == 2 && ftype == 1) return;

  // ── Print ─────────────────────────────────────────────────
  if (len < 24) {
    Serial.printf("[PA][%4s][%-14s] len:%3u  RSSI:%4d  ch:%2u\n",
      _typeName(ftype), _subName(ftype, fsub), len, rssi, ch);
    return;
  }

  const uint8_t* da    = pl + 4;
  const uint8_t* sa    = pl + 10;
  const uint8_t* bssid = pl + 16;
  char daS[18], saS[18], bsS[18];
  macToStr(da, daS); macToStr(sa, saS); macToStr(bssid, bsS);

  // SSID extraction (Beacon / Probe-Req / Probe-Rsp)
  char ssidBuf[38] = {0};
  if (ftype == 0 && (fsub == 0x08 || fsub == 0x04 || fsub == 0x05)) {
    if (len > 26 && pl[24] == 0x00) {
      uint8_t sLen = pl[25];
       if (sLen > 0 && sLen <= 32 && (uint32_t)(26 + sLen) <= len) {
        snprintf(ssidBuf, sizeof(ssidBuf), "  SSID:\"%.*s\"", (int)sLen, pl+26);
      }
    }
  }

  // Reason code (Deauth / Disassoc)
  char reasonBuf[26] = {0};
  if (ftype == 0 && (fsub == 0x0C || fsub == 0x0A)) {
    uint16_t rc = (len >= 26) ? (uint16_t)(pl[24] | (pl[25] << 8)) : 0;
    snprintf(reasonBuf, sizeof(reasonBuf), "  Reason:%u", rc);
  }

  Serial.printf("[PA][%4s][%-14s] %s→%s BSSID:%s RSSI:%4d len:%3u ch:%2u%s%s\n",
    _typeName(ftype), _subName(ftype, fsub),
    saS, daS, bsS, rssi, len, ch, ssidBuf, reasonBuf);
}

// ─── Final statistics ─────────────────────────────────────────
static void _printPaStats() {
  int32_t avgRssi = (_paStats.total > 0)
    ? (int32_t)(_paStats.rssiSum / (int32_t)_paStats.total) : 0;
  int8_t rMin = (_paStats.rssiMin == INT8_MAX) ? 0 : _paStats.rssiMin;

  Serial.println(F("\n╔══════════════════════════════════════════════════════╗"));
  Serial.println(F("║         Packet Analyzer — Final Report               ║"));
  Serial.println(F("╠══════════════════════════════════════════════════════╣"));
  Serial.printf ("║  Total          : %-6u                             ║\n", _paStats.total);
  Serial.printf ("║  Management     : %-6u                             ║\n", _paStats.mgmt);
  Serial.printf ("║  Control        : %-6u                             ║\n", _paStats.ctrl);
  Serial.printf ("║  Data           : %-6u                             ║\n", _paStats.data);
  Serial.printf ("║  Extension      : %-6u                             ║\n", _paStats.ext);
  Serial.printf ("║  Ring dropped   : %-6u                             ║\n", _paStats.ringDropped);
  Serial.println(F("╠══════════════════════════════════════════════════════╣"));
  Serial.printf ("║  RSSI min/avg/max: %4d / %4d / %4d dBm          ║\n", rMin, avgRssi, _paStats.rssiMax);
  Serial.println(F("╠══════════════════════════════════════════════════════╣"));
  Serial.printf ("║  ★ EAPOL frames : %-6u                             ║\n", _paStats.eapolFrames);
  Serial.println(F("║  EAPOL payloads  : counted only; no credentials parsed ║"));
  Serial.println(F("╠══════════════════════════════════════════════════════╣"));
  Serial.println(F("║  Management subtypes:                                ║"));
  for (int i = 0; i < 16; i++)
    if (_paStats.mgmtSubtype[i] > 0)
      Serial.printf("║    %-14s : %-6u                          ║\n",
        _mgmtSubNames[i], _paStats.mgmtSubtype[i]);
  Serial.println(F("╠══════════════════════════════════════════════════════╣"));
  Serial.println(F("║  Packets per channel:                                ║"));
  for (int i = 1; i <= CFG_CHANNEL_MAX; i++)
    if (_paStats.perChannel[i] > 0)
      Serial.printf("║    Ch %2d : %-6u                                  ║\n",
        i, _paStats.perChannel[i]);
  Serial.println(F("╚══════════════════════════════════════════════════════╝"));

  // JSON export
  Serial.println(F("\n// JSON export:"));
  Serial.printf("{\"total\":%u,\"mgmt\":%u,\"ctrl\":%u,\"data\":%u,"
    "\"eapol\":%u,"
    "\"rssi\":{\"min\":%d,\"avg\":%d,\"max\":%d}}\n",
    _paStats.total,_paStats.mgmt,_paStats.ctrl,_paStats.data,
    _paStats.eapolFrames,
    rMin,avgRssi,_paStats.rssiMax);
}

/*
 * packetAnalyzer()
 * ────────────────
 * Listens on `channel` for `durationSec` seconds (0 = until 's').
 * EAPOL counting runs regardless of verbosity setting.
 * Verbosity controls Management/Data frame print output only.
 */
void packetAnalyzer(uint8_t channel, uint32_t durationSec, volatile bool* stopFlag) {
  memset(&_paStats, 0, sizeof(_paStats));
  _paStats.rssiMin = INT8_MAX;
  _paStats.rssiMax = INT8_MIN;
  _paRing.reset();
  _paVerbosity = 1;

  WiFi.mode(WIFI_STA);
  WiFi.disconnect(true);
  delay(80);
  setTxPower(CFG_TX_POWER);

  // Management and data frames are observed for passive statistics.
  if (!enablePromiscuous(
        WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA,
        _paISR)) {
    LOG_E(TAG_PA, "Failed to enable promiscuous mode!");
    return;
  }
  if (!setChannel(channel)) { disablePromiscuous(); return; }

  LOG_I(TAG_PA, "Analyzer on ch %u. Verbosity: '0'-'3'. 's'=stop.", channel);
  LOG_I(TAG_PA, "Passive mode: EAPOL frames are counted only.");
  if (durationSec > 0) LOG_I(TAG_PA, "Auto-stop in %u s.", durationSec);

  uint32_t startMs   = millis();
  uint32_t lastStats = millis();

  while (!(*stopFlag)) {
    decltype(_paRing)::Entry entry;
    while (_paRing.pop(entry)) _processPaEntry(entry);

    if (durationSec > 0 && (millis()-startMs) >= durationSec*1000UL) break;

    if (millis()-lastStats >= (uint32_t)CFG_PA_STATS_EVERY_MS) {
      LOG_I(TAG_PA, "Total:%u Mgmt:%u Data:%u EAPOL:%u Dropped:%u",
        _paStats.total,_paStats.mgmt,_paStats.data,
        _paStats.eapolFrames,_paStats.ringDropped);
      lastStats = millis();
    }

    if (Serial.available()) {
      char c = Serial.read();
      switch(c) {
        case 's': case 'S': *stopFlag = true; break;
        case '0': _paVerbosity=0; LOG_I(TAG_PA,"Silent (stats+EAPOL count only)"); break;
        case '1': _paVerbosity=1; LOG_I(TAG_PA,"Mgmt frames only");          break;
        case '2': _paVerbosity=2; LOG_I(TAG_PA,"Mgmt + Data");               break;
        case '3': _paVerbosity=3; LOG_I(TAG_PA,"All frames (verbose)");      break;
      }
    }
    vTaskDelay(CFG_WDT_YIELD_TICKS);
  }

  // Drain remaining
  { decltype(_paRing)::Entry e; while(_paRing.pop(e)) _processPaEntry(e); }

  disablePromiscuous();
  _printPaStats();
  LOG_I(TAG_PA, "Stopped.");
}
