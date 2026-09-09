/*
 * utils.h — Common Utilities  [v3]
 * ══════════════════════════════════
 * v3.1 changes:
 *   ✅ Raw 802.11 transmission is fail-closed and disabled
 *   ✅ Ring buffer DEPTH uses uint8_t — safe up to 255 depth
 *   ✅ setLogLevel() is exposed as inline
 */

#pragma once
#include <Arduino.h>
#include <WiFi.h>
#include "esp_wifi.h"
#include "esp_rom_sys.h"
#include "config.h"

// ══════════════════════════════════════════════════════════════
// 1.  LOG LEVEL SYSTEM
// ══════════════════════════════════════════════════════════════

typedef enum : uint8_t {
  LOG_DEBUG = 0,
  LOG_INFO  = 1,
  LOG_WARN  = 2,
  LOG_ERROR = 3
} LogLevel;

static LogLevel currentLogLevel = LOG_INFO;

inline void setLogLevel(LogLevel lvl) { currentLogLevel = lvl; }

static inline uint32_t _tsMs() { return millis(); }

#define LOG_D(tag, fmt, ...)  do { if (currentLogLevel <= LOG_DEBUG) Serial.printf("[%7u][DBG][%-8s] " fmt "\n", _tsMs(), tag, ##__VA_ARGS__); } while(0)
#define LOG_I(tag, fmt, ...)  do { if (currentLogLevel <= LOG_INFO)  Serial.printf("[%7u][INF][%-8s] " fmt "\n", _tsMs(), tag, ##__VA_ARGS__); } while(0)
#define LOG_W(tag, fmt, ...)  do { if (currentLogLevel <= LOG_WARN)  Serial.printf("[%7u][WRN][%-8s] " fmt "\n", _tsMs(), tag, ##__VA_ARGS__); } while(0)
#define LOG_E(tag, fmt, ...)  do { if (currentLogLevel <= LOG_ERROR) Serial.printf("[%7u][ERR][%-8s] " fmt "\n", _tsMs(), tag, ##__VA_ARGS__); } while(0)

// ══════════════════════════════════════════════════════════════
// 2.  Raw 802.11 transmission is intentionally disabled
// ══════════════════════════════════════════════════════════════

/*
 * The original toolkit exposed a raw 802.11 TX wrapper used by disruptive
 * packet injection modules. Those modules are not part of this build.
 * Keep a fail-closed compatibility shim so an accidental call cannot
 * transmit frames.
 */
static inline bool wifi80211Tx(wifi_interface_t iface,
                                const uint8_t*  buf,
                                int             len,
                                bool            enSysBuf = false) {
  (void)iface;
  (void)buf;
  (void)len;
  (void)enSysBuf;
  LOG_W("TX", "Raw 802.11 transmission is disabled in this build.");
  return false;
}

// ══════════════════════════════════════════════════════════════
// 3.  SERIAL INPUT HELPERS
// ══════════════════════════════════════════════════════════════

static inline void serialFlush() {
  while (Serial.available()) Serial.read();
}

/*
 * readIntFromSerial()
 * ───────────────────
 * Blocks until an integer is typed, then returns it.
 * Yields to FreeRTOS every tick so WDT is fed and stopFlag is honoured.
 * Returns -1 immediately if stopFlag is already set.
 */
static int readIntFromSerial(volatile bool* stopFlag = nullptr) {
  if (stopFlag && *stopFlag) return -1;

  while (!Serial.available()) {
    vTaskDelay(CFG_WDT_YIELD_TICKS);
    if (stopFlag && *stopFlag) return -1;
  }
  int val = Serial.parseInt();
  serialFlush();
  return val;
}

/*
 * readLineFromSerial()
 * ────────────────────
 * Reads a trimmed String (up to newline).
 * Respects stopFlag and WDT.
 */
static String readLineFromSerial(volatile bool* stopFlag = nullptr) {
  if (stopFlag && *stopFlag) return String();

  while (!Serial.available()) {
    vTaskDelay(CFG_WDT_YIELD_TICKS);
    if (stopFlag && *stopFlag) return String();
  }
  String s = Serial.readStringUntil('\n');
  s.trim();
  serialFlush();
  return s;
}

/*
 * checkStopSerial()
 * ─────────────────
 * Non-blocking: returns true and sets *stopFlag if 's'/'S' is in the RX buffer.
 */
static inline bool checkStopSerial(volatile bool* stopFlag) {
  if (!Serial.available()) return false;
  char c = Serial.read();
  if (c == 's' || c == 'S') {
    if (stopFlag) *stopFlag = true;
    return true;
  }
  return false;
}

// ══════════════════════════════════════════════════════════════
// 4.  MAC ADDRESS HELPERS
// ══════════════════════════════════════════════════════════════

static inline void macToStr(const uint8_t* mac, char* buf /* 18 bytes */) {
  snprintf(buf, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/*
 * randomMac() — generates a locally-administered unicast MAC.
 * Bit 0 of byte 0 = 0 (unicast)
 * Bit 1 of byte 0 = 1 (locally administered)
 * Operator precedence: & > | in C, so ((x & 0xFE) | 0x02) is explicit.
 */
static void randomMac(uint8_t* mac) {
  uint32_t r1 = esp_random();
  uint32_t r2 = esp_random();
  mac[0] = (uint8_t)(((r1 >>  0) & 0xFE) | 0x02);  // unicast + locally-admin
  mac[1] = (uint8_t)((r1 >>  8) & 0xFF);
  mac[2] = (uint8_t)((r1 >> 16) & 0xFF);
  mac[3] = (uint8_t)((r2 >>  0) & 0xFF);
  mac[4] = (uint8_t)((r2 >>  8) & 0xFF);
  mac[5] = (uint8_t)((r2 >> 16) & 0xFF);
}

static inline bool macEqual(const uint8_t* a, const uint8_t* b) {
  return memcmp(a, b, 6) == 0;
}

// ══════════════════════════════════════════════════════════════
// 5.  WIFI HELPERS
// ══════════════════════════════════════════════════════════════

static bool setChannel(uint8_t ch) {
  if (ch < CFG_CHANNEL_MIN || ch > CFG_CHANNEL_MAX) {
    LOG_W("CH", "Invalid channel %u (valid: %u-%u)", ch, CFG_CHANNEL_MIN, CFG_CHANNEL_MAX);
    return false;
  }
  esp_err_t err = esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
  if (err != ESP_OK) {
    LOG_W("CH", "set_channel(%u) failed: %s", ch, esp_err_to_name(err));
    return false;
  }
  return true;
}

static bool enablePromiscuous(uint32_t filterMask, wifi_promiscuous_cb_t cb) {
  wifi_promiscuous_filter_t f = { .filter_mask = filterMask };
  esp_err_t e1 = esp_wifi_set_promiscuous_filter(&f);
  esp_err_t e2 = esp_wifi_set_promiscuous_rx_cb(cb);
  esp_err_t e3 = esp_wifi_set_promiscuous(true);
  if (e1 != ESP_OK || e2 != ESP_OK || e3 != ESP_OK) {
    LOG_E("PROMISC", "Enable failed: filter=%s cb=%s enable=%s",
      esp_err_to_name(e1), esp_err_to_name(e2), esp_err_to_name(e3));
    return false;
  }
  return true;
}

static void disablePromiscuous() {
  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(nullptr);
}

/*
 * setTxPower() — sets maximum TX power.
 * MUST be called while in STA mode (or before switching to AP mode).
 * In AP mode on some firmware versions, this may have no effect.
 */
static void setTxPower(int8_t power) {
  if (power < 0)  power = 0;
  if (power > 84) power = 84;
  esp_err_t err = esp_wifi_set_max_tx_power(power);
  if (err != ESP_OK)
    LOG_W("TXPWR", "set_max_tx_power(%d) failed: %s", power, esp_err_to_name(err));
}

// ══════════════════════════════════════════════════════════════
// 6.  ENCRYPTION TYPE STRING
// ══════════════════════════════════════════════════════════════

static const char* encryptionStr(wifi_auth_mode_t mode) {
  switch (mode) {
    case WIFI_AUTH_OPEN:             return "OPEN";
    case WIFI_AUTH_WEP:              return "WEP";
    case WIFI_AUTH_WPA_PSK:          return "WPA";
    case WIFI_AUTH_WPA2_PSK:         return "WPA2";
    case WIFI_AUTH_WPA_WPA2_PSK:     return "WPA/WPA2";
    case WIFI_AUTH_WPA2_ENTERPRISE:  return "WPA2-ENT";
    case WIFI_AUTH_WPA3_PSK:         return "WPA3";
    case WIFI_AUTH_WPA2_WPA3_PSK:    return "WPA2/WPA3";
    default:                         return "UNKNOWN";
  }
}

// ══════════════════════════════════════════════════════════════
// 7.  RING BUFFER — Single-Producer / Single-Consumer, ISR-safe
// ══════════════════════════════════════════════════════════════

/*
 * RingBuffer<DEPTH, MAX_LEN>
 * ──────────────────────────
 * Producer: promiscuous ISR (IRAM_ATTR).
 * Consumer: main loop / FreeRTOS task (non-ISR).
 *
 * Thread-safety: safe because:
 *   • head is written ONLY by the ISR (single writer).
 *   • tail is written ONLY by the consumer (single writer).
 *   • On ESP32 Xtensa, aligned 32-bit (and smaller) reads/writes
 *     are single-instruction → effectively atomic. Both head and
 *     tail are uint8_t in an aligned struct.
 *   • We commit head AFTER writing data (release-like ordering),
 *     which prevents the consumer seeing a partial write.
 *
 * ringDropped in ISR: uint32_t increment on ESP32 is a single
 * `s32i` instruction → no partial read possible; missed counts
 * are acceptable (counter is informational only).
 *
 * DEPTH must be ≤ 255 (uint8_t index arithmetic).
 * MAX_LEN must be ≤ 65535 (uint16_t length field).
 */
template<uint8_t DEPTH, uint16_t MAX_LEN>
struct RingBuffer {
  struct Entry {
    uint8_t  data[MAX_LEN];
    uint16_t len;
    int8_t   rssi;
    uint8_t  channel;
  };

  Entry            buf[DEPTH];
  volatile uint8_t head = 0;   // Written by ISR
  volatile uint8_t tail = 0;   // Written by consumer

  /* Push from ISR. Returns false (drop) if full. */
  IRAM_ATTR bool push(const uint8_t* data, uint16_t len,
                      int8_t rssi, uint8_t ch) {
    uint8_t h    = head;
    uint8_t next = (uint8_t)((h + 1) % DEPTH);
    if (next == tail) return false;           // Full — drop newest

    uint16_t copy = (len > MAX_LEN) ? MAX_LEN : len;
    memcpy(buf[h].data, data, copy);
    buf[h].len     = copy;
    buf[h].rssi    = rssi;
    buf[h].channel = ch;
    head = next;                              // Commit (single store — atomic)
    return true;
  }

  /* Pop from consumer. Returns false if empty. */
  bool pop(Entry& out) {
    uint8_t t = tail;
    if (t == head) return false;
    out  = buf[t];
    tail = (uint8_t)((t + 1) % DEPTH);
    return true;
  }

  bool empty() const { return head == tail; }
  void reset()       { head = 0; tail = 0;  }
};
