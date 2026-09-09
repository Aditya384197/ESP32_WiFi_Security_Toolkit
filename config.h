/*
 * config.h — Centralized Configuration  [v3]
 * ════════════════════════════════════════════
 * सभी tunable parameters एक जगह।
 * Compile-time constants — runtime पर नहीं बदलते।
 */

#pragma once

// ─── Serial ──────────────────────────────────────────────────
#define CFG_SERIAL_BAUD          115200
#define CFG_SERIAL_TIMEOUT_MS    15000  // parseInt() / readStringUntil() timeout

// ─── Wi-Fi Channels ──────────────────────────────────────────
#define CFG_CHANNEL_MIN          1
#define CFG_CHANNEL_MAX          13     // India/EU: 1-13  |  US: change to 11
#define CFG_CHANNEL_HOP_DWELL_MS 500

// ─── Scanner ─────────────────────────────────────────────────
#define CFG_SCAN_SHOW_HIDDEN     true
#define CFG_SCAN_MAX_NETWORKS    40     // Cap display/use to this many results

// ─── TX Power ────────────────────────────────────────────────
// Unit: 0.25 dBm. Range 0-84. 72 = 18 dBm (balanced); 84 = 21 dBm (max).
#define CFG_TX_POWER             72

// ─── Probe Sniffer ───────────────────────────────────────────
#define CFG_SNIFFER_MAX_DEVICES  50
#define CFG_SNIFFER_HOP_MS       200
#define CFG_SNIFFER_RING_SIZE    64
#define CFG_SNIFFER_MAX_PKT_LEN  400

// ─── Packet Analyzer ─────────────────────────────────────────
#define CFG_PA_RING_SIZE         64
#define CFG_PA_MAX_PKT_LEN       400
#define CFG_PA_STATS_EVERY_MS    10000

// ─── Watchdog ────────────────────────────────────────────────
// 1 tick = 1ms; every loop iteration yields to FreeRTOS scheduler + feeds WDT
#define CFG_WDT_YIELD_TICKS      pdMS_TO_TICKS(1)
