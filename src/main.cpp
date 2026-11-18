/*
 * BT_Beacon - Apple Find My (Offline Finding) beacon on a Seeed XIAO ESP32-C3
 *
 * Broadcasts the 31-byte Apple "Offline Finding" frame that a real AirTag sends,
 * but rotates through a ring of pre-generated keys every BEACON_ROTATE_SECONDS
 * (default 15 min), like an AirTag does. The BLE random address is derived from
 * the key, so it rotates too.
 *
 * Because the fetcher asks Apple for every hash in the ring, device and client
 * do not need a synchronised clock - the device just walks the ring.
 *
 * Frame layout (31 bytes = the whole legacy advertising payload, no flags AD):
 *   [0]      0x1e        AD length: 30 bytes follow
 *   [1]      0xff        AD type: manufacturer specific data
 *   [2..3]   4c 00       Apple company ID (0x004C)
 *   [4]      0x12        Apple type: Find My / Offline Finding
 *   [5]      0x19        payload length: 25
 *   [6]      0x00        status (battery/hint, 0x00 = unknown)
 *   [7..28]              key[6..27]  (22 bytes)
 *   [29]                 key[0] >> 6  (top two bits of byte 0)
 *   [30]     0x00        hint
 *
 * The other 6 key bytes live in the BLE device address:
 *   addr[0] = key[0] | 0xC0   (top two bits forced to 0b11 = static random)
 *   addr[1..5] = key[1..5]
 *
 * Arduino core 3.x for ESP32 ships NimBLE (Bluedroid was removed), so this uses
 * the NimBLE host API directly for byte-exact control of the payload.
 */

#include <Arduino.h>
#include <Preferences.h>
#include <esp_random.h>
#include <esp_system.h>

#include <host/ble_hs.h>
#include <host/util/util.h>
#include <nimble/nimble_port.h>
#include <nimble/nimble_port_freertos.h>

#include "beacon_keys.h"

// Key rotation period. Override with -D BEACON_ROTATE_SECONDS=20 for testing.
#ifndef BEACON_ROTATE_SECONDS
#define BEACON_ROTATE_SECONDS 900
#endif
static constexpr uint32_t ROTATE_MS = (uint32_t)BEACON_ROTATE_SECONDS * 1000UL;

// Settling time between ble_gap_adv_stop() and reconfiguring the address.
static constexpr uint32_t RESTART_DELAY_MS = 250;

// Unconditional stop/start of advertising, independent of the rotation timer.
// The controller can stop transmitting while the host still believes the
// advertiser is running (seen in the field as a tag that is silent for hours
// and comes back only after a reset). Re-arming costs a ~250 ms gap every few
// minutes, which no finder notices.
static constexpr uint32_t REARM_MS = 5UL * 60UL * 1000UL;

// After this many failed restarts in a row, reboot the MCU. The key ring lives
// in flash and the start slot is random, so a reboot is a safe last resort.
static constexpr uint32_t MAX_ADV_FAILURES = 5;

// CPU clock. BLE works fine at 80 MHz and it is the cheapest power saving
// available on this core (light sleep is compiled out of the Arduino SDK), so
// the value is a build flag and can differ per tag:
//   PLATFORMIO_BUILD_FLAGS="-D BEACON_CPU_MHZ=80"
#ifndef BEACON_CPU_MHZ
#define BEACON_CPU_MHZ 160
#endif

// Slow 1 Hz blink on an external LED wired to D10 (the board has no built-in
// user LED). Set to 0 to save power.
#ifndef ENABLE_STATUS_LED
#define ENABLE_STATUS_LED 1
#endif
static constexpr uint8_t STATUS_LED_PIN = D10;
static constexpr uint32_t BAUD = 115200;

static uint8_t adv_data[31];
static uint8_t addr_display[6];  // as scanners show it, MSB first
static uint8_t addr_le[6];       // NimBLE ble_addr_t order, LSB first
static struct ble_gap_adv_params adv_params;

static volatile bool advertising = false;
static volatile bool host_synced = false;
static uint32_t rotate_requested_ms = 0;  // 0 = no rotation in flight
static uint32_t rearm_requested_ms = 0;   // 0 = no re-arm in flight
static uint32_t last_rotate_ms = 0;
static uint32_t last_arm_ms = 0;          // last successful adv start
static uint32_t last_watchdog_ms = 0;
static uint32_t adv_failures = 0;         // consecutive failed restarts
static uint16_t key_index = 0;

static Preferences prefs;
static uint32_t boot_count = 0;
static uint32_t wd_restarts = 0;

// Survives power cycles: tells us whether the tag rebooted / browned out while
// it was away, which is otherwise invisible.
static const char *reset_reason_str(esp_reset_reason_t reason) {
  switch (reason) {
    case ESP_RST_POWERON: return "power-on";
    case ESP_RST_EXT: return "external";
    case ESP_RST_SW: return "software";
    case ESP_RST_PANIC: return "PANIC";
    case ESP_RST_INT_WDT: return "int-wdt";
    case ESP_RST_TASK_WDT: return "task-wdt";
    case ESP_RST_WDT: return "wdt";
    case ESP_RST_BROWNOUT: return "BROWNOUT";
    case ESP_RST_DEEPSLEEP: return "deepsleep";
    case ESP_RST_SDIO: return "sdio";
    default: return "other";
  }
}

static void print_hex(const char *label, const uint8_t *data, size_t len) {
  Serial.printf("%s", label);
  for (size_t i = 0; i < len; i++) {
    Serial.printf("%02x", data[i]);
    if (i + 1 < len) Serial.print(' ');
  }
  Serial.println();
}

static void build_frame(const uint8_t *key) {
  adv_data[0] = 0x1e;  // AD length
  adv_data[1] = 0xff;  // manufacturer specific data
  adv_data[2] = 0x4c;  // Apple company ID, little endian
  adv_data[3] = 0x00;
  adv_data[4] = 0x12;  // Find My / Offline Finding
  adv_data[5] = 0x19;  // 25-byte payload
  adv_data[6] = 0x00;  // status

  memcpy(&adv_data[7], &key[6], 22);
  adv_data[29] = key[0] >> 6;  // top two bits of key[0]
  adv_data[30] = 0x00;         // hint

  addr_display[0] = key[0] | 0xC0;  // static random address
  memcpy(&addr_display[1], &key[1], 5);

  for (int i = 0; i < 6; i++) {
    addr_le[i] = addr_display[5 - i];  // NimBLE stores addresses little endian
  }
}

static int adv_event_cb(struct ble_gap_event *event, void *arg) {
  if (event->type == BLE_GAP_EVENT_ADV_COMPLETE) {
    advertising = false;
  }
  return 0;
}

// Returns true when advertising is running again.
static bool start_advertising() {
  int rc = ble_hs_id_set_rnd(addr_le);
  if (rc != 0) {
    Serial.printf("!! ble_hs_id_set_rnd failed: %d\n", rc);
    return false;
  }

  rc = ble_gap_adv_set_data(adv_data, sizeof(adv_data));
  if (rc != 0) {
    Serial.printf("!! ble_gap_adv_set_data failed: %d\n", rc);
    return false;
  }

  rc = ble_gap_adv_start(BLE_OWN_ADDR_RANDOM, NULL, BLE_HS_FOREVER, &adv_params,
                         adv_event_cb, NULL);
  if (rc != 0) {
    Serial.printf("!! ble_gap_adv_start failed: %d\n", rc);
    return false;
  }

  advertising = true;
  return true;
}

static void rotate_to(uint16_t index) {
  key_index = index % BEACON_KEY_COUNT;
  build_frame(BEACON_KEYS[key_index]);

  Serial.printf("[%6lus] rotating to key %u/%u  addr %02x:%02x:%02x:%02x:%02x:%02x\n",
                (unsigned long)(millis() / 1000), (unsigned)key_index + 1,
                (unsigned)BEACON_KEY_COUNT, addr_display[0], addr_display[1],
                addr_display[2], addr_display[3], addr_display[4],
                addr_display[5]);

  // The random address can only change while advertising is stopped. Do not
  // wait for BLE_GAP_EVENT_ADV_COMPLETE here - NimBLE does not report it for
  // an explicit stop on this port - the loop restarts after a short delay.
  ble_gap_adv_stop();
  advertising = false;
  rotate_requested_ms = millis() | 1;
}

static void on_sync() {
  if (start_advertising()) {
    Serial.println("advertising as a Find My accessory");
    last_arm_ms = millis();
  }
  host_synced = true;
  last_watchdog_ms = millis();
}

static void on_reset(int reason) {
  Serial.printf("BLE host reset, reason=%d\n", reason);
}

static void nimble_host_task(void *param) {
  nimble_port_run();
  nimble_port_freertos_deinit();
}

void setup() {
  // Must run before Serial.begin(): changing the core clock reconfigures the
  // APB/UART dividers, and the Arduino core handles that for us.
  setCpuFrequencyMhz(BEACON_CPU_MHZ);

#if ENABLE_STATUS_LED
  pinMode(STATUS_LED_PIN, OUTPUT);
  digitalWrite(STATUS_LED_PIN, LOW);
#endif

  Serial.begin(BAUD);
  const uint32_t start = millis();
  while (!Serial && (millis() - start) < 3000) {
    delay(10);
  }

  memset(&adv_params, 0, sizeof(adv_params));
  adv_params.conn_mode = BLE_GAP_CONN_MODE_NON;
  adv_params.disc_mode = BLE_GAP_DISC_MODE_NON;
  adv_params.itvl_min = BLE_GAP_ADV_ITVL_MS(1000);
  adv_params.itvl_max = BLE_GAP_ADV_ITVL_MS(2000);

  // Random starting slot so a reboot does not always reveal key 0 first.
  key_index = esp_random() % BEACON_KEY_COUNT;
  build_frame(BEACON_KEYS[key_index]);

  // Boot diagnostics in NVS
  prefs.begin("beacon", false);
  boot_count = prefs.getUInt("boots", 0) + 1;
  prefs.putUInt("boots", boot_count);
  wd_restarts = prefs.getUInt("wd", 0);
  prefs.end();

  Serial.println();
  Serial.println("=========================================");
  Serial.println(" BT_Beacon - Apple Find My emulation");
  Serial.println("=========================================");
  Serial.printf("boot #%lu   reset reason: %s (%d)\n", (unsigned long)boot_count,
                reset_reason_str(esp_reset_reason()), (int)esp_reset_reason());
  Serial.printf("watchdog restarts so far: %lu\n", (unsigned long)wd_restarts);
  Serial.printf("chip        : %s rev %d\n", ESP.getChipModel(), ESP.getChipRevision());
  Serial.printf("cpu         : %u MHz\n", (unsigned)getCpuFrequencyMhz());
  Serial.printf("keys        : %u, rotating every %lus\n", (unsigned)BEACON_KEY_COUNT,
                (unsigned long)(ROTATE_MS / 1000));
  Serial.printf("start slot  : %u\n", (unsigned)key_index + 1);
  print_hex("BLE address : ", addr_display, 6);
  print_hex("adv frame   : ", adv_data, sizeof(adv_data));
  Serial.println("-----------------------------------------");
  Serial.flush();

  nimble_port_init();
  ble_hs_cfg.sync_cb = on_sync;
  ble_hs_cfg.reset_cb = on_reset;
  nimble_port_freertos_init(nimble_host_task);
}

void loop() {
  static uint32_t last_led = 0;
  static uint32_t last_report = 0;
  static bool led_on = false;

#if ENABLE_STATUS_LED
  if (millis() - last_led >= 1000) {
    last_led = millis();
    led_on = !led_on;
    digitalWrite(STATUS_LED_PIN, led_on ? HIGH : LOW);
  }
#endif

  // Complete whichever restart is pending: a scheduled key rotation or an
  // insurance re-arm. Both have already stopped the advertiser.
  uint32_t *pending = rotate_requested_ms
                          ? &rotate_requested_ms
                          : (rearm_requested_ms ? &rearm_requested_ms : nullptr);
  if (pending && (millis() - *pending) >= RESTART_DELAY_MS) {
    if (start_advertising()) {
      if (pending == &rotate_requested_ms) {
        last_rotate_ms = millis();
      }
      *pending = 0;
      last_arm_ms = millis();
      adv_failures = 0;
    } else {
      *pending = millis() | 1;  // retry
      Serial.printf("!! restart failed (%lu in a row)\n", (unsigned long)++adv_failures);
      if (adv_failures >= MAX_ADV_FAILURES) {
        Serial.println("!! advertising unrecoverable - rebooting");
        Serial.flush();
        ESP.restart();
      }
    }
  }

  if (!rotate_requested_ms && !rearm_requested_ms &&
      (millis() - last_rotate_ms) >= ROTATE_MS) {
    rotate_to(key_index + 1);
  }

  // Insurance against a controller that has silently stopped transmitting
  // while the host still thinks the advertiser is running: stop and start it
  // again on a fixed schedule, no matter what the flags say.
  if (!rotate_requested_ms && !rearm_requested_ms && advertising &&
      (millis() - last_arm_ms) >= REARM_MS) {
    Serial.printf("[%6lus] re-arming advertising\n", (unsigned long)(millis() / 1000));
    ble_gap_adv_stop();
    advertising = false;
    rearm_requested_ms = millis() | 1;
  }

  // Supervisor: if advertising is not running and no rotation is in flight,
  // restart it. Covers a failed rotation restart or a controller hiccup that
  // would otherwise leave the tag silent while the firmware looks healthy.
  if (host_synced && !advertising && !rotate_requested_ms && !rearm_requested_ms &&
      (millis() - last_watchdog_ms) >= 5000) {
    last_watchdog_ms = millis();
    Serial.println("!! advertising lost - restarting");
    prefs.begin("beacon", false);
    prefs.putUInt("wd", prefs.getUInt("wd", 0) + 1);
    prefs.end();
    if (start_advertising()) {
      last_arm_ms = millis();
      adv_failures = 0;
    } else {
      Serial.printf("!! watchdog restart failed (%lu in a row)\n", (unsigned long)++adv_failures);
      if (adv_failures >= MAX_ADV_FAILURES) {
        Serial.println("!! advertising unrecoverable - rebooting");
        Serial.flush();
        ESP.restart();
      }
    }
  }

  if (millis() - last_report >= 30000) {
    last_report = millis();
    const char *state = advertising ? "beaconing"
                        : (rotate_requested_ms || rearm_requested_ms) ? "restarting"
                                                                      : "NOT advertising";
    Serial.printf("[%6lus] %-15s key %u/%u  boot #%lu  heap=%lu\n",
                  (unsigned long)(millis() / 1000), state, (unsigned)key_index + 1,
                  (unsigned)BEACON_KEY_COUNT, (unsigned long)boot_count,
                  (unsigned long)ESP.getFreeHeap());
  }

  delay(50);
}
