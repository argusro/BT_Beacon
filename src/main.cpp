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
#include <esp_random.h>

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
static uint32_t rotate_requested_ms = 0;  // 0 = no rotation in flight
static uint32_t last_rotate_ms = 0;
static uint16_t key_index = 0;

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
  }
}

static void on_reset(int reason) {
  Serial.printf("BLE host reset, reason=%d\n", reason);
}

static void nimble_host_task(void *param) {
  nimble_port_run();
  nimble_port_freertos_deinit();
}

void setup() {
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

  Serial.println();
  Serial.println("=========================================");
  Serial.println(" BT_Beacon - Apple Find My emulation");
  Serial.println("=========================================");
  Serial.printf("chip        : %s rev %d\n", ESP.getChipModel(), ESP.getChipRevision());
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

  // Finish a rotation: give the controller a moment after the stop, then
  // reprogram the address/payload and restart advertising.
  if (rotate_requested_ms && (millis() - rotate_requested_ms) >= RESTART_DELAY_MS) {
    if (start_advertising()) {
      rotate_requested_ms = 0;
      last_rotate_ms = millis();
    } else {
      rotate_requested_ms = millis() | 1;  // retry
      Serial.println("!! restart failed, retrying");
    }
  }

  if (!rotate_requested_ms && (millis() - last_rotate_ms) >= ROTATE_MS) {
    rotate_to(key_index + 1);
  }

  if (millis() - last_report >= 30000) {
    last_report = millis();
    Serial.printf("[%6lus] %s  key %u/%u  heap=%lu\n", (unsigned long)(millis() / 1000),
                  advertising ? "beaconing" : "NOT advertising",
                  (unsigned)key_index + 1, (unsigned)BEACON_KEY_COUNT,
                  (unsigned long)ESP.getFreeHeap());
  }

  delay(50);
}
