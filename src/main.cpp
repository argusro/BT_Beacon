/*
 * BT_Beacon - Apple Find My (Offline Finding) beacon on a Seeed XIAO ESP32-C3
 *
 * The device broadcasts the exact 31-byte Apple "Offline Finding" frame that a
 * real AirTag sends, as a BLE ADV_NONCONN_IND, using a static random address
 * derived from the same key. To any nearby iPhone it looks like a Find My
 * accessory; if the key is registered with Apple (see README) the phone
 * encrypts its location to that key and uploads it to the Find My network.
 *
 * Frame layout (31 bytes = the whole legacy advertising payload, no flags AD):
 *   [0]      0x1e        AD length: 30 bytes follow
 *   [1]      0xff        AD type: manufacturer specific data
 *   [2..3]   4c 00       Apple company ID (0x004C)
 *   [4]      0x12        Apple type: Find My / Offline Finding
 *   [5]      0x19        payload length: 25
 *   [6]      0x00        status (battery/hint, 0x00 = unknown)
 *   [7..28]              adv_key[6..27]  (22 bytes)
 *   [29]                 adv_key[0] >> 6  (top two bits of byte 0)
 *   [30]     0x00        hint
 *
 * The other 6 bytes of the key live in the BLE device address:
 *   addr[0] = adv_key[0] | 0xC0   (top two bits forced to 0b11 = static random)
 *   addr[1..5] = adv_key[1..5]
 *
 * Arduino core 3.x for ESP32 ships NimBLE (Bluedroid was removed), so this
 * uses the NimBLE host API directly for byte-exact control of the payload.
 */

#include <Arduino.h>

#include <host/ble_hs.h>
#include <host/util/util.h>
#include <nimble/nimble_port.h>
#include <nimble/nimble_port_freertos.h>

#include "beacon_key.h"

// Slow 1 Hz blink on an external LED wired to D10 (the board has no built-in
// user LED). Set to 0 to save power.
#ifndef ENABLE_STATUS_LED
#define ENABLE_STATUS_LED 1
#endif
static constexpr uint8_t STATUS_LED_PIN = D10;

static constexpr uint32_t BAUD = 115200;

// Apple's finding accessories advertise roughly every 2 s; the reference
// firmware uses min 1 s / max 2 s.
static constexpr uint16_t ADV_INTERVAL_MS_MIN = 1000;
static constexpr uint16_t ADV_INTERVAL_MS_MAX = 2000;

static uint8_t adv_data[31];
static uint8_t addr_display[6];  // as scanners show it, MSB first
static uint8_t addr_le[6];       // NimBLE ble_addr_t order, LSB first
static volatile bool advertising = false;

static void print_hex(const char *label, const uint8_t *data, size_t len) {
  Serial.printf("%s", label);
  for (size_t i = 0; i < len; i++) {
    Serial.printf("%02x", data[i]);
    if (i + 1 < len) Serial.print(' ');
  }
  Serial.println();
}

static void build_frame() {
  adv_data[0] = 0x1e;  // AD length
  adv_data[1] = 0xff;  // manufacturer specific data
  adv_data[2] = 0x4c;  // Apple company ID, little endian
  adv_data[3] = 0x00;
  adv_data[4] = 0x12;  // Find My / Offline Finding
  adv_data[5] = 0x19;  // 25-byte payload
  adv_data[6] = 0x00;  // status

  memcpy(&adv_data[7], &BEACON_ADV_KEY[6], 22);
  adv_data[29] = BEACON_ADV_KEY[0] >> 6;  // top two bits of key[0]
  adv_data[30] = 0x00;                    // hint

  addr_display[0] = BEACON_ADV_KEY[0] | 0xC0;  // static random address
  memcpy(&addr_display[1], &BEACON_ADV_KEY[1], 5);

  // NimBLE stores BLE addresses little endian.
  for (int i = 0; i < 6; i++) {
    addr_le[i] = addr_display[5 - i];
  }
}

static int adv_event_cb(struct ble_gap_event *event, void *arg) {
  switch (event->type) {
    case BLE_GAP_EVENT_CONNECT:
      Serial.println("unexpected connection (we advertise non-connectable)");
      break;

    case BLE_GAP_EVENT_ADV_COMPLETE:
      advertising = false;
      Serial.println("advertising stopped");
      break;

    default:
      break;
  }
  return 0;
}

static void start_advertising() {
  int rc = ble_hs_id_set_rnd(addr_le);
  if (rc != 0) {
    Serial.printf("!! ble_hs_id_set_rnd failed: %d\n", rc);
    return;
  }

  rc = ble_gap_adv_set_data(adv_data, sizeof(adv_data));
  if (rc != 0) {
    Serial.printf("!! ble_gap_adv_set_data failed: %d\n", rc);
    return;
  }

  struct ble_gap_adv_params params;
  memset(&params, 0, sizeof(params));
  params.conn_mode = BLE_GAP_CONN_MODE_NON;
  params.disc_mode = BLE_GAP_DISC_MODE_NON;
  params.itvl_min = BLE_GAP_ADV_ITVL_MS(ADV_INTERVAL_MS_MIN);
  params.itvl_max = BLE_GAP_ADV_ITVL_MS(ADV_INTERVAL_MS_MAX);

  rc = ble_gap_adv_start(BLE_OWN_ADDR_RANDOM, NULL, BLE_HS_FOREVER, &params,
                         adv_event_cb, NULL);
  if (rc != 0) {
    Serial.printf("!! ble_gap_adv_start failed: %d\n", rc);
  } else {
    advertising = true;
    Serial.println("advertising as a Find My accessory");
  }
}

static void on_sync() { start_advertising(); }

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

  build_frame();

  Serial.println();
  Serial.println("=========================================");
  Serial.println(" BT_Beacon - Apple Find My emulation");
  Serial.println("=========================================");
  Serial.printf("chip        : %s rev %d\n", ESP.getChipModel(), ESP.getChipRevision());
  Serial.printf("adv key     : %02x%02x%02x%02x...%02x%02x\n", BEACON_ADV_KEY[0],
                BEACON_ADV_KEY[1], BEACON_ADV_KEY[2], BEACON_ADV_KEY[3],
                BEACON_ADV_KEY[26], BEACON_ADV_KEY[27]);
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

  if (millis() - last_report >= 30000) {
    last_report = millis();
    Serial.printf("[%6lus] %s  heap=%lu\n", (unsigned long)(millis() / 1000),
                  advertising ? "beaconing" : "NOT advertising",
                  (unsigned long)ESP.getFreeHeap());
  }

  delay(50);
}
