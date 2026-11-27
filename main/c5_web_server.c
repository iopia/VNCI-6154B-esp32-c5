/*
 * VNCI 6154B / ESP32-C5 web UI on 192.168.61.250 next to esp-hosted-mcu 2.13.1 (ESP-IDF 6.1.1).
 *
 * How it works: esp-hosted hands every Wi-Fi frame to the host. Frames for 192.168.61.250
 * (ARP who-has .250 and IPv4 to .250) are caught in wlan_ap_rx_callback / wlan_sta_rx_callback,
 * copied into a private lwIP netif on the C5 and answered by esp_http_server on port 80.
 * Replies go out with esp_wifi_internal_tx() on the same interface, with the interface MAC.
 *
 * v1 (chat#7 msg 46): tcpip thread start, httpd sockets, netif MAC, separate TX buffer, TX power.
 * v2 (chat#7 msg 47, Yura's hardware test):
 *  - CPU temperature: real temperature_sensor driver (was hard-coded 0.0).
 *  - Ether Scanner: IDF can scan only in STA/APSTA mode; in AP mode the slave switches to
 *    APSTA for the scan and back, the scan/STA events of this scan are not forwarded to host.
 *  - HT40 on 2.4G: profile is applied BEFORE esp_wifi_start (and again after host RPCs);
 *    on AP start the secondary channel is set if the driver left it at NONE.
 *  - NVS settings / presets: written and applied in a separate worker task, NO C5 reboot
 *    (a C5 reboot drops the SDIO link, the VNCI host does not re-attach the slave).
 *    Radio profile / country / TX power are applied live; SSID / password / channel are
 *    applied by the host's next AP set_config (power cycle of the VNCI).
 *  - OTA: image header checked (magic, chip id), ota_0/ota_1 picked by esp-ota, streamed in
 *    4 KB chunks, errors are reported as text, no auto reboot: boot slot is set, new firmware
 *    starts on the next power cycle of the VNCI.
 * v3 (chat#7 msg 50, Yura's test of v2):
 *  - Backups are saved under the names of the firmware files (bootloader.bin,
 *    partition-table.bin, ota_data_initial.bin, network_adapter.bin = esp-hosted build /
 *    VNCI OTA=3 / Flasher names); images are cut to their real length (esp_image_get_metadata).
 *  - Speedtest download: plain Content-Length response via httpd_send (no chunked framing).
 *  - Factory NVS view: ap.ssid / sta.ssid are blobs (len u32 + 32 B), read with nvs_get_blob.
 *  - RX intercept in IRAM (runs for every Wi-Fi frame).
 * v4 (chat#7 msgs 51/52/56):
 *  - Ether Scanner scans 2.4 + 5 GHz: a host 2G_ONLY / 5G_ONLY band mode is switched to AUTO
 *    for the scan and restored after it (also on error); host band RPCs during the scan win.
 *    JSON records get "band" ("2.4" / "5" by primary channel), up to 40 records.
 *  - UI: scan table sorting (SSID / Band / CH / RSSI / Auth), RU / EN switch; HTML and JSON
 *    are sent with charset=utf-8.
 * v5 (chat#7 msg 62, Yura's test of v4b):
 *  - "Reboot C5" removed: esp_restart() resets the C5 SDIO slave and the VNCI host never
 *    re-enumerates it (the host only resets/attaches the C5 at its own boot or OTA=3; reset GPIO
 *    is not wired to the C5 side, esp-hosted has no slave->host "restart me" event).
 *    /api/reboot no longer restarts anything, it answers with the power-cycle hint.
 *  - Telemetry "need": bit0 = OTA image / partition written, bit1 = SSID/pass/channel differ
 *    from what the host applied at boot, bit2 = next boot slot != running slot.
 *    The UI shows one "power-cycle the VNCI" banner for all of them.
 *  - Web TX: esp_wifi_internal_tx() retried on ESP_ERR_NO_MEM (5 x 1 ms, as esp-hosted does)
 *    instead of dropping the TCP segment; lwIP TCP window / send buffer 17280 -> 23040 (16 MSS).
 * v6 (chat#7 msg 67, Yura's Wireshark capture of the VNCI's own web interface):
 *  - "Reboot device" = the same request the VNCI web page sends (Administration -> System,
 *    "Reboot system"): POST /cgi-bin/formular.fcgi/ASYS (multipart, SysReboot=yes) to the host
 *    IP (192.168.61.54 in the capture; learned from host frames, .54 if none seen yet).
 *    PassEnable / Password are read first with GET /cgi-bin/formular.fcgi/ASYS (as the page does)
 *    and sent back unchanged; without them nothing is sent.
 *  - The C5 talks to the host over the SDIO data path: web UI frames for the host are handed to
 *    the host like Wi-Fi RX frames (source MAC 02:C5:<AP MAC 2..5>, locally administered), host
 *    frames for 192.168.61.250 are taken out of the host->Wi-Fi path, only while that request runs.
 *  - Power-cycle hint stays as the fallback when the request fails.
 * v7 (chat#7 msg 75): max CPU temperature since power-on. A low-priority task samples the
 *    sensor every 3 s from boot (also without an open page); the maximum of valid readings
 *    (not 0.0 / out of -40..150 C) is kept in RAM and sent in telemetry as "tmax" (null until
 *    the first valid reading). Sensor access is serialized with a mutex (task + httpd).
 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdarg.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_http_server.h"
#include "esp_ota_ops.h"
#include "esp_app_format.h"
#include "esp_app_desc.h"
#include "esp_image_format.h"
#include "esp_attr.h"
#include "esp_partition.h"
#include "esp_flash.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_err.h"
#include "esp_log.h"
#include "esp_chip_info.h"
#include "esp_heap_caps.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "driver/temperature_sensor.h"
#include "lwip/opt.h"
#include "lwip/netif.h"
#include "lwip/etharp.h"
#include "lwip/tcpip.h"
#include "lwip/pbuf.h"
#include "lwip/ip4_addr.h"
#include "lwip/sockets.h"
#include "lwip/udp.h"                 /* v11.3: mDNS responder */
#include "netif/ethernet.h"
#include "c5_web_server.h"
#include "c5_web_ui.h"
#include "esp_hosted_coprocessor_fw_ver.h"

static const char *TAG = "c5_web";

extern esp_err_t esp_wifi_internal_tx(wifi_interface_t wifi_if, void *buffer, uint16_t len);

#define C5_UI_IP_B0 192
#define C5_UI_IP_B1 168
#define C5_UI_IP_B2 61
#define C5_UI_IP_B3 250

#define C5_PWR_MAX_DBM 20   /* esp_wifi_set_max_tx_power(): [80..84] -> 80 = 20 dBm, chip/API ceiling */

/* v11.5: set to 0 to build WITHOUT car diagnostics (/diag, /api/diag, /api/power).
 * Then also remove c5_diag.c and c5_power.c from slave/main/CMakeLists.txt and
 * delete the b_diag button row from the HTML in c5_web_ui.h. */
#ifndef C5_WITH_DIAG
#define C5_WITH_DIAG 0
#endif

static struct netif s_lwip_netif;
static volatile bool s_netif_ready = false;
static volatile bool s_srv_started = false;
static uint32_t s_host_pkts = 0;
static uint32_t s_ui_pkts = 0;
static volatile wifi_interface_t s_active_wifi_if = WIFI_IF_AP;
static uint8_t s_if_mac[2][6];
static bool s_if_mac_ok[2];

/* v11.3: second address for STATION mode (customer router subnet).
 * 192.168.61.250 stays alive for AP mode; vnci.local answers with the live address. */
static struct netif s_alias_netif;
static volatile bool s_alias_ready = false;
static uint8_t s_alias_ip[4];                       /* active address, 0.0.0.0 = down */
static uint8_t s_alias_mask[4] = { 255, 255, 255, 0 };
static uint8_t s_alias_gw[4];
static uint8_t s_alias_cfg_ip[4];                   /* v11.5: NVS override, 0.0.0.0 = auto */
static volatile bool s_sta_link_up = false;
static uint8_t s_probe_ip[4];                       /* v11.5: ARP duplicate-address probe */
static volatile bool s_probing = false;
static volatile bool s_probe_hit = false;
static bool c5_post_job(uint8_t job);
static void alias_apply(const uint8_t ip[4], const uint8_t mask[4], const uint8_t gw[4], bool up);
static bool alias_auto_pick(uint8_t out[4]);      /* v11.5.1 */
static void mdns_announce(void);                  /* v11.7 */
static void mdns_timer_cb(void *arg);             /* v11.7 */
static void mdns_start_once(void);

/* v6: VNCI host (its own web server) as seen on the host -> Wi-Fi path */
/* v11.2: the VNCI host is ALWAYS 192.168.61.54 - never learned from the wire any more.
 * Forwarded Wi-Fi client frames used to overwrite this with a client address. */
static const uint8_t s_host_ip[4] = { C5_UI_IP_B0, C5_UI_IP_B1, C5_UI_IP_B2, 54 };
static volatile bool s_host_ip_learned = false;   /* now means: host MAC seen (IP is fixed) */
/* v11.4: in STA mode the host P4 has a router-assigned address, not 192.168.61.54. */
static uint8_t s_host_ip_sta[4];
static volatile bool s_host_ip_sta_valid = false;
static const uint8_t s_ui_ip_fixed[4] = { C5_UI_IP_B0, C5_UI_IP_B1, C5_UI_IP_B2, C5_UI_IP_B3 };

static void host_ip_current(uint8_t out[4])
{
    if (s_sta_link_up && s_host_ip_sta_valid) memcpy(out, s_host_ip_sta, 4);
    else memcpy(out, s_host_ip, 4);
}
static uint8_t s_host_mac[6];
static volatile bool s_host_mac_ok = false;
static volatile wifi_interface_t s_host_ifx = WIFI_IF_AP;
static volatile bool s_host_link_on = false;   /* reboot request / car diagnostics running: web UI <-> host frames */
static volatile int s_link_users;              /* v9: reboot request and diag task share the host link */
static volatile int s_diag_users;              /* v11.1: diag users counted separately */
static portMUX_TYPE s_link_mux = portMUX_INITIALIZER_UNLOCKED;   /* v11.1: counters + flags together */
static volatile bool s_diag_mode;              /* v9: DoIP discovery: broadcast frames also go to the host */
/* v9 counters for the extended telemetry (real values only, RAM, since boot) */
static uint32_t s_h2w_pkts;                    /* host -> Wi-Fi frames seen in the host TX path */
static uint32_t s_ev_sta_conn, s_ev_sta_disc, s_ev_ap_conn, s_ev_ap_disc, s_ev_ap_start;
static uint8_t s_last_disc_reason;
static uint8_t s_io_buf[4096];     /* httpd task only */
/* v10 heap guard: web UI traffic must not eat the heap the Wi-Fi driver / esp-hosted need.
 * RX: big frames for the web UI are dropped (TCP resends them) while the heap is below RX_GUARD.
 * TX: speedtest / page senders wait (max 1 s per chunk) while the heap is below TX_GUARD. */
#define C5_HEAP_RX_GUARD (16 * 1024)
#define C5_HEAP_TX_GUARD (20 * 1024)
static uint32_t s_lm_drop, s_lm_wait;
static TaskHandle_t s_temp_th, s_cfg_th;
static uint8_t s_tx_buf[1514];     /* tcpip thread only; v11.4: 1500 MTU + 14 Ethernet */

typedef struct {
    char ssid[33];
    char pass[65];
    char cc[4];
    uint8_t std;
    uint8_t ch;
    int8_t pwr;
} c5_override_cfg_t;

static c5_override_cfg_t s_ov_cfg = { .cc = "01", .std = 0, .ch = 0, .pwr = C5_PWR_MAX_DBM };
static SemaphoreHandle_t s_cfg_mtx;          /* s_ov_cfg: httpd, worker, RPC task, event loop */

/* worker task: NVS writes + live apply, never in httpd / RPC context */
typedef enum { C5_JOB_SAVE = 1, C5_JOB_RESET, C5_JOB_CLEAR_STA, C5_JOB_ALIAS } c5_job_t;   /* v11.3 */
static QueueHandle_t s_job_q;
static c5_override_cfg_t s_pending_cfg;      /* guarded by s_cfg_mtx */
static char s_apply_msg[96] = "idle";
static volatile bool s_nvs_locked = false;   /* raw nvs partition restored: no NVS writes until reboot */
static volatile bool s_flash_written = false; /* v5: OTA image or partition written: power cycle needed */
static c5_override_cfg_t s_boot_cfg;          /* v5: overrides as loaded at boot (what the host applied) */

/* last results of the RF profile (shown in telemetry) */
static volatile esp_err_t s_prof_err = ESP_OK;
/* v11.6: configured protocol masks for telemetry. The driver's live AP mask can
 * fluctuate on the unused band while STA is connected on 5 GHz. */
static volatile uint16_t s_prof_pr2 = 0, s_prof_pr5 = 0;

/* web scan: forward nothing of it to the host */
static volatile bool s_web_scan_active = false;
static volatile int64_t s_web_scan_quiet_until = 0;

/* v4: web scan covers 2.4 + 5 GHz. If the host keeps the radio in 2G_ONLY / 5G_ONLY,
 * h_scan switches to WIFI_BAND_MODE_AUTO for the scan and restores the host value.
 * While switched, req_wifi_get_band_mode reports the host value and a host
 * set_band_mode / set_band marks the host value as newer (then h_scan does not restore). */
#define C5_SCAN_MAX_AP 24
static volatile bool s_scan_band_switched = false;
static volatile bool s_host_band_changed = false;
static volatile wifi_band_mode_t s_scan_saved_band = WIFI_BAND_MODE_AUTO;

static void cfg_lock(void)   { if (s_cfg_mtx) xSemaphoreTake(s_cfg_mtx, portMAX_DELAY); }
static void cfg_unlock(void) { if (s_cfg_mtx) xSemaphoreGive(s_cfg_mtx); }

static void cfg_get(c5_override_cfg_t *out)
{
    cfg_lock();
    *out = s_ov_cfg;
    cfg_unlock();
}

/* v11.3: router-subnet alias, stored in NVS */
static bool ip4_text_parse(const char *t, uint8_t out[4])
{
    unsigned a, b, c, d;
    if (!t || !*t) return false;
    if (sscanf(t, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return false;
    if (a > 255 || b > 255 || c > 255 || d > 255) return false;
    out[0] = (uint8_t)a; out[1] = (uint8_t)b; out[2] = (uint8_t)c; out[3] = (uint8_t)d;
    return true;
}

static void alias_cfg_load(void)
{
    nvs_handle_t h;
    memset(s_alias_cfg_ip, 0, 4);
    if (nvs_open("c5_cfg", NVS_READWRITE, &h) != ESP_OK) return;
    /* v11.5: one-time migration - forget the address saved by the old manual-only
     * scheme, so the automatic picker starts working without any curl command. */
    uint8_t v2 = 0;
    if (!s_nvs_locked && (nvs_get_u8(h, "al_v2", &v2) != ESP_OK || v2 != 1)) {
        nvs_erase_key(h, "al_ip");
        nvs_erase_key(h, "al_mask");
        nvs_erase_key(h, "al_gw");
        nvs_set_u8(h, "al_v2", 1);
        nvs_commit(h);
    }
    char t[24];
    size_t l = sizeof(t);
    if (nvs_get_str(h, "al_ip", t, &l) == ESP_OK) {
        uint8_t ip[4];
        if (ip4_text_parse(t, ip) && (ip[0] | ip[1] | ip[2] | ip[3])) memcpy(s_alias_cfg_ip, ip, 4);
    }
    l = sizeof(t);
    if (nvs_get_str(h, "al_mask", t, &l) == ESP_OK) {
        uint8_t m[4];
        if (ip4_text_parse(t, m)) memcpy(s_alias_mask, m, 4);
    }
    l = sizeof(t);
    if (nvs_get_str(h, "al_gw", t, &l) == ESP_OK) {
        uint8_t g[4];
        if (ip4_text_parse(t, g)) memcpy(s_alias_gw, g, 4);
    }
    nvs_close(h);
}

static void cfg_sanitize(c5_override_cfg_t *c)
{
    c->ssid[sizeof(c->ssid) - 1] = 0;
    c->pass[sizeof(c->pass) - 1] = 0;
    c->cc[sizeof(c->cc) - 1] = 0;
    if (c->cc[0] == 0) strcpy(c->cc, "01");
    if (c->pwr < 2 || c->pwr > C5_PWR_MAX_DBM) c->pwr = C5_PWR_MAX_DBM;
    if (c->std > 4) c->std = 0;
    if (!((c->ch >= 1 && c->ch <= 14) || (c->ch >= 36 && c->ch <= 177))) c->ch = 0;
}

static void c5_load_overrides(void)
{
    nvs_handle_t h;
    c5_override_cfg_t c = { .cc = "01", .std = 0, .ch = 0, .pwr = C5_PWR_MAX_DBM };
    if (nvs_open("c5_cfg", NVS_READONLY, &h) == ESP_OK) {
        size_t len = sizeof(c.ssid);
        nvs_get_str(h, "ssid", c.ssid, &len);
        len = sizeof(c.pass);
        nvs_get_str(h, "pass", c.pass, &len);
        len = sizeof(c.cc);
        nvs_get_str(h, "cc", c.cc, &len);
        nvs_get_u8(h, "std", &c.std);
        nvs_get_u8(h, "ch", &c.ch);
        nvs_get_i8(h, "pwr", &c.pwr);
        nvs_close(h);
    }
    cfg_sanitize(&c);
    s_ov_cfg = c;
    s_boot_cfg = c;
    alias_cfg_load();                    /* v11.3 */
}

int8_t c5_tx_power_qdbm(void)
{
    int q = s_ov_cfg.pwr * 4;   /* int8 read, atomic */
    if (q < 8) q = 8;
    if (q > 84) q = 84;
    return (int8_t)q;
}

void c5_apply_tx_power(void)
{
    (void)esp_wifi_set_max_tx_power(c5_tx_power_qdbm());
}

/* called from req_wifi_set_config() before esp_wifi_set_config() */
void c5_apply_wifi_overrides(wifi_interface_t ifx, wifi_config_t *cfg)
{
    if (ifx != WIFI_IF_AP || !cfg) return;
    c5_override_cfg_t c;
    cfg_get(&c);
    if (c.ssid[0] != '\0') {
        size_t slen = strnlen(c.ssid, 32);
        memset(cfg->ap.ssid, 0, sizeof(cfg->ap.ssid));
        memcpy(cfg->ap.ssid, c.ssid, slen);
        cfg->ap.ssid_len = (uint8_t)slen;
    }
    if (strlen(c.pass) >= 8) {
        size_t plen = strnlen(c.pass, 63);
        memset(cfg->ap.password, 0, sizeof(cfg->ap.password));
        memcpy(cfg->ap.password, c.pass, plen);
        if (cfg->ap.authmode == WIFI_AUTH_OPEN) cfg->ap.authmode = WIFI_AUTH_WPA2_PSK;
    }
    if (c.ch > 0) {
        cfg->ap.channel = c.ch;
    }
}

static bool sta_is_connected(void)
{
    wifi_ap_record_t ap;
    return esp_wifi_sta_get_ap_info(&ap) == ESP_OK;
}

/* 2.4G AP in HT40: make sure the secondary channel is set (HT40+ for ch 1..4, HT40- above) */
static void c5_fix_ht40_second(void)
{
    wifi_mode_t mode = WIFI_MODE_NULL;
    if (esp_wifi_get_mode(&mode) != ESP_OK) return;
    if (mode != WIFI_MODE_AP && mode != WIFI_MODE_APSTA) return;
    if (mode == WIFI_MODE_APSTA && sta_is_connected()) return;   /* AP follows the STA channel */

    wifi_bandwidths_t bw = {0};
    if (esp_wifi_get_bandwidths(WIFI_IF_AP, &bw) != ESP_OK || bw.ghz_2g != WIFI_BW40) return;

    uint8_t ch = 0;
    wifi_second_chan_t sec = WIFI_SECOND_CHAN_NONE;
    if (esp_wifi_get_channel(&ch, &sec) != ESP_OK) return;
    if (ch < 1 || ch > 13 || sec != WIFI_SECOND_CHAN_NONE) return;

    wifi_second_chan_t want = (ch <= 4) ? WIFI_SECOND_CHAN_ABOVE : WIFI_SECOND_CHAN_BELOW;
    (void)esp_wifi_set_channel(ch, want);
}

/* Only valid IDF combos: 2.4G b / bg / bgn / bgnax, 5G a / an / anac / anacax.
 * HT40 is allowed only on a band without 11AC/11AX (esp_wifi.h, set_bandwidths attention 2),
 * so 40 MHz is used only on 2.4G with b/g/n. Order: protocols first, then bandwidths. */
void c5_apply_rf_profile(void)
{
    wifi_mode_t mode = WIFI_MODE_NULL;
    if (esp_wifi_get_mode(&mode) != ESP_OK || mode == WIFI_MODE_NULL) return;

    c5_override_cfg_t c;
    cfg_get(&c);

    wifi_protocols_t proto = {0};
    wifi_bandwidths_t bw = {0};
    const uint16_t P2_N  = WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N;
    const uint16_t P2_AX = P2_N | WIFI_PROTOCOL_11AX;
    const uint16_t P5_N  = WIFI_PROTOCOL_11A | WIFI_PROTOCOL_11N;
    const uint16_t P5_AC = P5_N | WIFI_PROTOCOL_11AC;
    const uint16_t P5_AX = P5_AC | WIFI_PROTOCOL_11AX;

    switch (c.std) {
        case 1: /* Wi-Fi 6, 20 MHz */
            proto.ghz_2g = P2_AX; proto.ghz_5g = P5_AX; bw.ghz_2g = WIFI_BW20; bw.ghz_5g = WIFI_BW20; break;
        case 2: /* Wi-Fi 5, 20 MHz */
            proto.ghz_2g = P2_N;  proto.ghz_5g = P5_AC; bw.ghz_2g = WIFI_BW20; bw.ghz_5g = WIFI_BW20; break;
        case 3: /* Wi-Fi 4, 40 MHz on 2.4G */
            proto.ghz_2g = P2_N;  proto.ghz_5g = P5_N;  bw.ghz_2g = WIFI_BW40; bw.ghz_5g = WIFI_BW20; break;
        case 4: /* Wi-Fi 4, 20 MHz */
            proto.ghz_2g = P2_N;  proto.ghz_5g = P5_N;  bw.ghz_2g = WIFI_BW20; bw.ghz_5g = WIFI_BW20; break;
        default: /* 0: Hybrid Max: 5G AX 20 MHz / 2.4G N 40 MHz */
            proto.ghz_2g = P2_N;  proto.ghz_5g = P5_AX; bw.ghz_2g = WIFI_BW40; bw.ghz_5g = WIFI_BW20; break;
    }
    s_prof_pr2 = proto.ghz_2g;          /* v11.6: stable profile for the UI */
    s_prof_pr5 = proto.ghz_5g;
    esp_err_t first = ESP_OK, e;
    if (mode == WIFI_MODE_AP || mode == WIFI_MODE_APSTA) {
        e = esp_wifi_set_protocols(WIFI_IF_AP, &proto);  if (first == ESP_OK) first = e;
        e = esp_wifi_set_bandwidths(WIFI_IF_AP, &bw);    if (first == ESP_OK) first = e;
    }
    if (mode == WIFI_MODE_STA || (mode == WIFI_MODE_APSTA && !s_web_scan_active)) {
        e = esp_wifi_set_protocols(WIFI_IF_STA, &proto); if (first == ESP_OK) first = e;
        e = esp_wifi_set_bandwidths(WIFI_IF_STA, &bw);   if (first == ESP_OK) first = e;
    }
    s_prof_err = first;
    c5_fix_ht40_second();   /* no-op before esp_wifi_start() */
}

static void c5_apply_country(const char *cc)
{
    if (cc && cc[0] != '\0' && strcmp(cc, "01") != 0) {
        (void)esp_wifi_set_country_code(cc, false);
    }
}

/* v11.11: when the user pins a channel, the band follows from it (ch>=36 -> 5 GHz).
 * The host likes to re-assert its own band mode / channel after us, so this is also
 * re-run from the host RPC hook. Never fight the web scan, and never touch the band
 * while a STA uplink owns the channel. */
static void c5_apply_band_override(void)
{
    if (s_web_scan_active || s_scan_band_switched) return;

    c5_override_cfg_t c;
    cfg_get(&c);
    if (c.ch == 0) return;                      /* auto channel: host decides */

    wifi_mode_t mode = WIFI_MODE_NULL;
    if (esp_wifi_get_mode(&mode) != ESP_OK) return;
    if (mode != WIFI_MODE_AP && mode != WIFI_MODE_APSTA) return;
    if (mode == WIFI_MODE_APSTA && sta_is_connected()) return;

    wifi_band_mode_t want = (c.ch >= 36) ? WIFI_BAND_MODE_5G_ONLY : WIFI_BAND_MODE_2G_ONLY;
    wifi_band_mode_t cur = WIFI_BAND_MODE_AUTO;
    if (esp_wifi_get_band_mode(&cur) == ESP_OK && cur != want) {
        (void)esp_wifi_set_band_mode(want);
    }

    uint8_t ch = 0;
    wifi_second_chan_t sec = WIFI_SECOND_CHAN_NONE;
    if (esp_wifi_get_channel(&ch, &sec) == ESP_OK && ch != c.ch) {
        (void)esp_wifi_set_channel(c.ch, WIFI_SECOND_CHAN_NONE);
        c5_fix_ht40_second();                   /* restore HT40 secondary if needed */
    }
}

/* called from req_wifi_start() right BEFORE esp_wifi_start(): AP comes up with the profile */
void c5_before_wifi_start(void)
{
    c5_override_cfg_t c;
    cfg_get(&c);
    c5_apply_country(c.cc);
    c5_apply_rf_profile();
}

/* called from req_wifi_start() right after esp_wifi_start() succeeded */
void c5_on_wifi_started(void)
{
    c5_override_cfg_t c;
    cfg_get(&c);
    c5_apply_country(c.cc);
    (void)esp_wifi_set_ps(WIFI_PS_NONE);
    c5_apply_rf_profile();
    c5_apply_band_override();      /* v11.11 */
    c5_apply_tx_power();          /* last: country change resets the power limit */
}

/* esp-hosted event_handler_wifi(): true = do not forward this event to the host */
bool c5_webui_suppress_wifi_event(int32_t event_id)
{
    if (event_id != WIFI_EVENT_SCAN_DONE && event_id != WIFI_EVENT_STA_START &&
        event_id != WIFI_EVENT_STA_STOP) {
        return false;
    }
    return s_web_scan_active || (esp_timer_get_time() < s_web_scan_quiet_until);
}

bool c5_webui_scan_band_mode(wifi_band_mode_t *band_mode)
{
    if (!s_scan_band_switched || !band_mode) return false;
    *band_mode = s_scan_saved_band;
    return true;
}

void c5_webui_host_band_changed(void)
{
    if (s_scan_band_switched) { s_host_band_changed = true; return; }
    c5_apply_band_override();   /* v11.11: pinned channel beats the host */
}

static void c5_wifi_evt(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg; (void)base;
    switch (id) {
        case WIFI_EVENT_AP_STACONNECTED: s_ev_ap_conn++; mdns_announce(); break;   /* v11.7 */
        case WIFI_EVENT_AP_STADISCONNECTED: s_ev_ap_disc++; break;
        case WIFI_EVENT_STA_DISCONNECTED:
            s_ev_sta_disc++;
            if (data) s_last_disc_reason = (uint8_t)((wifi_event_sta_disconnected_t *)data)->reason;
            s_sta_link_up = false;             /* v11.3: drop alias with the link */
            s_host_ip_sta_valid = false;       /* v11.4: host address is gone with the link */
            c5_post_job(C5_JOB_ALIAS);
            break;
        case WIFI_EVENT_AP_START:
            s_ev_ap_start++;
            mdns_announce();               /* v11.7.1 */
            s_if_mac_ok[WIFI_IF_AP] = false;   /* v11.2: the host may have set a new MAC */
            c5_fix_ht40_second();
            c5_apply_tx_power();
            break;
        case WIFI_EVENT_STA_START:
            s_if_mac_ok[WIFI_IF_STA] = false;  /* v11.2: same for the station interface */
            /* fall through */
        case WIFI_EVENT_STA_CONNECTED:   /* 802.11d of the AP may have changed the country */
            if (id == WIFI_EVENT_STA_CONNECTED) {
                s_ev_sta_conn++;
                s_sta_link_up = true;          /* v11.3: bring alias up */
                s_if_mac_ok[WIFI_IF_STA] = (esp_wifi_get_mac(WIFI_IF_STA, s_if_mac[WIFI_IF_STA]) == ESP_OK);
                c5_post_job(C5_JOB_ALIAS);
            }
            c5_apply_tx_power();
            break;
        default:
            break;
    }
}


/* ---------- v11.3: minimal mDNS responder ("vnci.local") ----------
 * The Espressif mDNS component binds to an esp-netif device; our netifs are raw lwIP
 * next to esp-hosted. This responder answers A queries for vnci.local on a plain UDP PCB. */
#define C5_MDNS_NAME "vnci"
static struct udp_pcb *s_mdns_pcb;
static esp_timer_handle_t s_mdns_timer;   /* v11.7: periodic announcement */
static volatile bool s_mdns_up;
static uint32_t s_mdns_q, s_mdns_resp;
static uint32_t s_mdns_txerr;                      /* v11.9 */
static wifi_interface_t s_mdns_ifx = WIFI_IF_AP;   /* v11.9 */

static bool __attribute__((unused)) ip4_same_subnet(const uint8_t *a, const uint8_t *b, const uint8_t *m)
{
    for (int i = 0; i < 4; i++) if ((a[i] & m[i]) != (b[i] & m[i])) return false;
    return true;
}

static bool mdns_label_eq(const uint8_t *p, const char *lit, uint8_t len)
{
    for (uint8_t i = 0; i < len; i++) {
        if ((uint8_t)(p[i] | 0x20) != (uint8_t)lit[i]) return false;
    }
    return true;
}

static void mdns_rx(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                    const ip_addr_t *addr, u16_t port)
{
    (void)arg; (void)pcb;
    if (!p || p->tot_len < 12) { if (p) pbuf_free(p); return; }
    uint8_t q[256];
    size_t ql = p->tot_len > sizeof(q) ? sizeof(q) : p->tot_len;
    pbuf_copy_partial(p, q, ql, 0);
    pbuf_free(p);

    if (q[2] & 0x80) return;                              /* a response, not a query */
    uint16_t qd = ((uint16_t)q[4] << 8) | q[5];
    if (!qd || qd > 8) return;
    size_t o = 12;
    size_t name_at = 0;
    uint16_t qclass = 0;
    int hit = 0;
    for (int i = 0; i < (int)qd; i++) {
        size_t ns = o;
        int match = 1, lab = 0;
        while (o < ql) {
            uint8_t l = q[o];
            if (!l) { o++; break; }
            if ((l & 0xC0) || (o + 1 + l > ql)) { o = ql; break; }
            if (lab == 0) { if (l != 4 || !mdns_label_eq(&q[o + 1], C5_MDNS_NAME, 4)) match = 0; }
            else if (lab == 1) { if (l != 5 || !mdns_label_eq(&q[o + 1], "local", 5)) match = 0; }
            else match = 0;
            lab++;
            o += 1 + l;
        }
        if (lab != 2) match = 0;
        if (o + 4 > ql) return;
        uint16_t qt = ((uint16_t)q[o] << 8) | q[o + 1];
        uint16_t qc = ((uint16_t)q[o + 2] << 8) | q[o + 3];
        o += 4;
        if (match && (qt == 1 || qt == 255) && (qc & 0x7FFF) == 1) {
            hit = 1; qclass = qc; name_at = ns;
        }
    }
    if (!hit) return;

    /* v11.9: choose the netif by the interface the query arrived on, not by the
     * querier's subnet - AP clients may sit in a different DHCP pool. */
    struct netif *n = &s_lwip_netif;
    const uint8_t *ra = s_ui_ip_fixed;
    if (s_mdns_ifx == WIFI_IF_STA && s_alias_ready) {
        n = &s_alias_netif; ra = s_alias_ip;
    }
    if (!netif_is_up(n)) return;
    /* v11.10: we bypass ip4_input for mDNS, so lwIP never learns the querier's
     * MAC. Ask for it explicitly - otherwise the first reply is lost. */
    etharp_request(n, ip_2_ip4(addr));

    uint8_t r[192];
    if (o + 16 > sizeof(r)) return;
    memcpy(r, q, o);                                      /* header + question */
    r[2] = 0x84; r[3] = 0x00;                             /* QR + AA */
    r[6] = 0; r[7] = 1;                                   /* ANCOUNT = 1 */
    r[8] = r[9] = r[10] = r[11] = 0;
    size_t nlen = o;
    r[nlen++] = (uint8_t)(0xC0 | (name_at >> 8));
    r[nlen++] = (uint8_t)(name_at & 0xFF);   /* pointer to the matched question */
    r[nlen++] = 0; r[nlen++] = 1;                         /* A */
    r[nlen++] = 0x80; r[nlen++] = 0x01;                     /* IN + cache flush */
    r[nlen++] = 0; r[nlen++] = 0; r[nlen++] = 0; r[nlen++] = 120;
    r[nlen++] = 0; r[nlen++] = 4;
    memcpy(r + nlen, ra, 4); nlen += 4;

    struct pbuf *rp = pbuf_alloc(PBUF_TRANSPORT, nlen, PBUF_RAM);
    if (!rp) return;
    pbuf_take(rp, r, nlen);
    err_t e = ERR_OK;
    if (qclass & 0x8000) {                                /* QU: unicast reply */
        e = udp_sendto_if(s_mdns_pcb, rp, addr, port, n);
    } else {
        ip_addr_t dst;
        ip_addr_set_ip4_u32(&dst, lwip_htonl(0xE00000FB)); /* 224.0.0.251 */
        e = udp_sendto_if(s_mdns_pcb, rp, &dst, 5353, n);
        err_t e2 = udp_sendto_if(s_mdns_pcb, rp, addr, port, n);
        if (e != ERR_OK) e = e2;
    }
    if (e == ERR_OK) s_mdns_resp++; else s_mdns_txerr++;
    pbuf_free(rp);
}

static void mdns_start_cb(void *arg)
{
    (void)arg;
    if (s_mdns_pcb) return;
    struct udp_pcb *pcb = udp_new();
    if (!pcb) return;
    if (udp_bind(pcb, IP_ADDR_ANY, 5353) != ERR_OK) { udp_remove(pcb); return; }
    s_mdns_pcb = pcb;
    udp_recv(pcb, mdns_rx, NULL);
    s_mdns_up = true;
    /* v11.7: announce ourselves periodically - clients can cache vnci.local even
     * when the Wi-Fi driver does not deliver their multicast queries to us (AP mode). */
    if (!s_mdns_timer) {
        const esp_timer_create_args_t ta = { .callback = mdns_timer_cb, .name = "c5_mdns" };
        if (esp_timer_create(&ta, &s_mdns_timer) == ESP_OK) {
            esp_timer_start_periodic(s_mdns_timer, 60000000);
        }
    }
    /* v11.7.1: only announce if the Wi-Fi link is already up */
    if (s_ev_ap_start || s_sta_link_up || s_alias_ready) mdns_announce();
}

static void mdns_start_once(void)
{
    if (s_mdns_up) return;
    tcpip_callback(mdns_start_cb, NULL);
}

/* v11.3.1: take mDNS queries directly from the RX intercept.
 * Do not depend on lwIP multicast/IGMP input on the raw netif. */
typedef struct {
    ip_addr_t addr;
    u16_t port;
    wifi_interface_t ifx;
    struct pbuf *p;
} mdns_job_t;
static mdns_job_t s_mdns_job;
static volatile bool s_mdns_job_busy;

static void mdns_direct_cb(void *arg)
{
    mdns_job_t *j = (mdns_job_t *)arg;
    if (!s_mdns_pcb) mdns_start_cb(NULL);
    if (s_mdns_pcb && j->p) {
        s_active_wifi_if = j->ifx;
        s_mdns_ifx = j->ifx;              /* v11.9 */
        s_mdns_q++;
        mdns_rx(NULL, s_mdns_pcb, j->p, &j->addr, j->port);
        j->p = NULL;                    /* mdns_rx freed it */
    } else if (j->p) {
        pbuf_free(j->p);
    }
    s_mdns_job_busy = false;
}

static void mdns_rx_frame(const uint8_t *f, uint16_t len, wifi_interface_t ifx)
{
    if (len < 34) return;
    uint8_t ihl = (uint8_t)((f[14] & 0x0F) * 4);
    if (ihl < 20 || len < 14 + ihl + 8 + 12) return;
    size_t udp = 14 + ihl;
    uint16_t ulen = (uint16_t)((f[udp + 4] << 8) | f[udp + 5]);
    if (ulen < 8 + 12 || len < udp + ulen) return;
    uint16_t dns_len = (uint16_t)(ulen - 8);
    /* v11.10: cheap filter before any allocation - most mDNS traffic is foreign */
    if (dns_len < 12) return;
    if (f[udp + 8 + 2] & 0x80) return;
    if (!(((uint16_t)f[udp + 8 + 4] << 8) | f[udp + 8 + 5])) return;

    if (s_mdns_job_busy) return;
    mdns_job_t *j = &s_mdns_job;
    s_mdns_job_busy = true;
    j->p = pbuf_alloc(PBUF_RAW, dns_len, PBUF_RAM);
    if (!j->p) { s_mdns_job_busy = false; return; }
    pbuf_take(j->p, f + udp + 8, dns_len);

    uint32_t sip;
    memcpy(&sip, &f[26], 4);
    ip_addr_set_ip4_u32(&j->addr, sip);
    j->port = (uint16_t)((f[udp] << 8) | f[udp + 1]);
    j->ifx = ifx;

    if (tcpip_callback(mdns_direct_cb, j) != ERR_OK) {
        pbuf_free(j->p);
        s_mdns_job_busy = false;
    }
}

/* v11.7: unsolicited mDNS announcement (QDCOUNT=0, ANCOUNT=1).
 * Sent on every live netif, so AP clients learn vnci.local -> 192.168.61.250
 * without us having to receive their multicast query. */
static void mdns_announce_cb(void *arg)
{
    (void)arg;
    if (!s_mdns_pcb) return;
    /* v11.7.1: do not transmit before Wi-Fi is up */
    if (!s_ev_ap_start && !s_sta_link_up && !s_alias_ready) return;
    uint8_t r[40];
    memset(r, 0, 12);
    r[2] = 0x84; r[3] = 0x00;                 /* QR + AA */
    r[7] = 1;                                 /* ANCOUNT = 1 */
    size_t n = 12;
    r[n++] = 4; memcpy(r + n, C5_MDNS_NAME, 4); n += 4;
    r[n++] = 5; memcpy(r + n, "local", 5); n += 5;
    r[n++] = 0;
    r[n++] = 0; r[n++] = 1;                   /* A */
    r[n++] = 0x80; r[n++] = 1;                /* IN + cache flush */
    r[n++] = 0; r[n++] = 0; r[n++] = 0; r[n++] = 120;
    r[n++] = 0; r[n++] = 4;
    size_t at = n;
    struct pbuf *rp = pbuf_alloc(PBUF_TRANSPORT, n + 4, PBUF_RAM);
    if (!rp) return;
    ip_addr_t dst;
    ip_addr_set_ip4_u32(&dst, lwip_htonl(0xE00000FB));
    if (s_netif_ready) {
        memcpy(r + at, s_ui_ip_fixed, 4);
        pbuf_take(rp, r, n + 4);
        udp_sendto_if(s_mdns_pcb, rp, &dst, 5353, &s_lwip_netif);
    }
    if (s_alias_ready) {
        memcpy(r + at, s_alias_ip, 4);
        pbuf_take(rp, r, n + 4);
        udp_sendto_if(s_mdns_pcb, rp, &dst, 5353, &s_alias_netif);
    }
    pbuf_free(rp);
}

static void mdns_announce(void)
{
    if (!s_mdns_up) return;
    tcpip_callback(mdns_announce_cb, NULL);
}

static void mdns_timer_cb(void *arg)
{
    (void)arg;
    mdns_announce();
}

/* ---------- CPU temperature (internal sensor) ---------- */

static temperature_sensor_handle_t s_tsens;
static int s_tsens_range = 0;
static const int8_t s_tsens_ranges[3][2] = { { 20, 100 }, { -10, 80 }, { 50, 125 } };

static bool c5_read_temp(float *out)
{
    for (int attempt = 0; attempt < 3; attempt++) {
        if (!s_tsens) {
            temperature_sensor_config_t tc = TEMPERATURE_SENSOR_CONFIG_DEFAULT(
                s_tsens_ranges[s_tsens_range][0], s_tsens_ranges[s_tsens_range][1]);
            if (temperature_sensor_install(&tc, &s_tsens) != ESP_OK) {
                s_tsens = NULL;
                s_tsens_range = (s_tsens_range + 1) % 3;
                continue;
            }
            if (temperature_sensor_enable(s_tsens) != ESP_OK) {
                temperature_sensor_uninstall(s_tsens);
                s_tsens = NULL;
                s_tsens_range = (s_tsens_range + 1) % 3;
                continue;
            }
        }
        if (temperature_sensor_get_celsius(s_tsens, out) == ESP_OK) return true;
        /* out of the current range: next range */
        temperature_sensor_disable(s_tsens);
        temperature_sensor_uninstall(s_tsens);
        s_tsens = NULL;
        s_tsens_range = (s_tsens_range + 1) % 3;
    }
    return false;
}

/* v7: max temperature since power-on (RAM only) */
#define C5_TEMP_POLL_MS 3000
static SemaphoreHandle_t s_tsens_mtx;
static float s_temp_max;
static bool s_temp_max_valid;
static float s_temp_last;                      /* v11.2: cached reading, httpd never touches the sensor */
static bool s_temp_last_valid;

static bool c5_temp_sample(float *out)
{
    bool ok = false;
    if (s_tsens_mtx) xSemaphoreTake(s_tsens_mtx, portMAX_DELAY);
    float t = 0;
    if (c5_read_temp(&t) && t == t && t > -40.0f && t < 150.0f) {   /* v11.2: 0.0 C is valid */
        ok = true;
        s_temp_last = t;
        s_temp_last_valid = true;
        if (!s_temp_max_valid || t > s_temp_max) {
            s_temp_max = t;
            s_temp_max_valid = true;
        }
        if (out) *out = t;
    }
    if (s_tsens_mtx) xSemaphoreGive(s_tsens_mtx);
    return ok;
}

static bool c5_temp_max_get(float *out)
{
    bool ok;
    if (s_tsens_mtx) xSemaphoreTake(s_tsens_mtx, portMAX_DELAY);
    ok = s_temp_max_valid;
    if (ok) *out = s_temp_max;
    if (s_tsens_mtx) xSemaphoreGive(s_tsens_mtx);
    return ok;
}

/* v11.2: httpd reads the cache, it must not install/uninstall the sensor itself */
static bool c5_temp_last_get(float *out)
{
    bool ok;
    if (s_tsens_mtx) xSemaphoreTake(s_tsens_mtx, portMAX_DELAY);
    ok = s_temp_last_valid;
    if (ok && out) *out = s_temp_last;
    if (s_tsens_mtx) xSemaphoreGive(s_tsens_mtx);
    return ok;
}

static void c5_temp_task(void *arg)
{
    (void)arg;
    int fails = 0;
    int64_t pause_until = 0;
    for (;;) {
        int64_t now = esp_timer_get_time() / 1000;
        if (now >= pause_until) {
            if (c5_temp_sample(NULL)) {
                fails = 0;
            } else if (++fails >= 3) {         /* v11.2: broken sensor -> retry only every 30 s */
                pause_until = now + 30000;
                fails = 0;
            }
        }
        vTaskDelay(pdMS_TO_TICKS(C5_TEMP_POLL_MS));
    }
}

/* ---------- worker: NVS + live apply ---------- */

static void set_apply_msg(const char *m)
{
    cfg_lock();
    strlcpy(s_apply_msg, m, sizeof(s_apply_msg));
    cfg_unlock();
}

static esp_err_t c5_nvs_write_cfg(const c5_override_cfg_t *c)
{
    nvs_handle_t h;
    esp_err_t e = nvs_open("c5_cfg", NVS_READWRITE, &h);
    if (e != ESP_OK) return e;
    esp_err_t r = ESP_OK;
    if ((e = nvs_set_str(h, "ssid", c->ssid)) != ESP_OK) r = e;
    if ((e = nvs_set_str(h, "pass", c->pass)) != ESP_OK) r = e;
    if ((e = nvs_set_str(h, "cc", c->cc)) != ESP_OK) r = e;
    if ((e = nvs_set_u8(h, "std", c->std)) != ESP_OK) r = e;
    if ((e = nvs_set_u8(h, "ch", c->ch)) != ESP_OK) r = e;
    if ((e = nvs_set_i8(h, "pwr", c->pwr)) != ESP_OK) r = e;
    if ((e = nvs_commit(h)) != ESP_OK) r = e;
    nvs_close(h);
    return r;
}

static void c5_worker_task(void *arg)
{
    (void)arg;
    uint8_t job;
    char msg[96];
    for (;;) {
        if (xQueueReceive(s_job_q, &job, portMAX_DELAY) != pdTRUE) continue;
        switch (job) {
        case C5_JOB_SAVE: {
            c5_override_cfg_t old, c;
            cfg_lock();
            old = s_ov_cfg;
            c = s_pending_cfg;
            cfg_unlock();
            esp_err_t e = s_nvs_locked ? ESP_ERR_INVALID_STATE : c5_nvs_write_cfg(&c);
            if (e != ESP_OK) {
                snprintf(msg, sizeof(msg), "NVS write failed: %s", esp_err_to_name(e));
                set_apply_msg(msg);
                break;
            }
            cfg_lock();
            s_ov_cfg = c;
            cfg_unlock();
            /* live: country, protocol/bandwidth profile, TX power (Wi-Fi APIs are thread safe) */
            wifi_mode_t mode = WIFI_MODE_NULL;
            if (esp_wifi_get_mode(&mode) == ESP_OK && mode != WIFI_MODE_NULL) {
                if (strcmp(old.cc, c.cc) != 0) {
                    (void)esp_wifi_set_country_code(c.cc, false);
                }
                if (old.std != c.std) c5_apply_rf_profile();
                c5_apply_tx_power();
                c5_apply_band_override();   /* v11.11 */
            }
            bool later = strcmp(old.ssid, c.ssid) || strcmp(old.pass, c.pass) || old.ch != c.ch;
            snprintf(msg, sizeof(msg), "Saved. Radio applied now (%s)%s",
                     esp_err_to_name(s_prof_err),
                     later ? "; SSID/pass/channel after VNCI power cycle" : "");
            set_apply_msg(msg);
            break;
        }
        case C5_JOB_RESET: {
            nvs_handle_t h;
            esp_err_t e = s_nvs_locked ? ESP_ERR_INVALID_STATE : nvs_open("c5_cfg", NVS_READWRITE, &h);
            if (e == ESP_OK) {
                e = nvs_erase_all(h);
                if (e == ESP_OK) e = nvs_commit(h);
                nvs_close(h);
            }
            c5_override_cfg_t c = { .cc = "01", .std = 0, .ch = 0, .pwr = C5_PWR_MAX_DBM };
            cfg_lock();
            s_ov_cfg = c;
            cfg_unlock();
            c5_apply_rf_profile();
            c5_apply_tx_power();
            snprintf(msg, sizeof(msg), "Overrides cleared (%s)", esp_err_to_name(e));
            set_apply_msg(msg);
            break;
        }
        case C5_JOB_ALIAS: {             /* v11.5: automatic address in the router subnet */
            uint8_t ip[4] = { 0, 0, 0, 0 };
            uint8_t mask[4] = { 255, 255, 255, 0 }, gw[4] = { 0, 0, 0, 0 };
            bool want = s_sta_link_up;
            if (want) {
                if (s_alias_cfg_ip[0] | s_alias_cfg_ip[1] | s_alias_cfg_ip[2] | s_alias_cfg_ip[3]) {
                    memcpy(ip, s_alias_cfg_ip, 4);
                    memcpy(mask, s_alias_mask, 4);
                    memcpy(gw, s_alias_gw, 4);
                } else if (alias_auto_pick(ip)) {
                    gw[0] = ip[0]; gw[1] = ip[1]; gw[2] = ip[2]; gw[3] = 1;
                } else {
                    want = false;        /* host address not known yet */
                }
            }
            if (want) {
                memcpy(s_alias_ip, ip, 4);
                memcpy(s_alias_mask, mask, 4);
                memcpy(s_alias_gw, gw, 4);
            } else {
                memset(s_alias_ip, 0, 4);
            }
            alias_apply(want ? ip : NULL, mask, gw, want);
            if (want) mdns_announce();       /* v11.7 */
            snprintf(msg, sizeof(msg), want ? "Alias %u.%u.%u.%u up" : "Alias off",
                     ip[0], ip[1], ip[2], ip[3]);
            set_apply_msg(msg);
            break;
        }
        case C5_JOB_CLEAR_STA: {
            nvs_handle_t h;
            esp_err_t e = s_nvs_locked ? ESP_ERR_INVALID_STATE : nvs_open("nvs.net80211", NVS_READWRITE, &h);
            if (e == ESP_OK) {
                nvs_erase_key(h, "sta.ssid");
                nvs_erase_key(h, "sta.pswd");
                e = nvs_commit(h);
                nvs_close(h);
            } else if (e == ESP_ERR_NVS_NOT_FOUND) {
                e = ESP_OK;   /* nothing stored */
            }
            snprintf(msg, sizeof(msg), "STA history cleared (%s)", esp_err_to_name(e));
            set_apply_msg(msg);
            break;
        }
        default:
            break;
        }
    }
}

static bool c5_post_job(uint8_t job)
{
    return s_job_q && xQueueSend(s_job_q, &job, 0) == pdTRUE;
}
/* ---------- private lwIP netif ---------- */

/* v5: Wi-Fi TX buffers full -> wait 1 ms and retry (same as esp-hosted wifi_tx_with_retry),
 * a dropped segment costs a TCP retransmit timeout and stalls the speedtest */
static void ui_wifi_tx(void *buf, uint16_t len)
{
    for (int retry = 0; retry <= 5; retry++) {
        if (esp_wifi_internal_tx(s_active_wifi_if, buf, len) != ESP_ERR_NO_MEM) return;
        vTaskDelay(pdMS_TO_TICKS(1));
    }
}

/* v6: web UI frame that must go to the host (its MAC, or ARP who-has host IP) */
static bool ui_frame_is_for_host(const uint8_t *f, uint16_t len)
{
    if (!s_host_link_on || len < 14) return false;
    if (s_host_mac_ok && memcmp(f, s_host_mac, 6) == 0) return true;
    if (s_diag_mode && (f[0] & 1)) {
        /* v9 DoIP: ARP who-has and UDP/13400 broadcasts go to the host (they would only go on air otherwise) */
        if (len >= 42 && f[12] == 0x08 && f[13] == 0x06) return true;
        if (len >= 38 && f[12] == 0x08 && f[13] == 0x00 && f[14] == 0x45 && f[23] == 17 &&
            f[36] == 0x34 && f[37] == 0x58) return true;
    }
    uint8_t hip[4];
    host_ip_current(hip);                  /* v11.5: in STA the host is not .54 */
    return (f[0] & 1) && len >= 42 && f[12] == 0x08 && f[13] == 0x06 && memcmp(&f[38], hip, 4) == 0;
}

static err_t ui_to_host(struct pbuf *p)
{
    uint8_t *f = malloc(p->tot_len);
    if (!f) return ERR_MEM;
    pbuf_copy_partial(p, f, p->tot_len, 0);
    /* own source MAC towards the host: the AP MAC is the host's own MAC */
    uint8_t la[6] = { 0x02, 0xC5, s_lwip_netif.hwaddr[2], s_lwip_netif.hwaddr[3],
                      s_lwip_netif.hwaddr[4], s_lwip_netif.hwaddr[5] };
    memcpy(&f[6], la, 6);
    if (p->tot_len >= 42 && f[12] == 0x08 && f[13] == 0x06) {
        memcpy(&f[22], la, 6);                 /* ARP sender hardware address */
    }
    return c5_hosted_frame_to_host(s_host_ifx, f, p->tot_len) == ESP_OK ? ERR_OK : ERR_IF;
}

static err_t lwip_ui_linkoutput(struct netif *netif, struct pbuf *p)
{
    (void)netif;
    if (!p) return ERR_ARG;
    if (s_host_link_on && p->len >= 14 && ui_frame_is_for_host((const uint8_t *)p->payload, p->len)) {
        return ui_to_host(p);
    }
    if (p->next == NULL) {
        ui_wifi_tx(p->payload, p->len);
    } else {
        if (p->tot_len > sizeof(s_tx_buf)) return ERR_BUF;
        pbuf_copy_partial(p, s_tx_buf, p->tot_len, 0);
        ui_wifi_tx(s_tx_buf, p->tot_len);
    }
    return ERR_OK;
}

static err_t lwip_ui_netif_init(struct netif *netif)
{
    netif->name[0] = 'c';
    netif->name[1] = '5';
    netif->output = etharp_output;
    netif->linkoutput = lwip_ui_linkoutput;
    netif->mtu = 1500;
    netif->hwaddr_len = 6;
    if (esp_wifi_get_mac(WIFI_IF_AP, netif->hwaddr) != ESP_OK) {
        memset(netif->hwaddr, 0, 6);
    }
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_ETHERNET | NETIF_FLAG_LINK_UP;
    return ERR_OK;
}


/* v11.3: alias shares the physical Wi-Fi link; only its IP differs. */
static err_t lwip_alias_netif_init(struct netif *netif)
{
    netif->name[0] = 'c';
    netif->name[1] = '6';
    netif->output = etharp_output;
    netif->linkoutput = lwip_ui_linkoutput;
    netif->mtu = 1500;
    netif->hwaddr_len = 6;
    memcpy(netif->hwaddr, s_lwip_netif.hwaddr, 6);
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_ETHERNET | NETIF_FLAG_LINK_UP;
    return ERR_OK;
}

typedef struct { uint8_t ip[4], mask[4], gw[4]; bool up; } alias_job_t;

static void alias_apply_cb(void *arg)                 /* tcpip thread */
{
    alias_job_t *j = (alias_job_t *)arg;
    if (!j->up) {
        if (s_alias_ready) {
            netif_set_down(&s_alias_netif);
            netif_remove(&s_alias_netif);
            s_alias_ready = false;
        }
        return;                                       /* keep configured address in RAM */
    }
    ip4_addr_t a, m, g;
    memcpy(&a.addr, j->ip, 4);
    memcpy(&m.addr, j->mask, 4);
    memcpy(&g.addr, j->gw, 4);
    if (!s_alias_ready) {
        if (netif_add(&s_alias_netif, &a, &m, &g, NULL, lwip_alias_netif_init, tcpip_input) == NULL) return;
        s_alias_ready = true;
    } else {
        netif_set_addr(&s_alias_netif, &a, &m, &g);
    }
    memcpy(s_alias_netif.hwaddr, s_lwip_netif.hwaddr, 6);
    netif_set_link_up(&s_alias_netif);
    netif_set_up(&s_alias_netif);
    etharp_gratuitous(&s_alias_netif);   /* v11.10 */
}

/* v11.5: RFC5227-style ARP probe - is this address already taken on the router LAN? */
static bool alias_addr_free(const uint8_t ip[4])
{
    if (!s_if_mac_ok[WIFI_IF_STA]) return false;
    uint8_t f[42];
    memset(f, 0, sizeof(f));
    memset(f, 0xFF, 6);                             /* broadcast */
    memcpy(f + 6, s_if_mac[WIFI_IF_STA], 6);
    f[12] = 0x08; f[13] = 0x06;                     /* ARP */
    f[15] = 1; f[16] = 0x08; f[18] = 6; f[19] = 4;
    f[21] = 1;                                      /* request */
    memcpy(f + 22, s_if_mac[WIFI_IF_STA], 6);
    memcpy(f + 38, ip, 4);                          /* sender IP stays 0.0.0.0 = probe */
    memcpy(s_probe_ip, ip, 4);
    s_probe_hit = false;
    s_probing = true;
    for (int t = 0; t < 2 && !s_probe_hit; t++) {
        esp_wifi_internal_tx(WIFI_IF_STA, f, sizeof(f));
        vTaskDelay(pdMS_TO_TICKS(300));
    }
    s_probing = false;
    memset(s_probe_ip, 0, 4);
    return !s_probe_hit;
}

/* v11.5: pick a free address in the host's /24 (.250 first, then neighbours) */
static bool alias_auto_pick(uint8_t out[4])
{
    if (!s_host_ip_sta_valid) return false;
    static const uint8_t tail[] = { 250, 251, 252, 253, 254, 249, 248, 247, 246, 245 };
    uint8_t cand[4] = { s_host_ip_sta[0], s_host_ip_sta[1], s_host_ip_sta[2], 0 };
    for (size_t i = 0; i < sizeof(tail); i++) {
        if (tail[i] == s_host_ip_sta[3]) continue;
        cand[3] = tail[i];
        if (alias_addr_free(cand)) { memcpy(out, cand, 4); return true; }
    }
    return false;
}

static void alias_apply(const uint8_t ip[4], const uint8_t mask[4], const uint8_t gw[4], bool up)
{
    alias_job_t j;
    memset(&j, 0, sizeof(j));
    if (ip) memcpy(j.ip, ip, 4);
    if (mask) memcpy(j.mask, mask, 4);
    if (gw) memcpy(j.gw, gw, 4);
    j.up = up;
    tcpip_callback_with_block(alias_apply_cb, &j, 1);   /* worker task only */
}

static void inject_to_lwip(const void *buf, uint16_t len)
{
    if (len > 128 && esp_get_free_heap_size() < C5_HEAP_RX_GUARD) {   /* v10: ACK / ARP still pass */
        s_lm_drop++;
        return;
    }
    struct pbuf *p = pbuf_alloc(PBUF_RAW, len, PBUF_RAM);
    if (!p) return;
    if (pbuf_take(p, buf, len) != ERR_OK) {
        pbuf_free(p);
        return;
    }
    struct netif *n = &s_lwip_netif;
    if (len >= 34) {
        const uint8_t *f = (const uint8_t *)buf;
        if (f[12] == 0x08 && f[13] == 0x00 && s_alias_ready && memcmp(&f[30], s_alias_ip, 4) == 0) {
            n = &s_alias_netif;
        } else if (f[12] == 0x08 && f[13] == 0x06 && len >= 42 && s_alias_ready && memcmp(&f[38], s_alias_ip, 4) == 0) {
            n = &s_alias_netif;
        }
    }
    if (n->input(p, n) != ERR_OK) {
        pbuf_free(p);
    }
}

static inline __attribute__((always_inline)) bool ip_is_ui(const uint8_t *a)
{
    if (a[0] == C5_UI_IP_B0 && a[1] == C5_UI_IP_B1 && a[2] == C5_UI_IP_B2 && a[3] == C5_UI_IP_B3) return true;
    return s_alias_ready && a[0] == s_alias_ip[0] && a[1] == s_alias_ip[1] &&
           a[2] == s_alias_ip[2] && a[3] == s_alias_ip[3];
}

bool c5_webui_rx_intercept(wifi_interface_t ifx, void *buf, uint16_t len)
{
    if (!s_netif_ready || !buf || len < 34 || (ifx != WIFI_IF_AP && ifx != WIFI_IF_STA)) {
        s_host_pkts++;
        return false;
    }
    const uint8_t *p = (const uint8_t *)buf;
    uint16_t eth_type = ((uint16_t)p[12] << 8) | p[13];
    /* v11.5: someone claims the address we are probing -> it is already taken */
    if (s_probing && eth_type == 0x0806 && len >= 42 && memcmp(&p[28], s_probe_ip, 4) == 0) {
        s_probe_hit = true;
        s_host_pkts++;
        return false;
    }
    bool mine = false;

    if (eth_type == 0x0806) {                 /* ARP, target protocol address @38 */
        mine = (len >= 42) && ip_is_ui(&p[38]);
    } else if (eth_type == 0x0800) {          /* IPv4, destination address @30 */
        mine = ip_is_ui(&p[30]);
        /* v11.3.1: mDNS query handled directly, still forwarded to the host */
        if (len >= 42 && p[23] == 17 && p[36] == 0x14 && p[37] == 0xE9 &&
            ((p[30] == 224 && p[31] == 0 && p[32] == 0 && p[33] == 251) || ip_is_ui(&p[30]))) {
            mdns_rx_frame(p, len, ifx);
            s_host_pkts++;
            return false;
        }
    }
    if (!mine) {
        s_host_pkts++;
        return false;
    }

    /* answer on the interface the request came from, with that interface's own MAC */
    if (!s_if_mac_ok[ifx]) {
        s_if_mac_ok[ifx] = (esp_wifi_get_mac(ifx, s_if_mac[ifx]) == ESP_OK);
    }
    if (s_if_mac_ok[ifx] && memcmp(s_lwip_netif.hwaddr, s_if_mac[ifx], 6) != 0) {
        memcpy(s_lwip_netif.hwaddr, s_if_mac[ifx], 6);
        if (s_alias_ready) memcpy(s_alias_netif.hwaddr, s_if_mac[ifx], 6);   /* v11.3 */
    }
    /* v11.1: s_active_wifi_if is read by the tcpip thread (ui_wifi_tx); publish it only when it
     * actually changes instead of storing it on every received frame. */
    if (ifx != s_active_wifi_if) s_active_wifi_if = ifx;
    s_ui_pkts++;
    inject_to_lwip(buf, len);
    return true;
}

/* v6: host -> Wi-Fi path. Learn host IP / MAC (ARP sender; until the first ARP also the IPv4
 * source) in 192.168.61.0/24, not .250;
 * while the reboot request runs, frames for .250 go into the web UI lwIP instead of the air. */
bool c5_webui_host_tx_intercept(wifi_interface_t ifx, const void *buf, uint16_t len)
{
    s_h2w_pkts++;
    if (!s_netif_ready || !buf || len < 34) return false;
    const uint8_t *p = (const uint8_t *)buf;
    const uint8_t *sip, *dip;
    bool arp = false;
    if (p[12] == 0x08 && p[13] == 0x00) {
        sip = &p[26]; dip = &p[30];
    } else if (p[12] == 0x08 && p[13] == 0x06 && len >= 42) {
        sip = &p[28]; dip = &p[38]; arp = true;
    } else {
        return false;
    }
    /* v11.2: only the host's own source IP may teach us its MAC / interface (AP or STA). */
    if (!(p[6] & 1) && sip[0] == s_host_ip[0] && sip[1] == s_host_ip[1] &&
        sip[2] == s_host_ip[2] && sip[3] == s_host_ip[3]) {
        if (arp || !s_host_mac_ok) {
            memcpy(s_host_mac, &p[6], 6);
            s_host_ifx = ifx;
            s_host_mac_ok = true;
            s_host_ip_learned = true;
        }
    }
    /* v11.4: STA host P4 uses the C5 STA MAC; learn its router address from its frames. */
    if (ifx == WIFI_IF_STA && s_if_mac_ok[WIFI_IF_STA] &&
        memcmp(&p[6], s_if_mac[WIFI_IF_STA], 6) == 0 && !(p[6] & 1)) {
        if (!ip_is_ui(sip) && sip[0] != 0 && sip[3] != 255 &&
            !(sip[0] == 169 && sip[1] == 254)) {
            bool changed = !s_host_ip_sta_valid || memcmp(s_host_ip_sta, sip, 4) != 0;
            memcpy(s_host_ip_sta, sip, 4);
            s_host_ip_sta_valid = true;
            if (changed) c5_post_job(C5_JOB_ALIAS);   /* v11.5: new network -> new alias */
        }
        if (arp || !s_host_mac_ok) {
            memcpy(s_host_mac, &p[6], 6);
            s_host_ifx = ifx;
            s_host_mac_ok = true;
            s_host_ip_learned = true;
        }
    }
    if (s_diag_mode && !arp && len >= 38 && p[14] == 0x45 && p[23] == 17 && !ip_is_ui(dip) &&
        (dip[3] == 255) && ((p[34] == 0x34 && p[35] == 0x58) || (p[36] == 0x34 && p[37] == 0x58))) {
        inject_to_lwip(buf, len);              /* v9: DoIP broadcast (announcement), copy only */
        return false;
    }
    if (!s_host_link_on || !ip_is_ui(dip)) return false;
    s_ui_pkts++;
    inject_to_lwip(buf, len);
    return true;
}

/* v10: wait while the heap is low (httpd task / senders only), max ~1 s */
void c5_heap_wait(void)
{
    for (int i = 0; i < 200 && esp_get_free_heap_size() < C5_HEAP_TX_GUARD; i++) {
        if (i == 0) s_lm_wait++;
        vTaskDelay(pdMS_TO_TICKS(5));
    }
}

/* v10: gzip page from flash in 2 KB chunks, heap checked between chunks
 * (one httpd_resp_send() lets lwIP queue up to TCP_SND_BUF = 22.5 KB of copies per socket) */
esp_err_t c5_web_send_gz(httpd_req_t *req, const uint8_t *d, size_t n)
{
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
    httpd_resp_set_hdr(req, "Cache-Control", "no-cache");
    for (size_t o = 0; o < n; o += 2048) {
        c5_heap_wait();
        size_t c = (n - o) > 2048 ? 2048 : (n - o);
        if (httpd_resp_send_chunk(req, (const char *)d + o, (ssize_t)c) != ESP_OK) return ESP_FAIL;
    }
    return httpd_resp_send_chunk(req, NULL, 0);
}

/* v10: 4 KB scratch buffer of the httpd task (handlers run one at a time in that task) */
uint8_t *c5_web_io_buf(size_t *cap)
{
    *cap = sizeof(s_io_buf);
    return s_io_buf;
}

void c5_heap_stats(uint32_t *free_b, uint32_t *min_b, uint32_t *lfb_b)
{
    *free_b = esp_get_free_heap_size();
    *min_b = esp_get_minimum_free_heap_size();
    *lfb_b = heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT);
}

static esp_err_t h_index(httpd_req_t *req)
{
    return c5_web_send_gz(req, web_ui_html_gz, web_ui_html_gz_len);
}

static esp_err_t h_telemetry(httpd_req_t *req)
{
    uint8_t ch = 0;
    wifi_second_chan_t sec = WIFI_SECOND_CHAN_NONE;
    esp_wifi_get_channel(&ch, &sec);

    int8_t pwr = 80;
    esp_wifi_get_max_tx_power(&pwr);

    int bw_mhz = 20;
    wifi_bandwidths_t bws = {0};
    wifi_interface_t bif = (s_active_wifi_if == WIFI_IF_STA) ? WIFI_IF_STA : WIFI_IF_AP;
    if (esp_wifi_get_bandwidths(bif, &bws) == ESP_OK) {
        wifi_bandwidth_t b = (ch > 14) ? bws.ghz_5g : bws.ghz_2g;
        bw_mhz = (b == WIFI_BW40) ? 40 : (b == WIFI_BW80) ? 80 : (b == WIFI_BW160) ? 160 : 20;
    }
    if (bw_mhz == 40 && sec == WIFI_SECOND_CHAN_NONE && ch <= 14) bw_mhz = 20;  /* no 2nd ch -> 20 */

    int cli_num = 0;
    int avg_rssi = 0;
    if (s_active_wifi_if == WIFI_IF_STA) {
        wifi_ap_record_t ap_info;
        memset(&ap_info, 0, sizeof(ap_info));
        if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK) {
            cli_num = 1;
            avg_rssi = ap_info.rssi;
        }
    } else {
        wifi_sta_list_t stas;
        memset(&stas, 0, sizeof(stas));
        if (esp_wifi_ap_get_sta_list(&stas) == ESP_OK && stas.num > 0) {
            cli_num = stas.num;
            for (int i = 0; i < stas.num; i++) avg_rssi += stas.sta[i].rssi;
            avg_rssi /= stas.num;
        }
    }

    const esp_partition_t *run = esp_ota_get_running_partition();
    const esp_partition_t *boot = esp_ota_get_boot_partition();
    const esp_partition_t *nxt = esp_ota_get_next_update_partition(NULL);
    /* "next boot": the slot the bootloader will start (= active, changes after OTA / slot switch) */
    const esp_partition_t *nb = boot ? boot : run;
    (void)nxt;

    float t = 0;
    char temp_s[16];
    if (c5_temp_last_get(&t)) snprintf(temp_s, sizeof(temp_s), "%.1f", t);
    else strcpy(temp_s, "null");
    float tm = 0;
    char tmax_s[16];
    if (c5_temp_max_get(&tm)) snprintf(tmax_s, sizeof(tmax_s), "%.1f", tm);
    else strcpy(tmax_s, "null");

    /* v5: what needs a VNCI power cycle */
    int need = 0;
    if (s_flash_written) need |= 1;
    {
        c5_override_cfg_t c;
        cfg_get(&c);
        if (strcmp(c.ssid, s_boot_cfg.ssid) || strcmp(c.pass, s_boot_cfg.pass) || c.ch != s_boot_cfg.ch) need |= 2;
    }
    if (run && nb && run != nb) need |= 4;

    uint32_t hf, hm, hl;
    c5_heap_stats(&hf, &hm, &hl);
    char json[520];
    snprintf(json, sizeof(json),
        "{\"temp\":%s,\"tmax\":%s,\"free_kb\":%lu,\"min_kb\":%lu,\"cur_ota\":\"%s\",\"nxt_ota\":\"%s\","
        "\"ch\":%u,\"sec\":%d,\"bw\":%d,\"perr\":\"%s\",\"pwr\":%.1f,\"cli\":%d,\"rssi\":%d,"
        "\"hpkt\":%lu,\"upkt\":%lu,\"up\":%lld,\"need\":%d,"
        "\"heap_free\":%lu,\"heap_min\":%lu,\"heap_lfb\":%lu,\"lm_drop\":%lu,\"lm_wait\":%lu}",
        temp_s, tmax_s,
        (unsigned long)(hf / 1024),
        (unsigned long)(hm / 1024),
        run ? run->label : "?",
        nb ? nb->label : "?",
        ch, (int)sec, bw_mhz, esp_err_to_name(s_prof_err), pwr / 4.0f, cli_num, avg_rssi,
        (unsigned long)s_host_pkts, (unsigned long)s_ui_pkts,
        (long long)(esp_timer_get_time() / 1000000ULL), need,
        (unsigned long)hf, (unsigned long)hm, (unsigned long)hl, (unsigned long)s_lm_drop, (unsigned long)s_lm_wait);

    httpd_resp_set_type(req, "application/json; charset=utf-8");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    return httpd_resp_sendstr(req, json);
}

/* httpd_req_recv with retry on socket timeout; <=0 = connection lost */
static int recv_chunk(httpd_req_t *req, uint8_t *buf, size_t want)
{
    for (int tries = 0; tries < 5; tries++) {
        int r = httpd_req_recv(req, (char *)buf, want);
        if (r == HTTPD_SOCK_ERR_TIMEOUT) continue;
        return r;
    }
    return HTTPD_SOCK_ERR_TIMEOUT;
}

static esp_err_t h_speedtest(httpd_req_t *req)
{
    if (req->method == HTTP_GET) {
        char q[64];
        size_t sz = 1048576;
        if (httpd_req_get_url_query_str(req, q, sizeof(q)) == ESP_OK) {
            char val[16];
            if (httpd_query_key_value(q, "sz", val, sizeof(val)) == ESP_OK) sz = (size_t)atoi(val);
        }
        if (sz > 8388608) sz = 8388608;
        memset(s_io_buf, 0xA5, sizeof(s_io_buf));
        /* v3: plain response with Content-Length written straight to the socket:
         * chunked mode costs 3 send() calls per 4 KB (size line, data, CRLF) */
        char hdr[160];
        int hl = snprintf(hdr, sizeof(hdr),
                          "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
                          "Cache-Control: no-store\r\nContent-Length: %u\r\n\r\n", (unsigned)sz);
        if (httpd_send(req, hdr, hl) != hl) return ESP_FAIL;
        size_t left = sz;
        while (left > 0) {
            size_t chunk = left > sizeof(s_io_buf) ? sizeof(s_io_buf) : left;
            c5_heap_wait();                                  /* v10 */
            int w = httpd_send(req, (const char *)s_io_buf, chunk);
            if (w <= 0) return ESP_FAIL;
            left -= (size_t)w;
        }
        return ESP_OK;
    } else {
        size_t left = req->content_len;
        while (left > 0) {
            int r = recv_chunk(req, s_io_buf, left > sizeof(s_io_buf) ? sizeof(s_io_buf) : left);
            if (r <= 0) return ESP_FAIL;
            left -= r;
        }
        return httpd_resp_sendstr(req, "OK");
    }
}

static void url_decode(char *dst, const char *src, size_t max_len)
{
    size_t di = 0;
    for (size_t si = 0; src[si] && di + 1 < max_len; si++) {
        if (src[si] == '%' && src[si + 1] && src[si + 2]) {
            char hex[3] = { src[si + 1], src[si + 2], 0 };
            char *end = NULL;
            long v = strtol(hex, &end, 16);
            /* v11.2: "%zz" used to store a NUL and cut the string */
            if (end && *end == 0 && v >= 0 && v <= 255) {
                dst[di++] = (char)v;
                si += 2;
                continue;
            }
            dst[di++] = src[si];
        } else if (src[si] == '+') {
            dst[di++] = ' ';
        } else {
            dst[di++] = src[si];
        }
    }
    dst[di] = 0;
}

static void json_escape(char *dst, const char *src, size_t max_len)
{
    size_t di = 0;
    for (size_t si = 0; src[si] && di + 2 < max_len; si++) {
        if (src[si] == 0x22 || src[si] == 0x5C) {
            dst[di++] = 0x5C;
            dst[di++] = src[si];
        } else if ((unsigned char)src[si] >= 0x20) {
            dst[di++] = src[si];
        }
    }
    dst[di] = 0;
}

static void nvs_get_ssid_blob(nvs_handle_t h, const char *key, char out[33])
{
    uint8_t b[36];
    size_t l = sizeof(b);
    out[0] = 0;
    if (nvs_get_blob(h, key, b, &l) == ESP_OK && l == sizeof(b)) {
        uint32_t n = (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
        if (n > 32) n = 32;
        memcpy(out, &b[4], n);
        out[n] = 0;
        return;
    }
    l = 33;   /* older layouts: plain string */
    if (nvs_get_str(h, key, out, &l) != ESP_OK) out[0] = 0;
}

static esp_err_t h_nvs(httpd_req_t *req)
{
    if (req->method == HTTP_GET) {
        char fac_ap[33] = {0}, fac_sta[33] = {0};
        nvs_handle_t h;
        if (nvs_open("nvs.net80211", NVS_READONLY, &h) == ESP_OK) {
            /* wifi driver keeps ssid as blob: uint32 len + 32 B ssid */
            nvs_get_ssid_blob(h, "ap.ssid", fac_ap);
            nvs_get_ssid_blob(h, "sta.ssid", fac_sta);
            nvs_close(h);
        }
        c5_override_cfg_t c;
        char am[sizeof(s_apply_msg)];
        cfg_lock();
        c = s_ov_cfg;
        memcpy(am, s_apply_msg, sizeof(am));
        cfg_unlock();
        char esc_ap[68], esc_sta[68], esc_ov_s[68], esc_ov_p[132], esc_am[200];
        json_escape(esc_ap, fac_ap, sizeof(esc_ap));
        json_escape(esc_sta, fac_sta, sizeof(esc_sta));
        json_escape(esc_ov_s, c.ssid, sizeof(esc_ov_s));
        json_escape(esc_ov_p, c.pass, sizeof(esc_ov_p));
        json_escape(esc_am, am, sizeof(esc_am));

        char json[704];
        int jn = snprintf(json, sizeof(json),
            "{\"ov_ssid\":\"%s\",\"ov_pass\":\"%s\",\"cc\":\"%s\",\"std\":%u,\"ch\":%u,\"pwr\":%d,"
            "\"fac_ap\":\"%s\",\"fac_sta\":\"%s\",\"apply\":\"%s\"}",
            esc_ov_s, esc_ov_p, c.cc, c.std, c.ch, c.pwr, esc_ap, esc_sta, esc_am);
        httpd_resp_set_type(req, "application/json; charset=utf-8");
        httpd_resp_set_hdr(req, "Cache-Control", "no-store");
        if (jn < 0 || (size_t)jn >= sizeof(json)) {   /* v11.2: never send a cut object */
            return httpd_resp_sendstr(req, "{\"ok\":false,\"err\":\"nvs info too long\"}");
        }
        return httpd_resp_sendstr(req, json);
    }

    /* POST: parse here, write NVS + apply in the worker task (no flash / Wi-Fi reconfig in httpd,
     * no C5 reboot: the VNCI host does not re-attach a rebooted slave) */
    c5_override_cfg_t c;
    cfg_get(&c);
    /* v11.10: secrets arrive in the POST body, not in the URL (history / Referer). */
    char q[512], raw[256];
    q[0] = 0;
    int cl = (int)req->content_len;
    if (cl > 0) {
        if (cl > (int)sizeof(q) - 1) cl = (int)sizeof(q) - 1;
        int got = 0;
        while (got < cl) {
            int r = httpd_req_recv(req, q + got, cl - got);
            if (r <= 0) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "body read failed");
            got += r;
        }
        q[got] = 0;
    } else {
        httpd_req_get_url_query_str(req, q, sizeof(q));
    }
    {
        esp_err_t qe;
        qe = httpd_query_key_value(q, "ssid", raw, sizeof(raw));
        if (qe == ESP_ERR_HTTPD_RESULT_TRUNC) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "SSID too long");
        if (qe == ESP_OK) url_decode(c.ssid, raw, sizeof(c.ssid));
        qe = httpd_query_key_value(q, "pass", raw, sizeof(raw));
        if (qe == ESP_ERR_HTTPD_RESULT_TRUNC) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Password too long");
        if (qe == ESP_OK) url_decode(c.pass, raw, sizeof(c.pass));
        if (httpd_query_key_value(q, "cc", raw, sizeof(raw)) == ESP_OK) url_decode(c.cc, raw, sizeof(c.cc));
        if (httpd_query_key_value(q, "std", raw, sizeof(raw)) == ESP_OK) c.std = (uint8_t)atoi(raw);
        if (httpd_query_key_value(q, "ch", raw, sizeof(raw)) == ESP_OK) c.ch = (uint8_t)atoi(raw);
        if (httpd_query_key_value(q, "pwr", raw, sizeof(raw)) == ESP_OK) c.pwr = (int8_t)atoi(raw);
    }
    size_t pl = strlen(c.pass);
    if (pl > 0 && pl < 8) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Password must be 8..63 chars or empty");
    }
    cfg_sanitize(&c);
    cfg_lock();
    s_pending_cfg = c;
    strlcpy(s_apply_msg, "applying...", sizeof(s_apply_msg));
    cfg_unlock();
    if (!c5_post_job(C5_JOB_SAVE)) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Busy, try again");
    return httpd_resp_sendstr(req, "Saved to NVS (c5_cfg). Radio profile / country / TX power are applied now, "
                                   "SSID / password / channel after VNCI power cycle. No C5 reboot.");
}

static esp_err_t h_nvs_reset(httpd_req_t *req)
{
    if (!c5_post_job(C5_JOB_RESET)) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Busy, try again");
    return httpd_resp_sendstr(req, "Overrides cleared (defaults: Hybrid Max, 20 dBm, host SSID/channel)");
}

static esp_err_t h_nvs_clear_sta(httpd_req_t *req)
{
    if (!c5_post_job(C5_JOB_CLEAR_STA)) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Busy, try again");
    return httpd_resp_sendstr(req, "STA history cleared");
}

static const char *auth_name(wifi_auth_mode_t a)
{
    switch (a) {
        case WIFI_AUTH_OPEN: return "OPEN";
        case WIFI_AUTH_WEP: return "WEP";
        case WIFI_AUTH_WPA_PSK: return "WPA";
        case WIFI_AUTH_WPA2_PSK: return "WPA2";
        case WIFI_AUTH_WPA_WPA2_PSK: return "WPA/WPA2";
        case WIFI_AUTH_WPA3_PSK: return "WPA3";
        case WIFI_AUTH_WPA2_WPA3_PSK: return "WPA2/WPA3";
        case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2-ENT";
        default: return "OTHER";
    }
}

/* IDF scans only in STA or APSTA mode (docs: station-scenarios). The VNCI runs AP only, so
 * for the scan we switch AP -> APSTA and back. AP keeps running; its clients see a short
 * pause while the radio visits the other channels. Scan / STA start/stop events of this
 * scan are not forwarded to the host (c5_webui_suppress_wifi_event). */
typedef struct { char ssid[33]; uint8_t primary; int8_t rssi; uint8_t authmode; } c5_scan_rec_t;

static esp_err_t h_scan(httpd_req_t *req)
{
    httpd_resp_set_type(req, "application/json; charset=utf-8");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");

    wifi_mode_t mode = WIFI_MODE_NULL;
    if (esp_wifi_get_mode(&mode) != ESP_OK || mode == WIFI_MODE_NULL) {
        return httpd_resp_sendstr(req, "{\"error\":\"Wi-Fi is not started by the host\"}");
    }

    s_web_scan_active = true;
    bool switched = false;
    esp_err_t e = ESP_OK;
    if (mode == WIFI_MODE_AP) {
        e = esp_wifi_set_mode(WIFI_MODE_APSTA);
        if (e == ESP_OK) {
            switched = true;
            vTaskDelay(pdMS_TO_TICKS(100));   /* STA interface start */
        }
    }

    /* v4: scan both bands. IDF scans only the channels of the current band mode, so a host
     * 2G_ONLY / 5G_ONLY is switched to AUTO (2.4 + 5 GHz) for the scan and restored after it.
     * esp_wifi.h (set_band_mode, attention 6): a default channel is assigned only if the change
     * moves the radio to another band; ONLY -> AUTO keeps the current band, the AP channel stays. */
    wifi_band_mode_t bm_prev = WIFI_BAND_MODE_AUTO;
    bool bm_switched = false;
    wifi_protocols_t ap_proto_prev = {0};
    wifi_bandwidths_t ap_bw_prev = {0};
    bool ap_prev_ok = false;
    if (e == ESP_OK && esp_wifi_get_band_mode(&bm_prev) == ESP_OK && bm_prev != WIFI_BAND_MODE_AUTO) {
        ap_prev_ok = (esp_wifi_get_protocols(WIFI_IF_AP, &ap_proto_prev) == ESP_OK) &&
                     (esp_wifi_get_bandwidths(WIFI_IF_AP, &ap_bw_prev) == ESP_OK);
        s_host_band_changed = false;
        s_scan_saved_band = bm_prev;
        s_scan_band_switched = true;
        esp_err_t be = esp_wifi_set_band_mode(WIFI_BAND_MODE_AUTO);
        if (be == ESP_OK) {
            bm_switched = true;
        } else {
            s_scan_band_switched = false;
            ESP_LOGW(TAG, "web scan: band mode AUTO failed (%s), scanning current band only", esp_err_to_name(be));
        }
    }

    uint16_t ap_num = 0;
    c5_scan_rec_t *recs = NULL;   /* v10: 40 B per AP instead of sizeof(wifi_ap_record_t) */
    if (e == ESP_OK) {
        wifi_scan_config_t sc;
        memset(&sc, 0, sizeof(sc));      /* channel 0 + empty channel_bitmap = all allowed channels */
        sc.show_hidden = true;
        sc.scan_type = WIFI_SCAN_TYPE_ACTIVE;
        sc.scan_time.active.min = 50;
        sc.scan_time.active.max = 110;
        sc.scan_time.passive = 150;
        sc.home_chan_dwell_time = 40;    /* go back to the AP channel between scanned channels */
        sc.max_scan_ap_num = C5_SCAN_MAX_AP;   /* driver keeps the strongest 24 only (heap bound) */
        e = esp_wifi_scan_start(&sc, true);
        if (e == ESP_OK) {
            uint16_t total = 0;
            esp_wifi_scan_get_ap_num(&total);
            if (total > C5_SCAN_MAX_AP) total = C5_SCAN_MAX_AP;
            recs = total ? calloc(total, sizeof(c5_scan_rec_t)) : NULL;
            if (recs || !total) {
                wifi_ap_record_t one;
                while (ap_num < total && esp_wifi_scan_get_ap_record(&one) == ESP_OK) {
                    c5_scan_rec_t *c = &recs[ap_num++];
                    memcpy(c->ssid, one.ssid, 32);
                    c->ssid[32] = 0;
                    c->primary = one.primary;
                    c->rssi = one.rssi;
                    c->authmode = (uint8_t)one.authmode;
                }
            } else {
                e = ESP_ERR_NO_MEM;
            }
            esp_wifi_clear_ap_list();   /* rest of the driver list (if any) */
        }
    }

    /* restore the host band mode (also after a scan error), unless the host set a new one meanwhile */
    if (bm_switched) {
        /* restoring 2G_ONLY with the AP on a 5 GHz channel (or the reverse) would move the AP to
         * the default channel 1 / 36 (attention 6): then keep AUTO and let the host decide */
        uint8_t hch = 0;
        wifi_second_chan_t hsec = WIFI_SECOND_CHAN_NONE;
        bool band_ok = (esp_wifi_get_channel(&hch, &hsec) != ESP_OK) || hch == 0 ||
                       (bm_prev == WIFI_BAND_MODE_2G_ONLY ? hch <= 14 : hch > 14);
        if (s_host_band_changed) {
            ESP_LOGW(TAG, "web scan: host changed band / channel during the scan, keeping the host value");
        } else if (!band_ok) {
            ESP_LOGW(TAG, "web scan: AP channel %u is not in the saved band, band mode left AUTO", hch);
        } else {
            wifi_band_mode_t now = WIFI_BAND_MODE_AUTO;
            if (esp_wifi_get_band_mode(&now) != ESP_OK || now != bm_prev) {
                esp_err_t re = esp_wifi_set_band_mode(bm_prev);
                if (re != ESP_OK) ESP_LOGW(TAG, "web scan: band mode restore failed (%s)", esp_err_to_name(re));
            }
            /* band mode change may touch AP protocol / bandwidth: put back the value of the active band */
            if (ap_prev_ok) {
                wifi_protocols_t pr = {0};
                wifi_bandwidths_t bw = {0};
                bool g2 = (bm_prev == WIFI_BAND_MODE_2G_ONLY);
                if (esp_wifi_get_protocols(WIFI_IF_AP, &pr) == ESP_OK &&
                    (g2 ? pr.ghz_2g != ap_proto_prev.ghz_2g : pr.ghz_5g != ap_proto_prev.ghz_5g)) {
                    if (g2) pr.ghz_2g = ap_proto_prev.ghz_2g; else pr.ghz_5g = ap_proto_prev.ghz_5g;
                    (void)esp_wifi_set_protocols(WIFI_IF_AP, &pr);
                }
                if (esp_wifi_get_bandwidths(WIFI_IF_AP, &bw) == ESP_OK &&
                    (g2 ? bw.ghz_2g != ap_bw_prev.ghz_2g : bw.ghz_5g != ap_bw_prev.ghz_5g)) {
                    if (g2) bw.ghz_2g = ap_bw_prev.ghz_2g; else bw.ghz_5g = ap_bw_prev.ghz_5g;
                    (void)esp_wifi_set_bandwidths(WIFI_IF_AP, &bw);
                }
            }
        }
        s_scan_band_switched = false;
    }

    if (switched) {
        wifi_mode_t now = WIFI_MODE_NULL;
        if (esp_wifi_get_mode(&now) == ESP_OK && now == WIFI_MODE_APSTA) {
            esp_wifi_set_mode(WIFI_MODE_AP);
        }
    }
    if (bm_switched) c5_fix_ht40_second();   /* 2.4G HT40 AP: secondary channel as before */
    s_web_scan_quiet_until = esp_timer_get_time() + 1500000;   /* late STA_STOP event */
    s_web_scan_active = false;

    if (e != ESP_OK) {
        free(recs);
        char err[96];
        snprintf(err, sizeof(err), "{\"error\":\"scan: %s\"}", esp_err_to_name(e));
        return httpd_resp_sendstr(req, err);
    }

    httpd_resp_sendstr_chunk(req, "[");
    char item[192];
    char esc_ssid[68];
    for (int i = 0; i < ap_num; i++) {
        json_escape(esc_ssid, (const char *)recs[i].ssid, sizeof(esc_ssid));
        snprintf(item, sizeof(item), "%s{\"ssid\":\"%s\",\"band\":\"%s\",\"ch\":%u,\"rssi\":%d,\"auth\":\"%s\"}",
                 i ? "," : "", esc_ssid, recs[i].primary > 14 ? "5" : "2.4", recs[i].primary,
                 recs[i].rssi, auth_name((wifi_auth_mode_t)recs[i].authmode));
        httpd_resp_sendstr_chunk(req, item);
    }
    free(recs);
    httpd_resp_sendstr_chunk(req, "]");
    return httpd_resp_sendstr_chunk(req, NULL);
}

/* v3: file names = names of the firmware files (esp-hosted build / flasher_args.json,
 * VNCI OTA=3 and VNCI6154 Flasher: bootloader.bin, partition-table.bin, ota_data_initial.bin,
 * network_adapter.bin). Partitions without a firmware file keep the partition name. */
typedef struct {
    const char *part;      /* ?part= */
    const char *file;      /* Content-Disposition */
    uint32_t off, size;    /* raw flash region (0 = look the partition up) */
    bool image;            /* esp image: cut to the real image length */
} c5_bk_t;

static const c5_bk_t s_bk[] = {
    { "bootloader",      "bootloader.bin",           0x2000, 0xA000, true  },
    { "partition_table", "partition-table.bin",      0xC000, 0x0C00, false },
    { "otadata",         "ota_data_initial.bin",     0, 0, false },
    { "app",             "network_adapter.bin",      0, 0, true  },   /* running slot */
    { "ota_0",           "network_adapter_ota_0.bin", 0, 0, true },
    { "ota_1",           "network_adapter_ota_1.bin", 0, 0, true },
    { "nvs",             "nvs.bin",                  0, 0, false },
    { "fctry",           "fctry.bin",                0, 0, false },
    { "phy_init",        "phy_init.bin",             0, 0, false },
    { "esp_secure_cert", "esp_secure_cert.bin",      0, 0, false },
    { "nvs_key",         "nvs_key.bin",              0, 0, false },
    { "full",            "c5_full_flash_4MB.bin",    0, 0x400000, false },
};

static esp_err_t send_flash_region(httpd_req_t *req, uint32_t off, uint32_t len)
{
    for (uint32_t pos = 0; pos < len; pos += sizeof(s_io_buf)) {
        uint32_t chunk = (len - pos) > sizeof(s_io_buf) ? sizeof(s_io_buf) : (len - pos);
        if (esp_flash_read(NULL, s_io_buf, off + pos, chunk) != ESP_OK) return ESP_FAIL;
        c5_heap_wait();                                  /* v11.1: same guard as the gz / speedtest senders */
        if (httpd_resp_send_chunk(req, (const char *)s_io_buf, chunk) != ESP_OK) return ESP_FAIL;
    }
    return httpd_resp_send_chunk(req, NULL, 0);
}

static esp_err_t h_backup(httpd_req_t *req)
{
    char q[64], part_name[24] = "full";
    if (httpd_req_get_url_query_str(req, q, sizeof(q)) == ESP_OK) {
        httpd_query_key_value(q, "part", part_name, sizeof(part_name));
    }
    const c5_bk_t *bk = NULL;
    for (size_t i = 0; i < sizeof(s_bk) / sizeof(s_bk[0]); i++) {
        if (strcmp(part_name, s_bk[i].part) == 0) { bk = &s_bk[i]; break; }
    }
    if (!bk) return httpd_resp_send_404(req);

    uint32_t off = bk->off, len = bk->size;
    if (len == 0) {
        const esp_partition_t *p = NULL;
        if (strcmp(bk->part, "app") == 0) p = esp_ota_get_running_partition();
        else p = esp_partition_find_first(ESP_PARTITION_TYPE_ANY, ESP_PARTITION_SUBTYPE_ANY, bk->part);
        if (!p) return httpd_resp_send_404(req);
        off = p->address;
        len = p->size;
    }
    if (bk->image) {
        /* same length as the .bin from the build (header + segments + checksum + SHA-256);
         * no valid image (empty slot) -> raw dump of the whole region */
        esp_partition_pos_t pos = { .offset = off, .size = len };
        esp_image_metadata_t md;
        memset(&md, 0, sizeof(md));
        if (esp_image_get_metadata(&pos, &md) == ESP_OK && md.image_len > 0 && md.image_len <= len) {
            len = md.image_len;
        }
    }

    char hdr[96];
    snprintf(hdr, sizeof(hdr), "attachment; filename=\"%s\"", bk->file);
    httpd_resp_set_type(req, "application/octet-stream");
    httpd_resp_set_hdr(req, "Content-Disposition", hdr);
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    return send_flash_region(req, off, len);
}

static esp_err_t send_err_text(httpd_req_t *req, httpd_err_code_t code, const char *what, esp_err_t e)
{
    char m[128];
    if (e == ESP_OK) snprintf(m, sizeof(m), "ERROR: %s", what);
    else snprintf(m, sizeof(m), "ERROR: %s (%s)", what, esp_err_to_name(e));
    return httpd_resp_send_err(req, code, m);
}

/* drain the rest of the body so the browser gets the answer instead of a reset */
static void drain_body(httpd_req_t *req, size_t left)
{
    while (left > 0) {
        int r = recv_chunk(req, s_io_buf, left > sizeof(s_io_buf) ? sizeof(s_io_buf) : left);
        if (r <= 0) break;
        left -= r;
    }
}

static esp_err_t h_ota(httpd_req_t *req)
{
    char q[64], target[24] = "ota";
    if (httpd_req_get_url_query_str(req, q, sizeof(q)) == ESP_OK) {
        httpd_query_key_value(q, "part", target, sizeof(target));
    }

    if (strcmp(target, "ota") != 0) {
        if (strcmp(target, "nvs") != 0 && strcmp(target, "fctry") != 0 && strcmp(target, "phy_init") != 0) {
            drain_body(req, req->content_len);
            return send_err_text(req, HTTPD_400_BAD_REQUEST, "protected partition", ESP_OK);
        }
        const esp_partition_t *p = esp_partition_find_first(ESP_PARTITION_TYPE_ANY, ESP_PARTITION_SUBTYPE_ANY, target);
        if (!p) {
            drain_body(req, req->content_len);
            return httpd_resp_send_404(req);
        }
        if (req->content_len == 0 || req->content_len > p->size || (req->content_len % 4096) != 0) {
            drain_body(req, req->content_len);
            return send_err_text(req, HTTPD_400_BAD_REQUEST, "invalid backup size (must be 4K multiple, <= partition)", ESP_OK);
        }
        esp_err_t e = esp_partition_erase_range(p, 0, req->content_len);
        if (e != ESP_OK) {
            drain_body(req, req->content_len);
            return send_err_text(req, HTTPD_500_INTERNAL_SERVER_ERROR, "erase", e);
        }
        /* v11.2: any raw data partition restored -> its cached copy is stale until reboot */
        s_nvs_locked = true;
        size_t off = 0;
        size_t left = req->content_len;
        while (left > 0) {
            int r = recv_chunk(req, s_io_buf, left > sizeof(s_io_buf) ? sizeof(s_io_buf) : left);
            if (r <= 0) return ESP_FAIL;
            c5_heap_wait();                       /* v11.2: same guard as the other flash paths */
            e = esp_partition_write(p, off, s_io_buf, r);
            if (e != ESP_OK) {
                drain_body(req, left - r);
                return send_err_text(req, HTTPD_500_INTERNAL_SERVER_ERROR, "write", e);
            }
            /* v11.2: read back what was written - a silent flash failure must not look like success */
            {
                static uint8_t vb[512];
                bool bad = false;
                for (int o = 0; o < r && !bad; o += (int)sizeof(vb)) {
                    int c = (r - o) > (int)sizeof(vb) ? (int)sizeof(vb) : (r - o);
                    if (esp_partition_read(p, off + o, vb, c) != ESP_OK || memcmp(vb, s_io_buf + o, c) != 0) bad = true;
                }
                if (bad) {
                    drain_body(req, left - r);
                    return send_err_text(req, HTTPD_500_INTERNAL_SERVER_ERROR, "verify after write", ESP_FAIL);
                }
            }
            off += r;
            left -= r;
        }
        char ok[128];
        s_flash_written = true;
        snprintf(ok, sizeof(ok), "Partition %s restored (%u bytes). Power-cycle the VNCI to use it.",
                 target, (unsigned)off);
        return httpd_resp_sendstr(req, ok);
    }

    /* ---- app OTA: next slot (ota_1 when running ota_0 and vice versa) ---- */
    const esp_partition_t *run = esp_ota_get_running_partition();
    const esp_partition_t *upd = esp_ota_get_next_update_partition(NULL);
    if (!upd) {
        drain_body(req, req->content_len);
        return send_err_text(req, HTTPD_500_INTERNAL_SERVER_ERROR, "no OTA partition", ESP_OK);
    }
    if (req->content_len < sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t) +
                           sizeof(esp_app_desc_t) || req->content_len > upd->size) {
        drain_body(req, req->content_len);
        return send_err_text(req, HTTPD_400_BAD_REQUEST, "file size does not fit the OTA slot (1920 KB)", ESP_OK);
    }

    /* first chunk: check the image header before touching flash */
    size_t left = req->content_len;
    size_t got = 0;
    size_t first = left > sizeof(s_io_buf) ? sizeof(s_io_buf) : left;
    while (got < first) {
        int r = recv_chunk(req, s_io_buf + got, first - got);
        if (r <= 0) return ESP_FAIL;
        got += r;
    }
    left -= got;
    const esp_image_header_t *ih = (const esp_image_header_t *)s_io_buf;
    if (ih->magic != ESP_IMAGE_HEADER_MAGIC) {
        drain_body(req, left);
        return send_err_text(req, HTTPD_400_BAD_REQUEST, "not an ESP app image (magic != 0xE9)", ESP_OK);
    }
    if (ih->chip_id != CONFIG_IDF_FIRMWARE_CHIP_ID) {
        drain_body(req, left);
        return send_err_text(req, HTTPD_400_BAD_REQUEST, "image is not for ESP32-C5 (chip id)", ESP_OK);
    }

    esp_ota_handle_t ota_h = 0;
    esp_err_t e = esp_ota_begin(upd, OTA_WITH_SEQUENTIAL_WRITES, &ota_h);
    if (e != ESP_OK) {
        drain_body(req, left);
        return send_err_text(req, HTTPD_500_INTERNAL_SERVER_ERROR, "esp_ota_begin", e);
    }
    e = esp_ota_write(ota_h, s_io_buf, got);
    while (e == ESP_OK && left > 0) {
        int r = recv_chunk(req, s_io_buf, left > sizeof(s_io_buf) ? sizeof(s_io_buf) : left);
        if (r <= 0) {
            esp_ota_abort(ota_h);
            return ESP_FAIL;            /* connection lost: nothing switched, old firmware stays */
        }
        e = esp_ota_write(ota_h, s_io_buf, r);
        left -= r;
        got += r;
    }
    if (e != ESP_OK) {
        esp_ota_abort(ota_h);
        drain_body(req, left);
        return send_err_text(req, HTTPD_500_INTERNAL_SERVER_ERROR, "esp_ota_write", e);
    }
    e = esp_ota_end(ota_h);                 /* verifies the whole image (segments + SHA-256) */
    if (e != ESP_OK) {
        return send_err_text(req, HTTPD_400_BAD_REQUEST, "image check failed, boot slot NOT changed", e);
    }
    e = esp_ota_set_boot_partition(upd);
    if (e != ESP_OK) {
        return send_err_text(req, HTTPD_500_INTERNAL_SERVER_ERROR, "set boot partition", e);
    }
    s_flash_written = true;
    char ok[200];
    snprintf(ok, sizeof(ok), "OTA OK: %u bytes written to %s and verified, next boot = %s "
             "(running %s). Power-cycle the VNCI to start it.",
             (unsigned)got, upd->label, upd->label, run ? run->label : "?");
    return httpd_resp_sendstr(req, ok);
}

static esp_err_t h_slot(httpd_req_t *req)
{
    const esp_partition_t *run = esp_ota_get_running_partition();
    const esp_partition_t *nxt = esp_ota_get_next_update_partition(NULL);
    if (!nxt) return send_err_text(req, HTTPD_500_INTERNAL_SERVER_ERROR, "no other slot", ESP_OK);
    /* toggle: if a different slot is already selected for boot, go back to the running one */
    const esp_partition_t *boot = esp_ota_get_boot_partition();
    const esp_partition_t *want = (boot && run && boot != run) ? run : nxt;
    esp_err_t e = esp_ota_set_boot_partition(want);   /* checks that the slot holds a valid app */
    if (e != ESP_OK) return send_err_text(req, HTTPD_500_INTERNAL_SERVER_ERROR, "slot has no valid app", e);
    char m[96];
    snprintf(m, sizeof(m), "Next boot slot: %s (power-cycle the VNCI)", want->label);
    return httpd_resp_sendstr(req, m);
}

/* v5: no C5-only restart any more (the VNCI host does not re-attach a restarted C5) */
/* ---------- v6: reboot the whole VNCI through the host's own web server ---------- */

#define HOST_HTTP_TMO_MS 2000   /* v11.1: httpd is one task; 4 s x 2 stalled every page poll for ~8 s */
#define HOST_FORM_URL "/cgi-bin/formular.fcgi/ASYS"
#define HOST_BOUNDARY "----C5FormBoundaryVNCI6154B"

static int host_connect(void)
{
    struct sockaddr_in sa = { 0 };
    sa.sin_family = AF_INET;
    sa.sin_port = htons(80);
    uint8_t hip[4];
    host_ip_current(hip);
    memcpy(&sa.sin_addr.s_addr, hip, 4);
    int s = lwip_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s < 0) return -1;
    int fl = lwip_fcntl(s, F_GETFL, 0);
    lwip_fcntl(s, F_SETFL, fl | O_NONBLOCK);
    int r = lwip_connect(s, (struct sockaddr *)&sa, sizeof(sa));
    if (r < 0 && errno != EINPROGRESS) { lwip_close(s); return -1; }
    if (r < 0) {
        fd_set wf; FD_ZERO(&wf); FD_SET(s, &wf);
        struct timeval tv = { .tv_sec = HOST_HTTP_TMO_MS / 1000, .tv_usec = 0 };
        int err = 0; socklen_t el = sizeof(err);
        if (lwip_select(s + 1, NULL, &wf, NULL, &tv) <= 0 ||
            lwip_getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &el) != 0 || err != 0) {
            lwip_close(s);
            return -1;
        }
    }
    lwip_fcntl(s, F_SETFL, fl & ~O_NONBLOCK);
    struct timeval to = { .tv_sec = HOST_HTTP_TMO_MS / 1000, .tv_usec = 0 };
    lwip_setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &to, sizeof(to));
    lwip_setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &to, sizeof(to));
    return s;
}

static bool host_send_all(int s, const char *b, size_t n)
{
    while (n) {
        int w = lwip_send(s, b, n, 0);
        if (w <= 0) return false;
        b += w; n -= (size_t)w;
    }
    return true;
}

/* value of <formdata ... key="K">value</formdata>, XML entities &amp; &lt; &gt; &quot; &apos; decoded */
static bool form_value(const char *xml, const char *key, char *out, size_t outsz)
{
    char pat[48];
    snprintf(pat, sizeof(pat), "key=\"%s\">", key);
    const char *a = strstr(xml, pat);
    if (!a) return false;
    a += strlen(pat);
    const char *e = strchr(a, '<');
    if (!e) return false;
    size_t o = 0;
    while (a < e) {
        static const struct { const char *ent; char c; } ents[] = {
            { "&amp;", '&' }, { "&lt;", '<' }, { "&gt;", '>' }, { "&quot;", '"' }, { "&apos;", '\'' } };
        char c = *a; size_t adv = 1;
        if (c == '&') {
            for (size_t i = 0; i < sizeof(ents) / sizeof(ents[0]); i++) {
                size_t l = strlen(ents[i].ent);
                if ((size_t)(e - a) >= l && !strncmp(a, ents[i].ent, l)) { c = ents[i].c; adv = l; break; }
            }
        }
        if (o + 1 >= outsz) return false;
        out[o++] = c; a += adv;
    }
    out[o] = 0;
    return true;
}

/* streaming scan of the host page: keeps only the <dyngenval> block (current form values) */
typedef struct { char *win; size_t cap; size_t wl; bool in_dyn; bool done; } dynscan_t;

static void dynscan_feed(dynscan_t *d, const char *c, size_t n)
{
    while (n && !d->done) {
        size_t room = d->cap - 1 - d->wl;
        if (room == 0) {
            if (d->in_dyn) { d->done = true; break; }        /* block > window: parse what we have */
            memmove(d->win, d->win + d->wl - 16, 16);        /* marker may straddle chunks */
            d->wl = 16;
            room = d->cap - 1 - d->wl;
        }
        size_t k = n < room ? n : room;
        memcpy(d->win + d->wl, c, k);
        d->wl += k; d->win[d->wl] = 0; c += k; n -= k;
        if (!d->in_dyn) {
            char *p = strstr(d->win, "<dyngenval>");
            if (p) { d->in_dyn = true; d->wl -= (size_t)(p - d->win); memmove(d->win, p, d->wl + 1); }
        }
        if (d->in_dyn && strstr(d->win, "</dyngenval>")) d->done = true;
    }
}

/* GET the ASYS form of the host page (as the VNCI web page does before the submit) */
static esp_err_t host_get_asys(char *ip, char *pass_en, size_t pe_sz, char *pass, size_t p_sz, char *err, size_t esz)
{
    int s = host_connect();
    if (s < 0) { snprintf(err, esz, "no connection to %s:80", ip); return ESP_FAIL; }
    char req[160];
    int n = snprintf(req, sizeof(req), "GET " HOST_FORM_URL " HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", ip);
    if (!host_send_all(s, req, n)) { lwip_close(s); snprintf(err, esz, "send failed (GET)"); return ESP_FAIL; }

    /* s_io_buf: [0..2047] scan window, [2048..4095] receive chunk */
    dynscan_t d = { .win = (char *)s_io_buf, .cap = 2048 };
    d.win[0] = 0;
    char status[16] = { 0 };
    bool first = true;
    while (!d.done) {
        int r = lwip_recv(s, s_io_buf + 2048, 2048, 0);
        if (r <= 0) break;
        if (first) { first = false; memcpy(status, s_io_buf + 2048, r < 15 ? r : 15); }
        dynscan_feed(&d, (const char *)s_io_buf + 2048, (size_t)r);
    }
    char *win = d.win;
    bool in_dyn = d.in_dyn;
    lwip_close(s);
    if (strncmp(status, "HTTP/1.", 7) != 0) { snprintf(err, esz, "no HTTP answer from %s", ip); return ESP_FAIL; }
    if (strncmp(status + 9, "200", 3) != 0) {
        snprintf(err, esz, "host page answered %.3s%s", status + 9,
                 !strncmp(status + 9, "401", 3) ? " (password protection of the VNCI web page is on)" : "");
        return ESP_FAIL;
    }
    if (!in_dyn || !strstr(win, "key=\"SysReboot\"")) { snprintf(err, esz, "no reboot item in the host form"); return ESP_FAIL; }
    if (!form_value(win, "PassEnable", pass_en, pe_sz) || !form_value(win, "Password", pass, p_sz)) {
        snprintf(err, esz, "host form values not found");
        return ESP_FAIL;
    }
    return ESP_OK;
}

/* POST the ASYS form with SysReboot=yes, the same fields the VNCI web page sends */
static esp_err_t host_post_reboot(const char *ip, const char *pass_en, const char *pass, bool *answered, char *err, size_t esz)
{
    char *body = malloc(1024), *hdr = malloc(512);
    if (!body || !hdr) { free(body); free(hdr); snprintf(err, esz, "no memory"); return ESP_FAIL; }
#define PART(name) "--" HOST_BOUNDARY "\r\nContent-Disposition: form-data; name=\"" name "\"\r\n\r\n"
    int bl = snprintf(body, 1024,
        PART("FORM_TRIGGER") "submit\r\n"
        PART("PassEnable") "%s\r\n"
        PART("Password") "%s\r\n"
        PART("FuncRLED") "0\r\n"
        "--" HOST_BOUNDARY "\r\nContent-Disposition: form-data; name=\"LoadSettings\"; filename=\"\"\r\n"
        "Content-Type: application/octet-stream\r\n\r\n\r\n"
        PART("SysReboot") "yes\r\n"
        PART("FORM_Submit") "Accept\r\n"
        "--" HOST_BOUNDARY "--\r\n", pass_en, pass);
#undef PART
    int hl = snprintf(hdr, 512,
        "POST " HOST_FORM_URL " HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n"
        "Content-Type: multipart/form-data; boundary=" HOST_BOUNDARY "\r\nContent-Length: %d\r\n"
        "Origin: http://%s\r\nReferer: http://%s" HOST_FORM_URL "\r\n\r\n", ip, bl, ip, ip);
    esp_err_t ret = ESP_FAIL;
    *answered = false;
    if (bl <= 0 || bl >= 1024 || hl <= 0 || hl >= 512) { snprintf(err, esz, "request too long"); goto out; }
    int s = host_connect();
    if (s < 0) { snprintf(err, esz, "no connection to %s:80", ip); goto out; }
    if (!host_send_all(s, hdr, hl) || !host_send_all(s, body, bl)) {
        lwip_close(s); snprintf(err, esz, "send failed (POST)"); goto out;
    }
    char st[16] = { 0 };
    int r = lwip_recv(s, st, sizeof(st) - 1, 0);
    lwip_close(s);
    if (r >= 12 && !strncmp(st, "HTTP/1.", 7)) {
        *answered = true;
        if (strncmp(st + 9, "200", 3) == 0) ret = ESP_OK;
        else snprintf(err, esz, "host answered %.3s", st + 9);
    } else {
        ret = ESP_OK;                     /* request fully sent, host went away (already rebooting) */
    }
out:
    free(body); free(hdr);
    return ret;
}


/* ---------- v9: extended telemetry, only values the IDF really reports ---------- */

#define C5_BUILD_NAME "web_v11_nvs"

static const char *reset_reason_str(esp_reset_reason_t r)
{
    switch (r) {
        case ESP_RST_POWERON: return "power-on";
        case ESP_RST_EXT: return "external pin";
        case ESP_RST_SW: return "software (esp_restart)";
        case ESP_RST_PANIC: return "panic";
        case ESP_RST_INT_WDT: return "interrupt WDT";
        case ESP_RST_TASK_WDT: return "task WDT";
        case ESP_RST_WDT: return "other WDT";
        case ESP_RST_DEEPSLEEP: return "deep sleep";
        case ESP_RST_BROWNOUT: return "brownout";
        case ESP_RST_SDIO: return "SDIO";
        case ESP_RST_USB: return "USB";
        case ESP_RST_JTAG: return "JTAG";
        case ESP_RST_EFUSE: return "eFuse";
        case ESP_RST_PWR_GLITCH: return "power glitch";
        case ESP_RST_CPU_LOCKUP: return "CPU lockup";
        default: return "unknown";
    }
}

#define INFO_SZ 4096   /* v10: built in s_io_buf (httpd task), no malloc */
typedef struct { char *b; size_t len; } jb_t;

static void jb_add(jb_t *j, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void jb_add(jb_t *j, const char *fmt, ...)
{
    if (j->len >= INFO_SZ - 1) return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(j->b + j->len, INFO_SZ - j->len, fmt, ap);
    va_end(ap);
    if (n > 0) j->len = (j->len + (size_t)n < INFO_SZ) ? j->len + (size_t)n : INFO_SZ - 1;
}

static void mac_str(char out[18], const uint8_t *m)
{
    snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4], m[5]);
}

static void phy_str(char *out, size_t sz, const wifi_sta_info_t *s)
{
    snprintf(out, sz, "%s%s%s%s%s%s%s", s->phy_11b ? "b" : "", s->phy_11g ? "g" : "", s->phy_11n ? "n" : "",
             s->phy_11a ? "a" : "", s->phy_11ac ? "ac" : "", s->phy_11ax ? "ax" : "", s->phy_lr ? " LR" : "");
}

static esp_err_t h_info(httpd_req_t *req)
{
    char *buf = (char *)s_io_buf;
    jb_t j = { buf, 0 };
    char tmp[100], mac[18];
    uint8_t hip[4];
    host_ip_current(hip);
    const uint8_t *uip = s_alias_ready ? s_alias_ip : s_ui_ip_fixed;
    jb_add(&j, "{\"build\":\"" C5_BUILD_NAME "\",\"idf\":\"%s\",\"ehv\":\"%d.%d.%d\"",
           esp_get_idf_version(), PROJECT_VERSION_MAJOR_1, PROJECT_VERSION_MINOR_1, PROJECT_VERSION_PATCH_1);
    const esp_app_desc_t *ad = esp_app_get_description();
    if (ad) {
        json_escape(tmp, ad->version, sizeof(tmp));
        jb_add(&j, ",\"appv\":\"%s\"", tmp);
        jb_add(&j, ",\"bdate\":\"%.16s %.16s\"", ad->date, ad->time);
    }
    jb_add(&j, ",\"rr\":\"%s\"", reset_reason_str(esp_reset_reason()));
    esp_chip_info_t ci;
    esp_chip_info(&ci);
    jb_add(&j, ",\"rev\":%u,\"cores\":%u", (unsigned)ci.revision, (unsigned)ci.cores);
    uint32_t fsz = 0;
    if (esp_flash_get_size(NULL, &fsz) == ESP_OK && fsz) jb_add(&j, ",\"flash_mb\":%lu", (unsigned long)(fsz >> 20));
    jb_add(&j, ",\"heap_max_kb\":%lu,\"tasks\":%u",
           (unsigned long)(heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT) / 1024), (unsigned)uxTaskGetNumberOfTasks());
    /* v10: free stack (bytes, lowest since start) of the busy tasks */
    {
        static const char *const tn[] = { "httpd", "tiT", "wifi", "sys_evt" };
        jb_add(&j, ",\"stk\":{");
        int k = 0;
        for (size_t i = 0; i < sizeof(tn) / sizeof(tn[0]); i++) {
            TaskHandle_t th = xTaskGetHandle(tn[i]);
            if (th) jb_add(&j, "%s\"%s\":%u", k++ ? "," : "", tn[i], (unsigned)uxTaskGetStackHighWaterMark(th));
        }
        if (s_temp_th) jb_add(&j, "%s\"c5_temp\":%u", k++ ? "," : "", (unsigned)uxTaskGetStackHighWaterMark(s_temp_th));
        if (s_cfg_th) jb_add(&j, "%s\"c5_cfg\":%u", k++ ? "," : "", (unsigned)uxTaskGetStackHighWaterMark(s_cfg_th));
#if C5_WITH_DIAG
        TaskHandle_t dt = c5_diag_task_handle();
        if (dt) jb_add(&j, "%s\"c5_diag\":%u", k++ ? "," : "", (unsigned)uxTaskGetStackHighWaterMark(dt));
#endif
        jb_add(&j, "},\"lm_drop\":%lu,\"lm_wait\":%lu", (unsigned long)s_lm_drop, (unsigned long)s_lm_wait);
    }

    wifi_mode_t mode;
    if (esp_wifi_get_mode(&mode) == ESP_OK) {
        jb_add(&j, ",\"mode\":\"%s\"", mode == WIFI_MODE_AP ? "AP" : mode == WIFI_MODE_STA ? "STA" :
                                       mode == WIFI_MODE_APSTA ? "AP+STA" : "off");
    }
    wifi_country_t cc;
    if (esp_wifi_get_country(&cc) == ESP_OK && cc.cc[0]) {
        jb_add(&j, ",\"cc\":\"%c%c\",\"cc_ch\":\"%u-%u\"", cc.cc[0] >= 32 ? cc.cc[0] : '?', cc.cc[1] >= 32 ? cc.cc[1] : '?',
               (unsigned)cc.schan, (unsigned)(cc.schan + cc.nchan - 1));
    }
    wifi_config_t wc;
    memset(&wc, 0, sizeof(wc));
    if (esp_wifi_get_config(WIFI_IF_AP, &wc) == ESP_OK && wc.ap.ssid[0]) {
        char ss[33];
        memcpy(ss, wc.ap.ssid, 32);
        ss[32] = 0;
        json_escape(tmp, ss, sizeof(tmp));
        jb_add(&j, ",\"ap_ssid\":\"%s\",\"ap_auth\":\"%s\",\"ap_hidden\":%d,\"ap_max\":%u", tmp, auth_name(wc.ap.authmode),
               wc.ap.ssid_hidden ? 1 : 0, (unsigned)wc.ap.max_connection);
    }
    uint8_t m6[6];
    if (esp_wifi_get_mac(WIFI_IF_AP, m6) == ESP_OK) { mac_str(mac, m6); jb_add(&j, ",\"ap_mac\":\"%s\"", mac); }
    if (esp_wifi_get_mac(WIFI_IF_STA, m6) == ESP_OK) { mac_str(mac, m6); jb_add(&j, ",\"sta_mac\":\"%s\"", mac); }
    /* v11.6: report the configured RF profile, not the live AP mask */
    if (s_prof_pr2 || s_prof_pr5) {
        jb_add(&j, ",\"ap_pr2\":%u,\"ap_pr5\":%u", (unsigned)s_prof_pr2, (unsigned)s_prof_pr5);
    } else {
        wifi_protocols_t pr;
        if (esp_wifi_get_protocols(WIFI_IF_AP, &pr) == ESP_OK) {
            jb_add(&j, ",\"ap_pr2\":%u,\"ap_pr5\":%u", (unsigned)pr.ghz_2g, (unsigned)pr.ghz_5g);
        }
    }
    wifi_ap_record_t ar;
    memset(&ar, 0, sizeof(ar));
    if (esp_wifi_sta_get_ap_info(&ar) == ESP_OK) {
        char ss[33];
        memcpy(ss, ar.ssid, 32);
        ss[32] = 0;
        json_escape(tmp, ss, sizeof(tmp));
        mac_str(mac, ar.bssid);
        jb_add(&j, ",\"sta_ssid\":\"%s\",\"sta_bssid\":\"%s\",\"sta_rssi\":%d,\"sta_ch\":%u", tmp, mac, ar.rssi, (unsigned)ar.primary);
    }
    jb_add(&j, ",\"alias_ip\":\"%u.%u.%u.%u\",\"alias_up\":%d,\"mdns\":\"vnci.local\",\"sta_link\":%d",
           s_alias_ip[0], s_alias_ip[1], s_alias_ip[2], s_alias_ip[3], s_alias_ready ? 1 : 0,
           s_sta_link_up ? 1 : 0);
    jb_add(&j, ",\"ui_ip\":\"%u.%u.%u.%u\",\"host_ip\":\"%u.%u.%u.%u\",\"host_ip_learned\":%d",
           uip[0], uip[1], uip[2], uip[3], hip[0], hip[1], hip[2], hip[3],
           (s_host_ip_learned || s_host_ip_sta_valid) ? 1 : 0);
    jb_add(&j, ",\"mdns_q\":%lu,\"mdns_resp\":%lu,\"mdns_txerr\":%lu", (unsigned long)s_mdns_q, (unsigned long)s_mdns_resp, (unsigned long)s_mdns_txerr);
    if (s_host_mac_ok) { mac_str(mac, s_host_mac); jb_add(&j, ",\"host_mac\":\"%s\"", mac); }
    jb_add(&j, ",\"h2w\":%lu,\"ev\":{\"ap_start\":%lu,\"ap_conn\":%lu,\"ap_disc\":%lu,\"sta_conn\":%lu,\"sta_disc\":%lu",
           (unsigned long)s_h2w_pkts, (unsigned long)s_ev_ap_start, (unsigned long)s_ev_ap_conn, (unsigned long)s_ev_ap_disc,
           (unsigned long)s_ev_sta_conn, (unsigned long)s_ev_sta_disc);
    if (s_ev_sta_disc) jb_add(&j, ",\"disc_reason\":%u", (unsigned)s_last_disc_reason);
    jb_add(&j, "},\"stas\":[");
    wifi_sta_list_t sl;
    memset(&sl, 0, sizeof(sl));
    if (esp_wifi_ap_get_sta_list(&sl) == ESP_OK) {
        for (int i = 0; i < sl.num && i < ESP_WIFI_MAX_CONN_NUM; i++) {
            char ph[24];
            phy_str(ph, sizeof(ph), &sl.sta[i]);
            mac_str(mac, sl.sta[i].mac);
            jb_add(&j, "%s{\"mac\":\"%s\",\"rssi\":%d,\"phy\":\"%s\"}", i ? "," : "", mac, sl.sta[i].rssi, ph);
        }
    }
    jb_add(&j, "]}");
    httpd_resp_set_type(req, "application/json; charset=utf-8");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    /* v11.2: a cut object is invalid JSON - answer with a short valid one instead */
    if (j.len < 2 || buf[j.len - 1] != '}') {
        return httpd_resp_sendstr(req, "{\"ok\":false,\"err\":\"info too long\"}");
    }
    return httpd_resp_send(req, buf, (ssize_t)j.len);
}

/* v9: shared host link (reboot request, diag task) */
void c5_web_host_link_acquire(bool diag)
{
    portENTER_CRITICAL(&s_link_mux);
    s_link_users++;
    if (diag) s_diag_users++;
    s_diag_mode = s_diag_users > 0;
    s_host_link_on = true;
    portEXIT_CRITICAL(&s_link_mux);
}

void c5_web_host_link_release(bool diag)
{
    /* v11.1: diag mode must survive while another diag user still holds the link */
    portENTER_CRITICAL(&s_link_mux);
    if (s_link_users > 0) s_link_users--;
    if (diag && s_diag_users > 0) s_diag_users--;
    s_diag_mode = s_diag_users > 0;
    if (s_link_users == 0) s_host_link_on = false;
    portEXIT_CRITICAL(&s_link_mux);
}

bool c5_web_nvs_locked(void)
{
    return s_nvs_locked;
}

bool c5_web_host_ip_get(uint8_t ip[4])
{
    host_ip_current(ip);
    return s_host_ip_learned || s_host_ip_sta_valid;
}


/* v11.3: set the router-subnet address of the web UI (POST /api/alias) */
static esp_err_t h_alias(httpd_req_t *req)
{
    char q[192] = "", v[24];
    uint8_t ip[4] = { 0, 0, 0, 0 }, mask[4] = { 255, 255, 255, 0 }, gw[4] = { 0, 0, 0, 0 };
    if (httpd_req_get_url_query_str(req, q, sizeof(q)) != ESP_OK) {
        return httpd_resp_sendstr(req, "{\"ok\":false,\"err\":\"no query\"}");
    }
    if (httpd_query_key_value(q, "ip", v, sizeof(v)) != ESP_OK || !ip4_text_parse(v, ip)) {
        return httpd_resp_sendstr(req, "{\"ok\":false,\"err\":\"bad ip\"}");
    }
    if (httpd_query_key_value(q, "mask", v, sizeof(v)) == ESP_OK && !ip4_text_parse(v, mask)) {
        return httpd_resp_sendstr(req, "{\"ok\":false,\"err\":\"bad mask\"}");
    }
    if (httpd_query_key_value(q, "gw", v, sizeof(v)) == ESP_OK && !ip4_text_parse(v, gw)) {
        return httpd_resp_sendstr(req, "{\"ok\":false,\"err\":\"bad gw\"}");
    }
    if (ip[0] == C5_UI_IP_B0 && ip[1] == C5_UI_IP_B1 && ip[2] == C5_UI_IP_B2 &&
        (ip[3] == C5_UI_IP_B3 || ip[3] == 54)) {
        return httpd_resp_sendstr(req, "{\"ok\":false,\"err\":\"address reserved\"}");
    }
    if (s_nvs_locked) return httpd_resp_sendstr(req, "{\"ok\":false,\"err\":\"nvs locked until reboot\"}");
    char si[24], sm[24], sg[24];
    snprintf(si, sizeof(si), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
    snprintf(sm, sizeof(sm), "%u.%u.%u.%u", mask[0], mask[1], mask[2], mask[3]);
    snprintf(sg, sizeof(sg), "%u.%u.%u.%u", gw[0], gw[1], gw[2], gw[3]);
    nvs_handle_t h;
    esp_err_t e = nvs_open("c5_cfg", NVS_READWRITE, &h);
    if (e == ESP_OK) {
        nvs_set_str(h, "al_ip", si);
        nvs_set_str(h, "al_mask", sm);
        nvs_set_str(h, "al_gw", sg);
        e = nvs_commit(h);
        nvs_close(h);
    }
    if (e != ESP_OK) return httpd_resp_sendstr(req, "{\"ok\":false,\"err\":\"nvs write failed\"}");
    memcpy(s_alias_cfg_ip, ip, 4);       /* v11.5: 0.0.0.0 = back to automatic */
    memcpy(s_alias_mask, mask, 4);
    memcpy(s_alias_gw, gw, 4);
    c5_post_job(C5_JOB_ALIAS);
    mdns_start_once();
    return httpd_resp_sendstr(req, "{\"ok\":true}");
}

static esp_err_t h_reboot(httpd_req_t *req)
{
    char ip[16], pe[8], pass[48], err[112] = "";
    bool answered = false;
    uint8_t hip[4];
    host_ip_current(hip);
    snprintf(ip, sizeof(ip), "%u.%u.%u.%u", hip[0], hip[1], hip[2], hip[3]);
    bool learned = s_host_ip_learned || s_host_ip_sta_valid;
    c5_web_host_link_acquire(false);
    esp_err_t e = host_get_asys(ip, pe, sizeof(pe), pass, sizeof(pass), err, sizeof(err));
    if (e == ESP_OK) e = host_post_reboot(ip, pe, pass, &answered, err, sizeof(err));
    c5_web_host_link_release(false);
    memset(pass, 0, sizeof(pass));
    ESP_LOGI(TAG, "host reboot via %s (%s): %s %s", ip, learned ? "learned" : "default",
             e == ESP_OK ? "sent" : "FAILED", err);

    char out[256];
    if (e == ESP_OK) {
        snprintf(out, sizeof(out), "{\"ok\":true,\"host\":\"%s\",\"answered\":%s}", ip, answered ? "true" : "false");
    } else {
        for (char *c = err; *c; c++) if (*c == '"' || *c == '\\') *c = '\'';
        snprintf(out, sizeof(out), "{\"ok\":false,\"host\":\"%s\",\"err\":\"%s\"}", ip, err);
    }
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, out);
}

typedef struct { SemaphoreHandle_t done; } netif_setup_ctx_t;

static void netif_setup_cb(void *arg)
{
    netif_setup_ctx_t *ctx = (netif_setup_ctx_t *)arg;
    if (!s_netif_ready) {
        ip4_addr_t ipaddr, netmask, gw;
        IP4_ADDR(&ipaddr, C5_UI_IP_B0, C5_UI_IP_B1, C5_UI_IP_B2, C5_UI_IP_B3);
        IP4_ADDR(&netmask, 255, 255, 255, 0);
        IP4_ADDR(&gw, C5_UI_IP_B0, C5_UI_IP_B1, C5_UI_IP_B2, C5_UI_IP_B3);
        if (netif_add(&s_lwip_netif, &ipaddr, &netmask, &gw, NULL, lwip_ui_netif_init, tcpip_input) != NULL) {
            netif_set_default(&s_lwip_netif);
            netif_set_link_up(&s_lwip_netif);
            netif_set_up(&s_lwip_netif);
            s_netif_ready = true;
            mdns_start_once();               /* v11.3: vnci.local */
        }
    }
    if (ctx && ctx->done) xSemaphoreGive(ctx->done);
}

static void ui_server_task(void *arg)
{
    (void)arg;

    /* 1. TCP/IP thread (no-op if already running) + our netif, inside tcpip thread */
    if (esp_netif_init() == ESP_OK) {
        netif_setup_ctx_t ctx = { .done = xSemaphoreCreateBinary() };
        if (ctx.done && tcpip_callback(netif_setup_cb, &ctx) == ERR_OK) {
            xSemaphoreTake(ctx.done, pdMS_TO_TICKS(5000));
        }
        if (ctx.done) vSemaphoreDelete(ctx.done);
    }

    /* 2. HTTP server: sockets = max_open_sockets + 3 must be <= CONFIG_LWIP_MAX_SOCKETS */
    httpd_config_t hcfg = HTTPD_DEFAULT_CONFIG();
    hcfg.server_port = 80;
    hcfg.task_priority = 5;
    hcfg.stack_size = 6144;
    hcfg.max_open_sockets = (CONFIG_LWIP_MAX_SOCKETS - 3) < 4 ? (CONFIG_LWIP_MAX_SOCKETS - 3) : 4;
    hcfg.max_uri_handlers = 24;
    hcfg.lru_purge_enable = true;
    hcfg.recv_wait_timeout = 10;
    hcfg.send_wait_timeout = 10;

    httpd_handle_t srv = NULL;
    for (int i = 0; i < 10 && srv == NULL; i++) {
        if (httpd_start(&srv, &hcfg) != ESP_OK) {
            srv = NULL;
            vTaskDelay(pdMS_TO_TICKS(1000));
        }
    }
    if (srv) {
        const httpd_uri_t uris[] = {
            { "/", HTTP_GET, h_index, NULL },
            { "/api/telemetry", HTTP_GET, h_telemetry, NULL },
            { "/api/speedtest", HTTP_GET, h_speedtest, NULL },
            { "/api/speedtest", HTTP_POST, h_speedtest, NULL },
            { "/api/nvs", HTTP_GET, h_nvs, NULL },
            { "/api/nvs", HTTP_POST, h_nvs, NULL },
            { "/api/nvs_reset", HTTP_POST, h_nvs_reset, NULL },
            { "/api/nvs_clear_sta", HTTP_POST, h_nvs_clear_sta, NULL },
            { "/api/scan", HTTP_GET, h_scan, NULL },
            { "/api/backup", HTTP_GET, h_backup, NULL },
            { "/api/ota", HTTP_POST, h_ota, NULL },
            { "/api/slot", HTTP_POST, h_slot, NULL },
            { "/api/reboot", HTTP_POST, h_reboot, NULL },
            { "/api/alias", HTTP_POST, h_alias, NULL },      /* v11.3 */
            { "/api/info", HTTP_GET, h_info, NULL },
        };
        for (size_t i = 0; i < sizeof(uris) / sizeof(uris[0]); i++) {
            httpd_register_uri_handler(srv, &uris[i]);
        }
#if C5_WITH_DIAG
        c5_diag_register(srv);     /* v9: /diag page + /api/diag (DoIP, own task) */
        c5_power_register(srv);    /* v11: /api/power, /api/power_cfg (KL30 / KL15 tile on /diag) */
#endif
    }
    vTaskDelete(NULL);
}

void c5_web_server_start(void)
{
    if (s_srv_started) return;
    s_srv_started = true;
    s_cfg_mtx = xSemaphoreCreateMutex();
    s_tsens_mtx = xSemaphoreCreateMutex();
    c5_load_overrides();                 /* v11.2: before any task / hook can read the config */
    esp_err_t le = esp_event_loop_create_default();
    if (le != ESP_OK && le != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "event loop: %s", esp_err_to_name(le));
    }
    esp_err_t he = esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, c5_wifi_evt, NULL);
    if (he != ESP_OK) ESP_LOGE(TAG, "wifi evt register: %s", esp_err_to_name(he));
    xTaskCreate(c5_temp_task, "c5_temp", 3072, NULL, 1, &s_temp_th);
    s_job_q = xQueueCreate(4, sizeof(uint8_t));
    if (s_job_q) xTaskCreate(c5_worker_task, "c5_cfg", 3584, NULL, 4, &s_cfg_th);
    if (sta_is_connected()) {                /* v11.3: STA may already be up */
        s_sta_link_up = true;
        c5_post_job(C5_JOB_ALIAS);
    }
    xTaskCreate(ui_server_task, "c5_ui", 4096, NULL, 5, NULL);
}
