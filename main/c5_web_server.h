/*
 * VNCI 6154B / ESP32-C5: local web UI on 192.168.61.250 (served by the C5 itself,
 * next to esp-hosted). Hooks used by esp_hosted_coprocessor.c and slave_wifi_std.c.
 */
#pragma once
#include <stdbool.h>
#include <stdint.h>
#include "esp_wifi.h"

#ifdef __cplusplus
extern "C" {
#endif

/* app_main: load NVS overrides, start TCP/IP + private netif + httpd */
void c5_web_server_start(void);

/* Wi-Fi RX path (AP/STA callbacks). true = frame belongs to the web UI,
 * it was copied into lwIP, caller must free eb and NOT send it to host. */
bool c5_webui_rx_intercept(wifi_interface_t ifx, void *buf, uint16_t len);

/* v6, host -> Wi-Fi path (process_rx_pkt): learns the host IP / MAC from its frames; while the
 * web UI talks to the host (reboot request) frames for 192.168.61.250 are copied into the
 * web UI lwIP. true = consumed, caller must NOT send it on air. */
bool c5_webui_host_tx_intercept(wifi_interface_t ifx, const void *buf, uint16_t len);

/* v6, esp_hosted_coprocessor.c: frame (malloc()ed, ownership taken) to the host as Wi-Fi RX of ifx */
int c5_hosted_frame_to_host(wifi_interface_t ifx, void *buf, uint16_t len);

/* req_wifi_set_config: apply NVS SSID/pass/channel overrides (AP) */
void c5_apply_wifi_overrides(wifi_interface_t ifx, wifi_config_t *cfg);

/* right before esp_wifi_start(): country + protocol/bandwidth profile (AP starts with HT40) */
void c5_before_wifi_start(void);

/* after esp_wifi_start(): country, protocol/bandwidth profile, TX power */
void c5_on_wifi_started(void);

/* event_handler_wifi(): true = event belongs to a web UI scan, do not forward to host */
bool c5_webui_suppress_wifi_event(int32_t event_id);

/* v4 web scan switches a host 2G_ONLY / 5G_ONLY band mode to AUTO for the scan:
 * true + host value while switched (req_wifi_get_band_mode reports the host value) */
bool c5_webui_scan_band_mode(wifi_band_mode_t *band_mode);
/* req_wifi_set_band_mode / set_band / set_channel succeeded: the web scan must not restore its saved value */
void c5_webui_host_band_changed(void);

/* re-apply profile after host changed protocols/bandwidths */
void c5_apply_rf_profile(void);

/* TX power in 0.25 dBm units the slave enforces (host requests are raised to this) */
int8_t c5_tx_power_qdbm(void);
void c5_apply_tx_power(void);

/* v9: host link shared by the reboot request and the diag task (frames web UI <-> host);
 * diag=true also routes ARP / UDP-13400 broadcasts to the host and copies host DoIP broadcasts */
void c5_web_host_link_acquire(bool diag);
void c5_web_host_link_release(bool diag);
/* host IP seen on the host -> Wi-Fi path (192.168.61.54 until learned); true = learned */
bool c5_web_host_ip_get(uint8_t ip[4]);

/* v11: true = raw nvs partition was restored, no NVS writes until reboot */
bool c5_web_nvs_locked(void);

/* v11 c5_power.c: register /api/power (GET) and /api/power_cfg (POST); its task runs only while polled */
void c5_power_register(void *httpd_handle);  /* httpd_handle_t */

/* v9 c5_diag.c: register /diag, /api/diag on the web UI httpd and start the diag task */
void c5_diag_register(void *httpd_handle);   /* httpd_handle_t */
/* v10 c5_diag.c: diag task (stack watermark in /api/info), NULL before start */
void *c5_diag_task_handle(void);

/* v10 heap guard helpers (c5_web_server.c) */
void c5_heap_wait(void);                                   /* httpd / sender tasks only */
void c5_heap_stats(uint32_t *free_b, uint32_t *min_b, uint32_t *lfb_b);
/* 4 KB scratch buffer, httpd task only (handlers run one at a time) */
uint8_t *c5_web_io_buf(size_t *cap);

#ifdef __cplusplus
}
#endif
