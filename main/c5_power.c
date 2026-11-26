/*
 * VNCI 6154B / ESP32-C5 web_v11: supply voltage tile on /diag (KL30 = OBD pin 16, KL15 = ignition).
 *
 * Sources, first valid one wins (per terminal):
 *   1. ADC of the C5 (GPIO 1..6 = ADC1 ch0..5) through a resistor divider. OFF by default: it is NOT known
 *      whether any C5 pin is wired to the OBD supply on the VNCI 6154B board. GPIO / divider / offset are
 *      set at runtime (POST /api/power_cfg, NVS namespace "c5_pwr").
 *   2. The VNCI host's own web page (P4, http://<host>/cgi-bin/formular.fcgi/GSINF "System information"):
 *      <formdata key=..> values whose key or caption looks like a voltage / terminal 30 / 15 are shown.
 *      Whether the host page carries a voltage at all is NOT verified; GET /api/power returns all keys
 *      seen ("keys") so the right one can be pinned with hk30 / hk15.
 * The task runs only while someone polls GET /api/power (stops 30 s after the last poll, frees its stack).
 * Heap (v10 guards): idle cost ~0.6 KB static; while polled ~4 KB work buffers + 4 KB task stack; the task does not start
 * below 24 KB free heap and skips the host page below 20 KB. JSON is built in the httpd scratch buffer (no malloc).
 * Not verified on hardware.
 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_http_server.h"
#include "esp_timer.h"
#include "esp_system.h"
#include "esp_log.h"
#include "nvs.h"
#include "lwip/sockets.h"
#include "esp_adc/adc_oneshot.h"
#include "esp_adc/adc_cali.h"
#include "esp_adc/adc_cali_scheme.h"
#include "c5_web_server.h"

static const char *TAG = "c5_pwr";

#define PWR_NS       "c5_pwr"
#define NMAX         6
#define KEYS_MAX     320
#define WIN_SZ       1024
#define RX_SZ        384
#define HOST_TMO_MS  3000
#define HOST_DL_MS   6000
#define HOST_MIN_MS  3000
#define IDLE_STOP_MS 30000
#define HEAP_START   (24 * 1024)   /* do not start the task below this free heap */
#define HEAP_FETCH   (20 * 1024)   /* skip the host page below this (= C5_HEAP_TX_GUARD) */

typedef struct {
    int8_t g30, g15;          /* ADC GPIO, -1 = off */
    uint32_t k30, k15;        /* divider ratio x1000 */
    int16_t o30, o15;         /* offset, mV */
    uint8_t host;             /* host web page source on */
    char form[8];             /* host form id */
    char hk30[24], hk15[24];  /* pinned host keys, "" = auto */
    uint16_t per;             /* ms */
} pwr_cfg_t;

typedef struct { char k[24]; char n[48]; char v[48]; int c; } pitem_t;

typedef struct {
    bool done, ok;
    char err[72];
    int64_t ts;
    pitem_t it[NMAX];
    int n;
    char keys[KEYS_MAX + 1];
} phost_t;

typedef struct { bool on, ok; int mv; float v; } pch_t;

typedef struct { char k[24]; char n[48]; } pname_t;

/* RAM only while the task runs (heap is tight on the C5): malloc'ed by task_kick, freed when the task stops */
typedef struct {
    phost_t pub;                 /* last finished host fetch (under s_mtx) */
    phost_t hw;                  /* host fetch under construction (task only) */
    char win[WIN_SZ];
    char rx[RX_SZ];
    pname_t names[NMAX];
} pwork_t;
static pwork_t *s_w;

static SemaphoreHandle_t s_mtx;
static pwr_cfg_t s_cfg;
static uint32_t s_gen = 1;
static pch_t s_a30, s_a15;               /* last ADC (under s_mtx) */
static bool s_cal;
static char s_adc_err[48];
static int64_t s_last_poll, s_last_cycle = -1;
static volatile bool s_task_on;

/* task-only */
static adc_oneshot_unit_handle_t s_unit;
static adc_cali_handle_t s_cali;
static int s_ch30 = -1, s_ch15 = -1;
static uint32_t s_adc_gen;

static int64_t now_ms(void) { return esp_timer_get_time() / 1000; }

/* ---------- config ---------- */

static void cfg_defaults(pwr_cfg_t *c)
{
    memset(c, 0, sizeof(*c));
    c->g30 = c->g15 = -1;
    c->k30 = c->k15 = 11000;
    c->host = 1;
    strcpy(c->form, "GSINF");
    c->per = 2000;
}

static bool gpio_ok(int g) { return g == -1 || (g >= 1 && g <= 6); }

static bool form_ok(const char *s)
{
    size_t n = strlen(s);
    if (n < 1 || n > 7) return false;
    for (; *s; s++) if (!((*s >= 'A' && *s <= 'Z') || (*s >= '0' && *s <= '9') || *s == '_')) return false;
    return true;
}

static bool hk_ok(const char *s)
{
    if (strlen(s) > 23) return false;
    for (; *s; s++) {
        char c = *s;
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-')) return false;
    }
    return true;
}

static void cfg_load(pwr_cfg_t *c)
{
    cfg_defaults(c);
    nvs_handle_t h;
    if (nvs_open(PWR_NS, NVS_READONLY, &h) != ESP_OK) return;
    size_t l;
    nvs_get_i8(h, "g30", &c->g30);
    nvs_get_i8(h, "g15", &c->g15);
    nvs_get_u32(h, "k30", &c->k30);
    nvs_get_u32(h, "k15", &c->k15);
    nvs_get_i16(h, "o30", &c->o30);
    nvs_get_i16(h, "o15", &c->o15);
    nvs_get_u8(h, "host", &c->host);
    l = sizeof(c->form); if (nvs_get_str(h, "form", c->form, &l) != ESP_OK) strcpy(c->form, "GSINF");
    l = sizeof(c->hk30); if (nvs_get_str(h, "hk30", c->hk30, &l) != ESP_OK) c->hk30[0] = 0;
    l = sizeof(c->hk15); if (nvs_get_str(h, "hk15", c->hk15, &l) != ESP_OK) c->hk15[0] = 0;
    nvs_get_u16(h, "per", &c->per);
    nvs_close(h);
    /* sanitize whatever is stored */
    pwr_cfg_t d; cfg_defaults(&d);
    if (!gpio_ok(c->g30)) c->g30 = -1;
    if (!gpio_ok(c->g15)) c->g15 = -1;
    if (c->k30 < 1000 || c->k30 > 200000) c->k30 = d.k30;
    if (c->k15 < 1000 || c->k15 > 200000) c->k15 = d.k15;
    if (c->o30 < -5000 || c->o30 > 5000) c->o30 = 0;
    if (c->o15 < -5000 || c->o15 > 5000) c->o15 = 0;
    if (c->host > 1) c->host = 1;
    if (!form_ok(c->form)) strcpy(c->form, d.form);
    if (!hk_ok(c->hk30)) c->hk30[0] = 0;
    if (!hk_ok(c->hk15)) c->hk15[0] = 0;
    if (c->per < 1000 || c->per > 3000) c->per = d.per;
}

static esp_err_t cfg_save(const pwr_cfg_t *c)
{
    nvs_handle_t h;
    esp_err_t e = nvs_open(PWR_NS, NVS_READWRITE, &h), r = ESP_OK;
    if (e != ESP_OK) return e;
    if ((e = nvs_set_i8(h, "g30", c->g30)) != ESP_OK) r = e;
    if ((e = nvs_set_i8(h, "g15", c->g15)) != ESP_OK) r = e;
    if ((e = nvs_set_u32(h, "k30", c->k30)) != ESP_OK) r = e;
    if ((e = nvs_set_u32(h, "k15", c->k15)) != ESP_OK) r = e;
    if ((e = nvs_set_i16(h, "o30", c->o30)) != ESP_OK) r = e;
    if ((e = nvs_set_i16(h, "o15", c->o15)) != ESP_OK) r = e;
    if ((e = nvs_set_u8(h, "host", c->host)) != ESP_OK) r = e;
    if ((e = nvs_set_str(h, "form", c->form)) != ESP_OK) r = e;
    if ((e = nvs_set_str(h, "hk30", c->hk30)) != ESP_OK) r = e;
    if ((e = nvs_set_str(h, "hk15", c->hk15)) != ESP_OK) r = e;
    if ((e = nvs_set_u16(h, "per", c->per)) != ESP_OK) r = e;
    if ((e = nvs_commit(h)) != ESP_OK) r = e;
    nvs_close(h);
    return r;
}

static esp_err_t cfg_erase(void)
{
    nvs_handle_t h;
    esp_err_t e = nvs_open(PWR_NS, NVS_READWRITE, &h);
    if (e != ESP_OK) return e;
    e = nvs_erase_all(h);
    if (e == ESP_OK) e = nvs_commit(h);
    nvs_close(h);
    return e;
}

/* ---------- text helpers ---------- */

static char lc(char c) { return (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c; }

static bool ci_has(const char *h, const char *n)
{
    size_t nl = strlen(n);
    for (; *h; h++) {
        size_t i = 0;
        while (i < nl && h[i] && lc(h[i]) == lc(n[i])) i++;
        if (i == nl) return true;
    }
    return false;
}

static const char *const KW_ASCII[] = { "volt", "spann", "batt", "ubat", "u_bat", "vbat", "kl30", "kl.30", "kl 30",
    "kl_30", "kl15", "kl.15", "kl 15", "kl_15", "clamp", "terminal", "ignition", "supply" };
static const char *const KW_UTF8[] = { "z\xc3\xbcnd", "Z\xc3\xbcnd",                                /* zünd */
    "\xd0\xbd\xd0\xb0\xd0\xbf\xd1\x80\xd1\x8f\xd0\xb6", "\xd0\x9d\xd0\xb0\xd0\xbf\xd1\x80\xd1\x8f\xd0\xb6", /* напряж */
    "\xd0\xb7\xd0\xb0\xd0\xb6\xd0\xb8\xd0\xb3", "\xd0\x97\xd0\xb0\xd0\xb6\xd0\xb8\xd0\xb3",               /* зажиг */
    "\xd0\xba\xd0\xbb\xd0\xb5\xd0\xbc", "\xd0\x9a\xd0\xbb\xd0\xb5\xd0\xbc" };                              /* клем */

static bool kw(const char *s)
{
    if (!s || !*s) return false;
    for (size_t i = 0; i < sizeof(KW_ASCII) / sizeof(KW_ASCII[0]); i++) if (ci_has(s, KW_ASCII[i])) return true;
    for (size_t i = 0; i < sizeof(KW_UTF8) / sizeof(KW_UTF8[0]); i++) if (strstr(s, KW_UTF8[i])) return true;
    return false;
}

static int cls_of(const char *k, const char *n)
{
    const char *s[2] = { k, n };
    for (int i = 0; i < 2; i++) {
        if (!s[i]) continue;
        if (strstr(s[i], "15") || ci_has(s[i], "ign") || strstr(s[i], KW_UTF8[0]) || strstr(s[i], KW_UTF8[1]) ||
            strstr(s[i], KW_UTF8[4]) || strstr(s[i], KW_UTF8[5])) return 15;
    }
    return 30;
}

/* decode XML entities of [a,e) into out (trimmed) */
static void xml_text(const char *a, const char *e, char *out, size_t cap)
{
    static const struct { const char *ent; char c; } ents[] = {
        { "&amp;", '&' }, { "&lt;", '<' }, { "&gt;", '>' }, { "&quot;", '"' }, { "&apos;", '\'' }, { "&#160;", ' ' }, { "&nbsp;", ' ' } };
    size_t o = 0;
    while (a < e && (*a == ' ' || *a == '\t' || *a == '\r' || *a == '\n')) a++;
    while (a < e && o + 1 < cap) {
        char c = *a; size_t adv = 1;
        if (c == '&') {
            for (size_t i = 0; i < sizeof(ents) / sizeof(ents[0]); i++) {
                size_t l = strlen(ents[i].ent);
                if ((size_t)(e - a) >= l && !strncmp(a, ents[i].ent, l)) { c = ents[i].c; adv = l; break; }
            }
        }
        out[o++] = c; a += adv;
    }
    while (o && (out[o - 1] == ' ' || out[o - 1] == '\t' || out[o - 1] == '\r' || out[o - 1] == '\n')) o--;
    out[o] = 0;
}

/* first number in s, "mV"/"мВ" -> /1000; valid 0..40 V. strict (auto-picked keys): the value must carry
 * a unit V / В or a decimal separator, so on/off flags like "1" are not shown as volts */
static bool volts_of(const char *s, float *out, bool strict)
{
    bool unit = strchr(s, 'V') || strstr(s, "\xd0\x92");
    while (*s && !(*s >= '0' && *s <= '9')) s++;
    if (!*s) return false;
    double v = 0, f = 0.1;
    while (*s >= '0' && *s <= '9') v = v * 10 + (*s++ - '0');
    if ((*s == '.' || *s == ',') && s[1] >= '0' && s[1] <= '9') {
        s++;
        while (*s >= '0' && *s <= '9') { v += (*s++ - '0') * f; f /= 10; }
        unit = true;
    }
    if (strict && !unit) return false;
    while (*s == ' ') s++;
    if ((s[0] == 'm' && s[1] == 'V') || !strncmp(s, "\xd0\xbc\xd0\x92", 4)) v /= 1000.0;
    if (v < 0.0 || v > 40.0) return false;
    *out = (float)v;
    return true;
}

/* attribute value of key="..." inside tag [a,e) */
static bool attr_key(const char *a, const char *e, char *out, size_t cap)
{
    for (const char *p = a + 1; p + 5 < e; p++) {
        if ((p[-1] == ' ' || p[-1] == '\t' || p[-1] == '\n') && !strncmp(p, "key=\"", 5)) {
            p += 5;
            size_t o = 0;
            while (p < e && *p != '"' && o + 1 < cap) out[o++] = *p++;
            out[o] = 0;
            return p < e && *p == '"';
        }
    }
    return false;
}

/* ---------- host page parser (task only) ---------- */

static int s_nn;
static char s_pkey[24];
static bool s_pname_done;

static const char *name_of(const char *k)
{
    for (int i = 0; i < s_nn; i++) if (!strcmp(s_w->names[i].k, k)) return s_w->names[i].n;
    return NULL;
}

static void on_formdata(const pwr_cfg_t *c, const char *k, const char *v)
{
    size_t cur = strlen(s_w->hw.keys), kl = strlen(k);
    if (cur + kl + 2 <= KEYS_MAX) {
        if (cur) s_w->hw.keys[cur++] = ',';
        memcpy(s_w->hw.keys + cur, k, kl + 1);
    }
    const char *n = name_of(k);
    bool p30 = c->hk30[0] && !strcmp(k, c->hk30), p15 = c->hk15[0] && !strcmp(k, c->hk15);
    if (!(p30 || p15 || n || kw(k)) || s_w->hw.n >= NMAX) return;
    pitem_t *it = &s_w->hw.it[s_w->hw.n++];
    snprintf(it->k, sizeof(it->k), "%s", k);
    snprintf(it->n, sizeof(it->n), "%s", n ? n : "");
    snprintf(it->v, sizeof(it->v), "%s", v);
    it->c = p30 ? 30 : p15 ? 15 : cls_of(k, n);
}

/* parse complete elements in s_w->win[0..*wl); keep the incomplete tail */
static void parse_win(const pwr_cfg_t *c, size_t *wl)
{
    char *w = s_w->win, *end = s_w->win + *wl, *p = w;
    for (;;) {
        char *lt = memchr(p, '<', (size_t)(end - p));
        if (!lt) { p = end; break; }
        char *gt = memchr(lt, '>', (size_t)(end - lt));
        if (!gt) { p = lt; break; }
        char *next = gt + 1;
        size_t tl = (size_t)(gt - lt);
        if (tl >= 9 && !strncmp(lt, "<formitem", 9)) {
            if (!attr_key(lt, gt, s_pkey, sizeof(s_pkey))) s_pkey[0] = 0;
            s_pname_done = false;
        } else if (tl >= 10 && !strncmp(lt, "</formitem", 10)) {
            s_pkey[0] = 0;
        } else if (tl >= 5 && !strncmp(lt, "<name", 5) && (lt[5] == '>' || lt[5] == ' ') && s_pkey[0] && !s_pname_done) {
            char *te = memchr(next, '<', (size_t)(end - next));
            if (!te) { p = lt; break; }
            char nm[48];
            xml_text(next, te, nm, sizeof(nm));
            s_pname_done = true;
            if ((kw(s_pkey) || kw(nm)) && s_nn < NMAX) {
                snprintf(s_w->names[s_nn].k, sizeof(s_w->names[0].k), "%s", s_pkey);
                snprintf(s_w->names[s_nn].n, sizeof(s_w->names[0].n), "%s", nm);
                s_nn++;
            }
            next = te;
        } else if (tl >= 9 && !strncmp(lt, "<formdata", 9) && gt[-1] != '/') {
            char *te = memchr(next, '<', (size_t)(end - next));
            if (!te) { p = lt; break; }
            char k[24], v[48];
            if (attr_key(lt, gt, k, sizeof(k))) {
                xml_text(next, te, v, sizeof(v));
                on_formdata(c, k, v);
            }
            next = te;
        }
        p = next;
    }
    size_t keep = (size_t)(end - p);
    if (keep == *wl && keep >= WIN_SZ - 1) keep = 0;       /* one element larger than the window: drop it */
    if (keep && p != w) memmove(w, p, keep);
    *wl = keep;
}

static int host_connect(const uint8_t ip[4])
{
    struct sockaddr_in sa = { 0 };
    sa.sin_family = AF_INET;
    sa.sin_port = htons(80);
    memcpy(&sa.sin_addr.s_addr, ip, 4);
    int s = lwip_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s < 0) return -1;
    int fl = lwip_fcntl(s, F_GETFL, 0);
    lwip_fcntl(s, F_SETFL, fl | O_NONBLOCK);
    int r = lwip_connect(s, (struct sockaddr *)&sa, sizeof(sa));
    if (r < 0 && errno != EINPROGRESS) { lwip_close(s); return -1; }
    if (r < 0) {
        fd_set wf; FD_ZERO(&wf); FD_SET(s, &wf);
        struct timeval tv = { .tv_sec = HOST_TMO_MS / 1000, .tv_usec = 0 };
        int err = 0; socklen_t el = sizeof(err);
        if (lwip_select(s + 1, NULL, &wf, NULL, &tv) <= 0 ||
            lwip_getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &el) != 0 || err != 0) {
            lwip_close(s);
            return -1;
        }
    }
    lwip_fcntl(s, F_SETFL, fl & ~O_NONBLOCK);
    struct timeval to = { .tv_sec = HOST_TMO_MS / 1000, .tv_usec = 0 };
    lwip_setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &to, sizeof(to));
    lwip_setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &to, sizeof(to));
    return s;
}

static void host_fetch(const pwr_cfg_t *c)
{
    memset(&s_w->hw, 0, sizeof(s_w->hw));
    s_nn = 0; s_pkey[0] = 0; s_pname_done = false;
    uint8_t ip[4];
    c5_web_host_ip_get(ip);
    char ips[16];
    snprintf(ips, sizeof(ips), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
    c5_web_host_link_acquire(false);
    int s = host_connect(ip);
    if (s < 0) {
        snprintf(s_w->hw.err, sizeof(s_w->hw.err), "no connection to %s:80", ips);
    } else {
        char req[160];
        int n = snprintf(req, sizeof(req), "GET /cgi-bin/formular.fcgi/%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", c->form, ips);
        if (lwip_send(s, req, (size_t)n, 0) != n) {
            snprintf(s_w->hw.err, sizeof(s_w->hw.err), "send failed");
        } else {
            int64_t dl = now_ms() + HOST_DL_MS;
            size_t wl = 0;
            bool first = true, timeout = false;
            for (;;) {
                if (now_ms() > dl) { timeout = true; break; }
                int r = lwip_recv(s, s_w->rx, sizeof(s_w->rx), 0);
                if (r <= 0) break;
                if (first) {
                    first = false;
                    if (r < 12 || strncmp(s_w->rx, "HTTP/1.", 7)) { snprintf(s_w->hw.err, sizeof(s_w->hw.err), "no HTTP answer from %s", ips); break; }
                    if (strncmp(s_w->rx + 9, "200", 3)) {
                        snprintf(s_w->hw.err, sizeof(s_w->hw.err), "host page answered %.3s%s", s_w->rx + 9,
                                 !strncmp(s_w->rx + 9, "401", 3) ? " (password protection is on)" : "");
                        break;
                    }
                }
                size_t off = 0;
                while (off < (size_t)r) {
                    size_t room = WIN_SZ - 1 - wl, k = (size_t)r - off;
                    if (k > room) k = room;
                    memcpy(s_w->win + wl, s_w->rx + off, k);
                    wl += k; off += k; s_w->win[wl] = 0;
                    parse_win(c, &wl);
                }
            }
            if (first && !s_w->hw.err[0]) snprintf(s_w->hw.err, sizeof(s_w->hw.err), "no answer from %s (timeout)", ips);
            else if (!s_w->hw.err[0]) {
                s_w->hw.ok = true;
                if (timeout) snprintf(s_w->hw.err, sizeof(s_w->hw.err), "page cut by the 6 s limit");
            }
        }
        lwip_close(s);
    }
    c5_web_host_link_release(false);
    s_w->hw.ts = now_ms();
    s_w->hw.done = true;
}

/* ---------- ADC (task only) ---------- */

static void adc_down(void)
{
    if (s_cali) { adc_cali_delete_scheme_curve_fitting(s_cali); s_cali = NULL; }
    if (s_unit) { adc_oneshot_del_unit(s_unit); s_unit = NULL; }
    s_ch30 = s_ch15 = -1;
}

static int adc_chan(int gpio)
{
    adc_unit_t u; adc_channel_t ch;
    if (gpio < 0 || adc_oneshot_io_to_channel(gpio, &u, &ch) != ESP_OK || u != ADC_UNIT_1) return -1;
    adc_oneshot_chan_cfg_t cc = { .atten = ADC_ATTEN_DB_12, .bitwidth = ADC_BITWIDTH_DEFAULT };
    return adc_oneshot_config_channel(s_unit, ch, &cc) == ESP_OK ? (int)ch : -1;
}

static void adc_up(const pwr_cfg_t *c, char *err, size_t esz)
{
    adc_down();
    if (c->g30 < 0 && c->g15 < 0) return;
    adc_oneshot_unit_init_cfg_t uc = { .unit_id = ADC_UNIT_1, .ulp_mode = ADC_ULP_MODE_DISABLE };
    if (adc_oneshot_new_unit(&uc, &s_unit) != ESP_OK) { s_unit = NULL; snprintf(err, esz, "ADC1 init failed"); return; }
    s_ch30 = adc_chan(c->g30);
    s_ch15 = adc_chan(c->g15);
    adc_cali_curve_fitting_config_t cal = { .unit_id = ADC_UNIT_1, .atten = ADC_ATTEN_DB_12, .bitwidth = ADC_BITWIDTH_DEFAULT };
    if (adc_cali_create_scheme_curve_fitting(&cal, &s_cali) != ESP_OK) s_cali = NULL;
    if ((c->g30 >= 0 && s_ch30 < 0) || (c->g15 >= 0 && s_ch15 < 0)) snprintf(err, esz, "ADC channel config failed");
}

static void adc_one(int ch, uint32_t k, int16_t o, pch_t *out)
{
    memset(out, 0, sizeof(*out));
    if (ch < 0 || !s_unit) return;
    out->on = true;
    int32_t sum = 0;
    for (int i = 0; i < 16; i++) {
        int raw = 0;
        if (adc_oneshot_read(s_unit, (adc_channel_t)ch, &raw) != ESP_OK) return;
        sum += raw;
    }
    int raw = (int)(sum / 16), mv = 0;
    if (!s_cali || adc_cali_raw_to_voltage(s_cali, raw, &mv) != ESP_OK) mv = raw * 3300 / 4095;
    out->mv = mv;
    out->v = ((float)mv * (float)k / 1000.0f + (float)o) / 1000.0f;
    out->ok = true;
}

/* ---------- task ---------- */

static void pwr_task(void *arg)
{
    (void)arg;
    int64_t last_host = -100000;
    static char aerr[48];
    s_adc_gen = 0;
    for (;;) {
        xSemaphoreTake(s_mtx, portMAX_DELAY);
        bool idle = now_ms() - s_last_poll > IDLE_STOP_MS;
        pwr_cfg_t c = s_cfg;
        uint32_t gen = s_gen;
        xSemaphoreGive(s_mtx);
        if (idle) {
            adc_down();                       /* before s_task_on = false: a new task may start right after */
            s_adc_gen = 0;
            xSemaphoreTake(s_mtx, portMAX_DELAY);
            idle = now_ms() - s_last_poll > IDLE_STOP_MS;
            pwork_t *w = NULL;
            if (idle) { s_task_on = false; w = s_w; s_w = NULL; }
            xSemaphoreGive(s_mtx);
            if (idle) { free(w); break; }
            continue;                         /* polled again meanwhile: keep running */
        }

        if (gen != s_adc_gen) { aerr[0] = 0; adc_up(&c, aerr, sizeof(aerr)); s_adc_gen = gen; }
        pch_t a30, a15;
        adc_one(s_ch30, c.k30, c.o30, &a30);
        adc_one(s_ch15, c.k15, c.o15, &a15);

        bool fetched = false;
        int min_gap = c.per > HOST_MIN_MS ? c.per : HOST_MIN_MS;
        if (c.host && now_ms() - last_host >= min_gap) {
            if (esp_get_free_heap_size() < HEAP_FETCH) {
                memset(&s_w->hw, 0, sizeof(s_w->hw));
                snprintf(s_w->hw.err, sizeof(s_w->hw.err), "skipped: low heap");
                s_w->hw.done = true;
                s_w->hw.ts = now_ms();
            } else {
                host_fetch(&c);
            }
            last_host = now_ms();
            fetched = true;
        }

        xSemaphoreTake(s_mtx, portMAX_DELAY);
        s_a30 = a30; s_a15 = a15;
        s_cal = s_cali != NULL;
        snprintf(s_adc_err, sizeof(s_adc_err), "%s", aerr);
        if (fetched) s_w->pub = s_w->hw;
        if (!c.host) s_w->pub.done = false;
        s_last_cycle = now_ms();
        xSemaphoreGive(s_mtx);

        vTaskDelay(pdMS_TO_TICKS(c.per));
    }
    ESP_LOGI(TAG, "idle, task stopped");
    vTaskDelete(NULL);
}

/* ---------- HTTP ---------- */

typedef struct { char *b; size_t cap, n; } jb_t;
static void ja(jb_t *j, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void ja(jb_t *j, const char *fmt, ...)
{
    if (j->n >= j->cap - 1) return;
    va_list ap; va_start(ap, fmt);
    int r = vsnprintf(j->b + j->n, j->cap - j->n, fmt, ap);
    va_end(ap);
    if (r > 0) j->n = (j->n + (size_t)r < j->cap) ? j->n + (size_t)r : j->cap - 1;
}

/* JSON string without escaping needs: '"' '\\' and control chars -> '?' */
static void js(jb_t *j, const char *s)
{
    ja(j, "\"");
    for (; *s && j->n + 2 < j->cap; s++) {
        char c = *s;
        if (c == '"' || c == '\\' || (unsigned char)c < 32) c = '?';
        j->b[j->n++] = c;
    }
    j->b[j->n] = 0;
    ja(j, "\"");
}

static void jv(jb_t *j, bool ok, float v) { if (ok) ja(j, "%.2f", (double)v); else ja(j, "null"); }

static void pick(jb_t *j, const char *name, const pch_t *a, const char *pin, int cls, const phost_t *h)
{
    ja(j, ",\"%s\":{", name);
    if (a->on && a->ok) { ja(j, "\"v\":%.2f,\"src\":\"adc\",\"key\":\"\"}", (double)a->v); return; }
    const pitem_t *best = NULL;
    float bv = 0;
    if (h->done && h->ok) {
        for (int pass = 0; pass < 2 && !best; pass++) {
            for (int i = 0; i < h->n; i++) {
                const pitem_t *it = &h->it[i];
                float v;
                if (pass == 0 ? (pin[0] && !strcmp(it->k, pin)) : (!pin[0] && it->c == cls)) {
                    if (volts_of(it->v, &v, pass == 1)) { best = it; bv = v; break; }
                }
            }
        }
    }
    if (best) { ja(j, "\"v\":%.2f,\"src\":\"host\",\"key\":", (double)bv); js(j, best->k); ja(j, "}"); }
    else ja(j, "\"v\":null,\"src\":\"none\",\"key\":\"\"}");
}

static void task_kick(void)
{
    bool start = false;
    xSemaphoreTake(s_mtx, portMAX_DELAY);
    s_last_poll = now_ms();
    if (!s_task_on && esp_get_free_heap_size() < HEAP_START) {
        snprintf(s_adc_err, sizeof(s_adc_err), "low heap, polling not started");
    } else if (!s_task_on) {
        s_w = calloc(1, sizeof(pwork_t));
        if (s_w) { s_task_on = true; start = true; }
        else snprintf(s_adc_err, sizeof(s_adc_err), "no memory");
    }
    xSemaphoreGive(s_mtx);
    if (start && xTaskCreate(pwr_task, "c5_pwr", 4096, NULL, 2, NULL) != pdPASS) {
        xSemaphoreTake(s_mtx, portMAX_DELAY);
        s_task_on = false;
        free(s_w); s_w = NULL;
        snprintf(s_adc_err, sizeof(s_adc_err), "no memory for the task");
        xSemaphoreGive(s_mtx);
    }
}

static esp_err_t send_json(httpd_req_t *req, const char *s, size_t n)
{
    httpd_resp_set_type(req, "application/json; charset=utf-8");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    return httpd_resp_send(req, s, (ssize_t)n);
}

static esp_err_t h_power_get(httpd_req_t *req)
{
    task_kick();
    size_t cap = 0;
    char *b = (char *)c5_web_io_buf(&cap);       /* 4 KB httpd task scratch (handlers run one at a time), no malloc */
    jb_t j = { b, cap, 0 };
    b[0] = 0;
    static const phost_t none;                   /* nothing fetched yet / task stopped */
    uint8_t ip[4];
    c5_web_host_ip_get(ip);
    bool locked = c5_web_nvs_locked();
    /* JSON is built under the mutex straight from the task data (no copies); sending happens after */
    xSemaphoreTake(s_mtx, portMAX_DELAY);
    const pwr_cfg_t *c = &s_cfg;
    const phost_t *h = s_w ? &s_w->pub : &none;
    int64_t t = now_ms();
    ja(&j, "{\"ok\":true,\"per\":%u,\"age\":%lld", c->per, (long long)(s_last_cycle < 0 ? -1 : t - s_last_cycle));
    pick(&j, "k30", &s_a30, c->hk30, 30, h);
    pick(&j, "k15", &s_a15, c->hk15, 15, h);
    ja(&j, ",\"adc\":{\"g30\":%d,\"g15\":%d,\"k30\":%lu,\"k15\":%lu,\"o30\":%d,\"o15\":%d,\"mv30\":", c->g30, c->g15,
       (unsigned long)c->k30, (unsigned long)c->k15, c->o30, c->o15);
    if (s_a30.ok) ja(&j, "%d", s_a30.mv); else ja(&j, "null");
    ja(&j, ",\"mv15\":"); if (s_a15.ok) ja(&j, "%d", s_a15.mv); else ja(&j, "null");
    ja(&j, ",\"v30\":"); jv(&j, s_a30.ok, s_a30.v);
    ja(&j, ",\"v15\":"); jv(&j, s_a15.ok, s_a15.v);
    ja(&j, ",\"cal\":%s,\"err\":", s_cal ? "true" : "false"); js(&j, s_adc_err);
    ja(&j, "},\"host\":{\"on\":%u,\"form\":", c->host); js(&j, c->form);
    ja(&j, ",\"hk30\":"); js(&j, c->hk30);
    ja(&j, ",\"hk15\":"); js(&j, c->hk15);
    ja(&j, ",\"ip\":\"%u.%u.%u.%u\",\"done\":%s,\"ok\":%s,\"err\":", ip[0], ip[1], ip[2], ip[3],
       h->done ? "true" : "false", h->ok ? "true" : "false");
    js(&j, h->err);
    ja(&j, ",\"age\":%lld,\"items\":[", (long long)(h->done ? t - h->ts : -1));
    for (int i = 0; i < h->n; i++) {
        ja(&j, "%s{\"k\":", i ? "," : ""); js(&j, h->it[i].k);
        ja(&j, ",\"n\":"); js(&j, h->it[i].n);
        ja(&j, ",\"v\":"); js(&j, h->it[i].v);
        ja(&j, ",\"c\":%d}", h->it[i].c);
    }
    ja(&j, "],\"keys\":"); js(&j, h->keys);
    xSemaphoreGive(s_mtx);
    ja(&j, "},\"nvs_locked\":%s}", locked ? "true" : "false");
    c5_heap_wait();
    return send_json(req, b, j.n);
}

static bool qv(const char *q, const char *k, char *v, size_t vs)
{
    if (httpd_query_key_value(q, k, v, vs) != ESP_OK) return false;
    /* only "%2D"/"%2d" (minus) may be encoded in our values */
    char *p;
    while ((p = strstr(v, "%2D")) || (p = strstr(v, "%2d"))) { *p = '-'; memmove(p + 1, p + 3, strlen(p + 3) + 1); }
    return true;
}

static bool qint(const char *q, const char *k, long lo, long hi, long *out, bool *bad)
{
    char v[16];
    if (!qv(q, k, v, sizeof(v))) return false;
    char *e = NULL;
    long x = strtol(v, &e, 10);
    if (!v[0] || !e || *e || x < lo || x > hi) { *bad = true; return false; }
    *out = x;
    return true;
}

#define JERR(s) do { static const char m[] = "{\"ok\":false,\"err\":\"" s "\"}"; return send_json(req, m, sizeof(m) - 1); } while (0)

static esp_err_t h_power_cfg(httpd_req_t *req)
{
    char q[256] = "", v[32];
    if (httpd_req_get_url_query_str(req, q, sizeof(q)) != ESP_OK) JERR("query missing or too long");
    if (c5_web_nvs_locked()) JERR("nvs locked until reboot");
    pwr_cfg_t c;
    xSemaphoreTake(s_mtx, portMAX_DELAY);
    c = s_cfg;
    xSemaphoreGive(s_mtx);
    if (qv(q, "reset", v, sizeof(v)) && !strcmp(v, "1")) {
        if (cfg_erase() != ESP_OK) JERR("nvs write failed");
        cfg_defaults(&c);
    } else {
        long x; bool bad = false;
        if (qint(q, "g30", -1, 6, &x, &bad)) { if (!gpio_ok((int)x)) bad = true; else c.g30 = (int8_t)x; }
        if (bad) JERR("bad g30 (-1 or 1..6)");
        if (qint(q, "g15", -1, 6, &x, &bad)) { if (!gpio_ok((int)x)) bad = true; else c.g15 = (int8_t)x; }
        if (bad) JERR("bad g15 (-1 or 1..6)");
        if (qint(q, "k30", 1000, 200000, &x, &bad)) c.k30 = (uint32_t)x;
        if (bad) JERR("bad k30 (1000..200000)");
        if (qint(q, "k15", 1000, 200000, &x, &bad)) c.k15 = (uint32_t)x;
        if (bad) JERR("bad k15 (1000..200000)");
        if (qint(q, "o30", -5000, 5000, &x, &bad)) c.o30 = (int16_t)x;
        if (bad) JERR("bad o30 (-5000..5000)");
        if (qint(q, "o15", -5000, 5000, &x, &bad)) c.o15 = (int16_t)x;
        if (bad) JERR("bad o15 (-5000..5000)");
        if (qint(q, "host", 0, 1, &x, &bad)) c.host = (uint8_t)x;
        if (bad) JERR("bad host (0/1)");
        if (qint(q, "per", 1000, 3000, &x, &bad)) c.per = (uint16_t)x;
        if (bad) JERR("bad per (1000..3000)");
        if (qv(q, "form", v, sizeof(v))) { if (!form_ok(v)) JERR("bad form"); memcpy(c.form, v, strlen(v) + 1);   /* length checked above */ }
        if (qv(q, "hk30", v, sizeof(v))) { if (!hk_ok(v)) JERR("bad hk30"); memcpy(c.hk30, v, strlen(v) + 1);   /* length checked above */ }
        if (qv(q, "hk15", v, sizeof(v))) { if (!hk_ok(v)) JERR("bad hk15"); memcpy(c.hk15, v, strlen(v) + 1);   /* length checked above */ }
        if (cfg_save(&c) != ESP_OK) JERR("nvs write failed");
    }
    xSemaphoreTake(s_mtx, portMAX_DELAY);
    s_cfg = c;
    s_gen++;
    xSemaphoreGive(s_mtx);
    ESP_LOGI(TAG, "cfg: adc %d/%d k %lu/%lu o %d/%d host %u form %s hk %s/%s per %u", c.g30, c.g15,
             (unsigned long)c.k30, (unsigned long)c.k15, c.o30, c.o15, c.host, c.form, c.hk30, c.hk15, c.per);
    static const char ok[] = "{\"ok\":true}";
    return send_json(req, ok, sizeof(ok) - 1);
}

void c5_power_register(void *handle)
{
    httpd_handle_t srv = (httpd_handle_t)handle;
    if (!s_mtx) {
        s_mtx = xSemaphoreCreateMutex();
        if (!s_mtx) return;
        cfg_load(&s_cfg);
    }
    static const httpd_uri_t uris[] = {
        { "/api/power", HTTP_GET, h_power_get, NULL },
        { "/api/power_cfg", HTTP_POST, h_power_cfg, NULL },
    };
    for (size_t i = 0; i < sizeof(uris) / sizeof(uris[0]); i++) httpd_register_uri_handler(srv, &uris[i]);
}
