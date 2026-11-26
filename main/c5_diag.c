/*
 * VNCI 6154B / ESP32-C5 web_v9: car diagnostics page (/diag) and DoIP client (ISO 13400-2).
 *
 * Own FreeRTOS task, one job at a time; httpd never blocks: POST /api/diag starts a job,
 * GET /api/diag returns the state and, when done, the result JSON. All sockets have timeouts.
 * Traffic uses the private lwIP of the web UI (192.168.61.250). Frames to the host P4 are
 * handed over by c5_web_server.c while the host link is acquired (c5_web_host_link_acquire).
 *
 * Only reading: UDS services 0x22, 0x19, 0x3E and 0x10 03 are allowed, everything else is refused
 * here (and again in the task). Not verified on hardware: it is not known whether the P4 answers
 * DoIP towards the C5 at all.
 *
 * v10: ECU identification (22 F187/F189/F191/F1A3/F197/F18C/F19E, coding 22 0600, module voltage 22 F442),
 * ECU search over an address list in one TCP session (22 F187 / F197), DoIP protocol version 02 / 03,
 * discovery also with the 0xFF default version; work buffers allocated only while a job runs,
 * result kept in an exact-size heap copy, GET /api/diag built in the httpd scratch buffer (no malloc).
 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"
#include "esp_http_server.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "lwip/sockets.h"
#include "c5_web_server.h"
#include "c5_diag_ui.h"

static const char *TAG = "c5_diag";

#define DOIP_PORT      13400
#define TESTER_LA_DEF  0x0E80
#define ECU_LA_DEF     0x1010
#define UDS_MAX        32
#define RES_SZ         (ITEMS_SZ + RAW_SZ + 160)   /* v11.1: was 3072, could cut the result JSON */
#define ITEMS_SZ       2048
#define RAW_SZ         900
#define SCAN_MAX       32          /* ECU search: addresses per run */
#define RAW_HEX_MAX    40          /* bytes of a frame shown in the raw log */
#define PAYLOAD_MAX    512

typedef enum { OP_NONE = 0, OP_DISC, OP_ENT, OP_PWR, OP_STD, OP_UDS, OP_IDENT, OP_SCAN } diag_op_t;
static const char *const OP_NAME[] = { "none", "disc", "ent", "pwr", "std", "uds", "ident", "scan" };

esp_err_t c5_web_send_gz(httpd_req_t *req, const uint8_t *d, size_t n);   /* c5_web_server.c */

typedef struct {
    diag_op_t op;
    uint8_t ip[4];
    bool ip_set;
    uint16_t ta;          /* ECU logical address (0 = default) */
    uint16_t sa;          /* tester logical address (0 = default) */
    uint8_t uds[UDS_MAX];
    uint8_t uds_len;
    uint8_t pv;           /* v10: DoIP protocol version 2 / 3 */
    uint8_t tl_n;         /* v10: ECU search list */
    uint16_t tl[SCAN_MAX];
} job_t;

static QueueHandle_t s_q;
static SemaphoreHandle_t s_mtx;
static volatile int s_state;               /* 0 idle, 1 running, 2 done */
static diag_op_t s_cur_op;
static uint32_t s_seq;
static int64_t s_t0_ms, s_dur_ms;
static char *s_res;                        /* v10: exact-size heap copy of the result JSON (s_state == 2) */
static TaskHandle_t s_task;
static uint8_t s_pv = 0x02;                /* DoIP protocol version of the running job */

/* result under construction (diag task only); v10: heap, only while a job runs */
static char *s_items, *s_raw;
static size_t s_items_n, s_raw_n;
static bool s_res_ok;
static char s_res_err[96];

/* what the last discovery found */
static uint8_t s_last_ip[4];
static uint16_t s_last_la;
static bool s_last_ok;

static uint8_t *s_rx;                      /* PAYLOAD_MAX + 8 */
#define RX_CAP (PAYLOAD_MAX + 8)

/* ---------- result builders ---------- */

static void app(char *b, size_t cap, size_t *n, const char *fmt, ...) __attribute__((format(printf, 4, 5)));
static void app(char *b, size_t cap, size_t *n, const char *fmt, ...)
{
    if (*n >= cap - 1) return;
    va_list ap;
    va_start(ap, fmt);
    int r = vsnprintf(b + *n, cap - *n, fmt, ap);
    va_end(ap);
    /* v10: whole entries only (a cut entry made the result JSON invalid when the raw log was full) */
    if (r > 0 && *n + (size_t)r < cap) *n += (size_t)r;
    else b[*n] = 0;
}

static void hex_str(char *out, size_t cap, const uint8_t *d, size_t n, size_t maxb)
{
    size_t i, o = 0;
    for (i = 0; i < n && i < maxb && o + 3 < cap; i++) o += (size_t)snprintf(out + o, cap - o, "%02X", d[i]);
    if (n > maxb && o + 4 < cap) { out[o++] = '.'; out[o++] = '.'; out[o++] = '.'; }
    out[o] = 0;
}

/* item: key + value (value must not need JSON escaping: callers pass hex / digits / sanitized text) */
static void item(const char *k, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void item(const char *k, const char *fmt, ...)
{
    char v[160];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(v, sizeof(v), fmt, ap);
    va_end(ap);
    for (char *c = v; *c; c++) if (*c == '"' || *c == '\\' || (unsigned char)*c < 32) *c = '?';
    app(s_items, ITEMS_SZ, &s_items_n, "%s{\"k\":\"%s\",\"v\":\"%s\"}", s_items_n ? "," : "", k, v);
}

static void rawlog(bool tx, const char *peer, const uint8_t *d, size_t n)
{
    char h[RAW_HEX_MAX * 2 + 8];
    hex_str(h, sizeof(h), d, n, RAW_HEX_MAX);
    app(s_raw, RAW_SZ, &s_raw_n, "%s{\"d\":\"%s\",\"a\":\"%s\",\"n\":%u,\"h\":\"%s\"}", s_raw_n ? "," : "",
        tx ? "tx" : "rx", peer, (unsigned)n, h);
}

static void fail(const char *e)
{
    s_res_ok = false;
    snprintf(s_res_err, sizeof(s_res_err), "%s", e);
}

static void ip_str(char out[24], const uint8_t ip[4])
{
    snprintf(out, 24, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
}

/* ---------- DoIP frames ---------- */

static size_t doip_hdr(uint8_t *b, uint16_t type, uint32_t plen)
{
    b[0] = s_pv; b[1] = (uint8_t)~s_pv;
    b[2] = type >> 8; b[3] = (uint8_t)type;
    b[4] = plen >> 24; b[5] = plen >> 16; b[6] = plen >> 8; b[7] = (uint8_t)plen;
    return 8;
}

static bool doip_valid(const uint8_t *b, size_t n)
{
    return n >= 8 && (uint8_t)(b[0] ^ b[1]) == 0xFF;
}

static uint16_t be16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }

static const char *nack_txt(uint8_t c)
{
    switch (c) {
        case 0: return "incorrect pattern";
        case 1: return "unknown payload type";
        case 2: return "message too large";
        case 3: return "out of memory";
        case 4: return "invalid payload length";
        default: return "?";
    }
}

/* ---------- UDP ---------- */

static int udp_open(void)
{
    int s = lwip_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s < 0) return -1;
    int one = 1;
    lwip_setsockopt(s, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));
    return s;
}

static void udp_send(int s, const uint8_t ip[4], const uint8_t *b, size_t n)
{
    struct sockaddr_in sa = { 0 };
    sa.sin_family = AF_INET;
    sa.sin_port = htons(DOIP_PORT);
    memcpy(&sa.sin_addr.s_addr, ip, 4);
    char peer[32];
    char ips[24];
    ip_str(ips, ip);
    snprintf(peer, sizeof(peer), "%s:%d", ips, DOIP_PORT);
    int r = lwip_sendto(s, b, n, 0, (struct sockaddr *)&sa, sizeof(sa));
    (void)r;
    rawlog(true, peer, b, n);
}

/* wait for one datagram until the deadline (ms since boot); returns length, 0 timeout */
static int udp_recv(int s, uint8_t *buf, size_t cap, int64_t deadline_ms, uint8_t from[4])
{
    int64_t left = deadline_ms - esp_timer_get_time() / 1000;
    if (left <= 0) return 0;
    fd_set rf;
    FD_ZERO(&rf);
    FD_SET(s, &rf);
    struct timeval tv = { .tv_sec = (long)(left / 1000), .tv_usec = (long)(left % 1000) * 1000 };
    if (lwip_select(s + 1, &rf, NULL, NULL, &tv) <= 0) return 0;
    struct sockaddr_in sa;
    socklen_t sl = sizeof(sa);
    int r = lwip_recvfrom(s, buf, cap, 0, (struct sockaddr *)&sa, &sl);
    if (r <= 0) return 0;
    memcpy(from, &sa.sin_addr.s_addr, 4);
    return r;
}

static void ascii_safe(char *out, const uint8_t *d, size_t n)
{
    for (size_t i = 0; i < n; i++) out[i] = (d[i] >= 0x20 && d[i] < 0x7F && d[i] != '"' && d[i] != '\\') ? (char)d[i] : '?';
    out[n] = 0;
}

static void note_peer(const uint8_t from[4], const char *what, const uint8_t *d, size_t n)
{
    char peer[32], ips[24];
    ip_str(ips, from);
    snprintf(peer, sizeof(peer), "%s:%d", ips, DOIP_PORT);
    (void)what;
    rawlog(false, peer, d, n);
}

/* 0x0001 Vehicle Identification Request to .54 / .255 / 255.255.255.255 */
static void op_disc(const job_t *jb)
{
    (void)jb;
    int s = udp_open();
    if (s < 0) { fail("no socket"); return; }
    uint8_t req[8];
    doip_hdr(req, 0x0001, 0);
    uint8_t host[4];
    c5_web_host_ip_get(host);
    uint8_t bc[4] = { host[0], host[1], host[2], 255 };
    uint8_t bc2[4] = { 255, 255, 255, 255 };
    udp_send(s, host, req, 8);
    udp_send(s, bc, req, 8);
    udp_send(s, bc2, req, 8);
    uint8_t rqd[8];                                  /* v10: ISO 13400-2 default version 0xFF for 0x0001 */
    memcpy(rqd, req, 8);
    rqd[0] = 0xFF; rqd[1] = 0x00;
    udp_send(s, bc, rqd, 8);
    udp_send(s, bc2, rqd, 8);
    int64_t dl = esp_timer_get_time() / 1000 + 2000;
    int found = 0;
    uint8_t from[4], seen[4][4];
    for (;;) {
        int r = udp_recv(s, s_rx, RX_CAP, dl, from);
        if (r <= 0) break;
        note_peer(from, "rx", s_rx, (size_t)r);
        if (!doip_valid(s_rx, (size_t)r)) continue;
        uint16_t type = be16(&s_rx[2]);
        uint32_t plen = ((uint32_t)s_rx[4] << 24) | (s_rx[5] << 16) | (s_rx[6] << 8) | s_rx[7];
        /* v11.1: 0x0004 payload is 32 B (VIN17+LA2+EID6+GID6+FA1); the 33rd byte is optional */
        if (type == 0x0004 && plen >= 32 && (size_t)r >= 8 + 32 && found < 4) {
            bool dup = false;
            for (int i = 0; i < found; i++) if (!memcmp(seen[i], from, 4)) dup = true;
            if (dup) continue;
            memcpy(seen[found++], from, 4);
            const uint8_t *p = &s_rx[8];
            char vin[18], ips[24], eid[16], gid[16];
            ascii_safe(vin, p, 17);
            hex_str(eid, sizeof(eid), p + 19, 6, 6);
            hex_str(gid, sizeof(gid), p + 25, 6, 6);
            ip_str(ips, from);
            item("from", "%s", ips);
            item("vin", "%s", vin);
            item("la", "%04X", be16(p + 17));
            item("eid", "%s", eid);
            item("gid", "%s", gid);
            item("fa", "%02X", p[31]);
            if (!s_last_ok) {
                memcpy(s_last_ip, from, 4);
                s_last_la = be16(p + 17);
                s_last_ok = true;
            }
        } else if (type == 0x0000 && plen >= 1) {
            item("nack", "%02X %s", s_rx[8], nack_txt(s_rx[8]));
        } else {
            item("other", "type %04X len %u", type, (unsigned)plen);
        }
    }
    lwip_close(s);
    if (!found) item("none", "no answer");
}

static bool pick_ip(const job_t *jb, uint8_t ip[4])
{
    if (jb->ip_set) { memcpy(ip, jb->ip, 4); return true; }
    if (s_last_ok) { memcpy(ip, s_last_ip, 4); return true; }
    c5_web_host_ip_get(ip);
    return true;
}

/* 0x4001 Entity Status / 0x4003 Diagnostic Power Mode over UDP */
static void op_udp_query(const job_t *jb, uint16_t type, uint16_t rtype)
{
    uint8_t ip[4];
    pick_ip(jb, ip);
    char ips[24];
    ip_str(ips, ip);
    int s = udp_open();
    if (s < 0) { fail("no socket"); return; }
    uint8_t req[8];
    doip_hdr(req, type, 0);
    udp_send(s, ip, req, 8);
    int64_t dl = esp_timer_get_time() / 1000 + 2000;
    bool got = false;
    uint8_t from[4];
    while (!got) {
        int r = udp_recv(s, s_rx, RX_CAP, dl, from);
        if (r <= 0) break;
        note_peer(from, "rx", s_rx, (size_t)r);
        if (!doip_valid(s_rx, (size_t)r)) continue;
        uint16_t t = be16(&s_rx[2]);
        uint32_t plen = ((uint32_t)s_rx[4] << 24) | (s_rx[5] << 16) | (s_rx[6] << 8) | s_rx[7];
        if (t == rtype && type == 0x4001 && plen >= 3 && r >= 11) {
            item("from", "%s", ips);
            item("node", "%u", s_rx[8]);                         /* 0 gateway, 1 node */
            item("sock_max", "%u", s_rx[9]);
            item("sock_cur", "%u", s_rx[10]);
            if (plen >= 7 && r >= 15) item("maxdata", "%lu", ((unsigned long)s_rx[11] << 24) | (s_rx[12] << 16) | (s_rx[13] << 8) | s_rx[14]);
            got = true;
        } else if (t == rtype && type == 0x4003 && plen >= 1 && r >= 9) {
            item("from", "%s", ips);
            item("pm", "%u", s_rx[8]);                           /* 0 not ready, 1 ready, 2 not supported */
            got = true;
        } else if (t == 0x0000 && plen >= 1) {
            item("nack", "%02X %s", s_rx[8], nack_txt(s_rx[8]));
            got = true;
        }
    }
    lwip_close(s);
    if (!got) item("none", "no answer from %s", ips);
}

/* ---------- TCP / diagnostic messages ---------- */

static int tcp_open(const uint8_t ip[4], int tmo_ms)
{
    struct sockaddr_in sa = { 0 };
    sa.sin_family = AF_INET;
    sa.sin_port = htons(DOIP_PORT);
    memcpy(&sa.sin_addr.s_addr, ip, 4);
    int s = lwip_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s < 0) return -1;
    int fl = lwip_fcntl(s, F_GETFL, 0);
    lwip_fcntl(s, F_SETFL, fl | O_NONBLOCK);
    int r = lwip_connect(s, (struct sockaddr *)&sa, sizeof(sa));
    if (r < 0 && errno != EINPROGRESS) { lwip_close(s); return -1; }
    if (r < 0) {
        fd_set wf;
        FD_ZERO(&wf);
        FD_SET(s, &wf);
        struct timeval tv = { .tv_sec = tmo_ms / 1000, .tv_usec = (tmo_ms % 1000) * 1000 };
        int err = 0;
        socklen_t el = sizeof(err);
        if (lwip_select(s + 1, NULL, &wf, NULL, &tv) <= 0 ||
            lwip_getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &el) != 0 || err != 0) {
            lwip_close(s);
            return -1;
        }
    }
    lwip_fcntl(s, F_SETFL, fl & ~O_NONBLOCK);
    return s;
}

static bool tcp_send_all(int s, const uint8_t *b, size_t n)
{
    struct timeval to = { .tv_sec = 3, .tv_usec = 0 };
    lwip_setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &to, sizeof(to));
    while (n) {
        int w = lwip_send(s, b, n, 0);
        if (w <= 0) return false;
        b += w;
        n -= (size_t)w;
    }
    return true;
}

/* read exactly n bytes before the deadline: 1 ok, 0 timeout, -1 closed / error */
static int tcp_read_n(int s, uint8_t *b, size_t n, int64_t dl)
{
    while (n) {
        int64_t left = dl - esp_timer_get_time() / 1000;
        if (left <= 0) return 0;
        struct timeval to = { .tv_sec = (long)(left / 1000), .tv_usec = (long)(left % 1000) * 1000 };
        lwip_setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &to, sizeof(to));
        int r = lwip_recv(s, b, n, 0);
        if (r == 0) return -1;
        if (r < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ETIMEDOUT) return 0;
            return -1;
        }
        b += r;
        n -= (size_t)r;
    }
    return 1;
}

/* one DoIP message: returns payload length (>=0) with type, -1 timeout, -2 closed, -3 bad header */
static int doip_read(int s, uint16_t *type, int64_t dl, const char *peer)
{
    uint8_t h[8];
    int r = tcp_read_n(s, h, 8, dl);
    if (r <= 0) return r == 0 ? -1 : -2;
    if (!doip_valid(h, 8)) return -3;
    uint32_t plen = ((uint32_t)h[4] << 24) | (h[5] << 16) | (h[6] << 8) | h[7];
    *type = be16(&h[2]);
    size_t keep = plen > PAYLOAD_MAX ? PAYLOAD_MAX : plen;
    if (keep) {
        r = tcp_read_n(s, s_rx, keep, dl);
        if (r <= 0) return r == 0 ? -1 : -2;
    }
    for (size_t left = plen - keep; left;) {            /* drain what does not fit */
        uint8_t t[64];
        size_t c = left > sizeof(t) ? sizeof(t) : left;
        if (tcp_read_n(s, t, c, dl) <= 0) return -2;
        left -= c;
    }
    uint8_t shown[8 + 40];
    memcpy(shown, h, 8);
    size_t sn = keep > 40 ? 40 : keep;
    memcpy(shown + 8, s_rx, sn);
    rawlog(false, peer, shown, 8 + plen);
    return (int)keep;
}

typedef struct {
    int s;
    char peer[32];
    uint16_t sa, ta;
} sess_t;

/* routing activation; true = success (0x10) */
static bool doip_activate(sess_t *c)
{
    uint8_t m[8 + 7];
    doip_hdr(m, 0x0005, 7);
    m[8] = c->sa >> 8; m[9] = (uint8_t)c->sa;
    m[10] = 0x00;                       /* activation type: default */
    memset(&m[11], 0, 4);               /* reserved by ISO */
    rawlog(true, c->peer, m, sizeof(m));
    if (!tcp_send_all(c->s, m, sizeof(m))) { fail("send failed (routing activation)"); return false; }
    int64_t dl = esp_timer_get_time() / 1000 + 3000;
    for (;;) {
        uint16_t t;
        int n = doip_read(c->s, &t, dl, c->peer);
        if (n == -1) { fail("no routing activation answer (timeout)"); return false; }
        if (n < 0) { fail("connection closed / bad header during routing activation"); return false; }
        if (t == 0x0006 && n >= 9) {
            uint8_t code = s_rx[4];
            item("act_entity", "%04X", be16(&s_rx[2]));
            item("act_code", "%02X", code);
            if (code == 0x10) return true;
            fail("routing activation refused");
            return false;
        }
        if (t == 0x0000 && n >= 1) { item("nack", "%02X %s", s_rx[0], nack_txt(s_rx[0])); fail("generic NACK on routing activation"); return false; }
    }
}

/* send UDS, wait for the response; returns UDS length in out (>0), 0 = no response, <0 = error */
static int doip_uds_t(sess_t *c, const uint8_t *uds, size_t ul, uint8_t *out, size_t ocap, char *why, size_t wsz, int tmo_ms)
{
    uint8_t m[8 + 4 + UDS_MAX];
    doip_hdr(m, 0x8001, 4 + ul);
    m[8] = c->sa >> 8; m[9] = (uint8_t)c->sa;
    m[10] = c->ta >> 8; m[11] = (uint8_t)c->ta;
    memcpy(&m[12], uds, ul);
    rawlog(true, c->peer, m, 12 + ul);
    if (!tcp_send_all(c->s, m, 12 + ul)) { snprintf(why, wsz, "send failed"); return -1; }
    int64_t t0 = esp_timer_get_time() / 1000;
    int64_t dl = t0 + tmo_ms;
    for (;;) {
        uint16_t t;
        int n = doip_read(c->s, &t, dl, c->peer);
        if (n == -1) { snprintf(why, wsz, "no UDS answer (timeout)"); return 0; }
        if (n < 0) { snprintf(why, wsz, "connection closed / bad header"); return -1; }
        if (t == 0x8003 && n >= 5) { snprintf(why, wsz, "diagnostic NACK %02X", s_rx[4]); return -4; }
        if (t == 0x0007) {                                   /* alive check request: answer with the tester address */
            uint8_t a[10];
            doip_hdr(a, 0x0008, 2);
            a[8] = c->sa >> 8; a[9] = (uint8_t)c->sa;
            tcp_send_all(c->s, a, sizeof(a));
            continue;
        }
        if (t == 0x8001 && n >= 5) {
            size_t u = (size_t)n - 4;
            if (u >= 3 && s_rx[4] == 0x7F && s_rx[6] == 0x78) {   /* response pending */
                if (esp_timer_get_time() / 1000 + 5000 > t0 + 15000) dl = t0 + 15000; else dl = esp_timer_get_time() / 1000 + 5000;
                continue;
            }
            if (u > ocap) u = ocap;
            memcpy(out, &s_rx[4], u);
            return (int)u;
        }
        /* 0x8002 positive ack and anything else: keep waiting */
    }
}

static int doip_uds(sess_t *c, const uint8_t *uds, size_t ul, uint8_t *out, size_t ocap, char *why, size_t wsz)
{
    return doip_uds_t(c, uds, ul, out, ocap, why, wsz, 5000);
}

static const char *nrc_txt(uint8_t c)
{
    switch (c) {
        case 0x10: return "general reject";
        case 0x11: return "service not supported";
        case 0x12: return "sub-function not supported";
        case 0x13: return "incorrect length / format";
        case 0x22: return "conditions not correct";
        case 0x31: return "request out of range";
        case 0x33: return "security access denied";
        case 0x7E: return "sub-function not supported in session";
        case 0x7F: return "service not supported in session";
        default: return "";
    }
}

static void report_uds(const char *key, const uint8_t *r, int n, const char *why)
{
    if (n <= 0) { item(key, "%s", why); return; }
    char h[2 * 40 + 8];
    hex_str(h, sizeof(h), r, (size_t)n, 40);
    if (r[0] == 0x7F && n >= 3) item(key, "NRC %02X %s (%s)", r[2], nrc_txt(r[2]), h);
    else item(key, "%s", h);
}

static bool uds_allowed(const uint8_t *u, size_t n)
{
    if (n < 1 || n > UDS_MAX) return false;
    switch (u[0]) {
        case 0x22: return n >= 3 && (n & 1) == 1;                 /* 22 + DID(s) */
        case 0x19: return n >= 2;                                 /* read DTC information */
        case 0x3E: return n == 2 && (u[1] == 0x00 || u[1] == 0x80);
        case 0x10: return n == 2 && u[1] == 0x03;                 /* extended session only */
        default: return false;
    }
}

static bool session_open(const job_t *jb, sess_t *c)
{
    uint8_t ip[4];
    pick_ip(jb, ip);
    char ips[24];
    ip_str(ips, ip);
    snprintf(c->peer, sizeof(c->peer), "%s:%d", ips, DOIP_PORT);
    c->sa = jb->sa ? jb->sa : TESTER_LA_DEF;
    c->ta = jb->ta ? jb->ta : (s_last_ok ? s_last_la : ECU_LA_DEF);
    if (!jb->ta && !s_last_ok) c->ta = ECU_LA_DEF;
    item("tcp", "%s", c->peer);
    item("sa", "%04X", c->sa);
    item("ta", "%04X", c->ta);
    c->s = tcp_open(ip, 3000);
    if (c->s < 0) { fail("TCP connect failed (no route to host / port closed)"); return false; }
    if (!doip_activate(c)) { lwip_close(c->s); c->s = -1; return false; }
    return true;
}

static void op_std(const job_t *jb)
{
    sess_t c;
    if (!session_open(jb, &c)) return;
    uint8_t r[256];
    char why[64] = "";
    static const uint8_t vin_rq[] = { 0x22, 0xF1, 0x90 };
    int n = doip_uds(&c, vin_rq, sizeof(vin_rq), r, sizeof(r), why, sizeof(why));
    if (n >= 3 + 17 && r[0] == 0x62 && r[1] == 0xF1 && r[2] == 0x90) {
        char vin[18];
        ascii_safe(vin, &r[3], 17);
        item("vin_uds", "%s", vin);
    } else {
        report_uds("vin_uds", r, n, why);
    }
    static const uint8_t dtc_rq[] = { 0x19, 0x02, 0xFF };
    n = doip_uds(&c, dtc_rq, sizeof(dtc_rq), r, sizeof(r), why, sizeof(why));
    if (n >= 3 && r[0] == 0x59 && r[1] == 0x02) {
        item("dtc_cnt", "%u", (unsigned)((n - 3) / 4));
        if (n >= 255) item("dtc_note", "list truncated, count may be higher");
    } else {
        report_uds("dtc_uds", r, n, why);
    }
    lwip_close(c.s);
}

static void op_uds(const job_t *jb)
{
    if (!uds_allowed(jb->uds, jb->uds_len)) { fail("blocked: only 22, 19, 3E, 10 03 are allowed"); return; }
    sess_t c;
    if (!session_open(jb, &c)) return;
    uint8_t r[PAYLOAD_MAX > 128 ? 128 : PAYLOAD_MAX];
    char why[64] = "";
    int n = doip_uds(&c, jb->uds, jb->uds_len, r, sizeof(r), why, sizeof(why));
    report_uds("uds_rsp", r, n, why);
    lwip_close(c.s);
}

/* v10: printable -> text (trimmed), else hex */
static void did_value(char *out, size_t cap, const uint8_t *d, size_t n)
{
    bool txt = n > 0;
    for (size_t i = 0; i < n; i++) if ((d[i] < 0x20 || d[i] >= 0x7F) && d[i] != 0) { txt = false; break; }
    if (txt) {
        size_t o = 0;
        for (size_t i = 0; i < n && o + 1 < cap; i++) {
            char ch = (char)d[i];
            if (ch == 0 || ch == '"' || ch == '\\') ch = ' ';
            out[o++] = ch;
        }
        while (o && out[o - 1] == ' ') o--;
        size_t b = 0;
        while (b < o && out[b] == ' ') b++;
        memmove(out, out + b, o - b);
        out[o - b] = 0;
    } else {
        hex_str(out, cap, d, n, 64);
    }
}

/* v10: ECU identification, read only. First request decides: no answer -> stop. */
static void op_ident(const job_t *jb)
{
    static const struct { uint16_t did; const char *k; } ids[] = {
        { 0xF187, "id_pn" }, { 0xF189, "id_sw" }, { 0xF191, "id_hwn" }, { 0xF1A3, "id_hwv" },
        { 0xF197, "id_sys" }, { 0xF18C, "id_ser" }, { 0xF19E, "id_odx" }, { 0x0600, "id_cod" },
    };
    sess_t c;
    if (!session_open(jb, &c)) return;
    uint8_t r[128];
    char why[64] = "", v[136];
    int answered = 0;
    for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
        uint8_t rq[3] = { 0x22, (uint8_t)(ids[i].did >> 8), (uint8_t)ids[i].did };
        int n = doip_uds_t(&c, rq, 3, r, sizeof(r), why, sizeof(why), 3000);
        if (n >= 3 && r[0] == 0x62 && r[1] == rq[1] && r[2] == rq[2]) {
            answered++;
            if (ids[i].did == 0x0600) hex_str(v, sizeof(v), &r[3], (size_t)n - 3, 64);
            else did_value(v, sizeof(v), &r[3], (size_t)n - 3);
            item(ids[i].k, "%s", v);
        } else if (n > 0) {
            answered++;
            if (r[0] == 0x7F && n >= 3) item(ids[i].k, "NRC %02X %s", r[2], nrc_txt(r[2]));
            else report_uds(ids[i].k, r, n, why);
        } else {
            report_uds(ids[i].k, r, n, why);
            if (n == -1 || n == -2 || answered == 0) break;   /* closed, or nothing answers: stop */
        }
    }
    if (answered) {                                     /* OBD PID 42 as DID F442, 0.001 V/bit */
        static const uint8_t vq[] = { 0x22, 0xF4, 0x42 };
        int n = doip_uds_t(&c, vq, 3, r, sizeof(r), why, sizeof(why), 2000);
        if (n >= 5 && r[0] == 0x62 && r[1] == 0xF4 && r[2] == 0x42) {
            unsigned mv = ((unsigned)r[3] << 8) | r[4];
            item("volt", "%u.%02u", mv / 1000, (mv % 1000) / 10);
        }
    }
    lwip_close(c.s);
}

/* v10: ECU search: one routing activation, 22 F187 (+ F197) to each address of the list */
static void op_scan(const job_t *jb)
{
    sess_t c;
    if (!session_open(jb, &c)) return;
    uint8_t r[96];
    char why[64] = "", pn[64], sy[64];
    int found = 0, absent = 0, silent = 0;
    for (int i = 0; i < jb->tl_n; i++) {
        c.ta = jb->tl[i];
        static const uint8_t q1[] = { 0x22, 0xF1, 0x87 };
        int n = doip_uds_t(&c, q1, 3, r, sizeof(r), why, sizeof(why), 1200);
        if (n == -1 || n == -2 || n == -3) { item("scan_stop", "%04X: %s", c.ta, why); break; }
        if (n == -4) { absent++; continue; }               /* gateway: unknown / unreachable target */
        if (n == 0) { silent++; continue; }
        found++;
        if (n >= 3 && r[0] == 0x62) did_value(pn, sizeof(pn), &r[3], (size_t)n - 3);
        else if (r[0] == 0x7F && n >= 3) snprintf(pn, sizeof(pn), "NRC %02X", r[2]);
        else hex_str(pn, sizeof(pn), r, (size_t)n, 16);
        sy[0] = 0;
        static const uint8_t q2[] = { 0x22, 0xF1, 0x97 };
        n = doip_uds_t(&c, q2, 3, r, sizeof(r), why, sizeof(why), 1200);
        if (n >= 3 && r[0] == 0x62) did_value(sy, sizeof(sy), &r[3], (size_t)n - 3);
        else if (n == -1 || n == -2) { item("ecu", "%04X|%s|", c.ta, pn); item("scan_stop", "%04X: %s", c.ta, why); break; }
        item("ecu", "%04X|%s|%s", c.ta, pn, sy);
    }
    item("scan_sum", "%d|%d|%d|%d", jb->tl_n, found, absent, silent);
    lwip_close(c.s);
}

/* ---------- task ---------- */

static void finish(diag_op_t op, int64_t t0)
{
    /* v11.1: the "ok":false branch serialises to 41 + err + items + raw bytes. The old 40 was
     * one byte short, so app() (whole entries only) dropped the entire tail and the result stayed
     * an unclosed object -> /api/diag became invalid JSON and the page spun until its timeout. */
    size_t need = 64 + strlen(s_res_err) + (s_items ? s_items_n : 0) + (s_raw ? s_raw_n : 0);
    if (need > RES_SZ) need = RES_SZ;
    char *res = malloc(need + 1);
    if (res) {
        size_t n = 0;
        res[0] = 0;
        if (s_res_ok) app(res, need + 1, &n, "{\"ok\":true");
        else app(res, need + 1, &n, "{\"ok\":false,\"err\":\"%s\"", s_res_err);
        app(res, need + 1, &n, ",\"items\":[%s],\"raw\":[%s]}", s_items ? s_items : "", s_raw ? s_raw : "");
        /* v11.1: never publish an unclosed object - h_diag_get embeds it verbatim */
        if (n < 2 || res[n - 1] != '}') {
            snprintf(res, need + 1, "{\"ok\":false,\"err\":\"result too long\",\"items\":[],\"raw\":[]}");
        }
    }
    xSemaphoreTake(s_mtx, portMAX_DELAY);
    free(s_res);
    s_res = res;
    s_dur_ms = esp_timer_get_time() / 1000 - t0;
    s_cur_op = op;
    s_state = 2;
    xSemaphoreGive(s_mtx);
}

static void diag_task(void *arg)
{
    (void)arg;
    job_t jb;
    for (;;) {
        if (xQueueReceive(s_q, &jb, portMAX_DELAY) != pdTRUE) continue;
        int64_t t0 = esp_timer_get_time() / 1000;
        xSemaphoreTake(s_mtx, portMAX_DELAY);              /* v10: drop the previous result */
        free(s_res);
        s_res = NULL;
        xSemaphoreGive(s_mtx);
        s_items_n = s_raw_n = 0;
        s_res_ok = true;
        s_res_err[0] = 0;
        s_pv = (jb.pv == 3) ? 0x03 : 0x02;
        char *wb = malloc(ITEMS_SZ + RAW_SZ + RX_CAP);
        if (!wb) {
            s_items = s_raw = NULL;
            s_rx = NULL;
            fail("no memory");
            finish(jb.op, t0);
            continue;
        }
        s_items = wb;
        s_raw = wb + ITEMS_SZ;
        s_rx = (uint8_t *)(wb + ITEMS_SZ + RAW_SZ);
        s_items[0] = s_raw[0] = 0;
        c5_web_host_link_acquire(true);
        switch (jb.op) {
            case OP_DISC: op_disc(&jb); break;
            case OP_ENT: op_udp_query(&jb, 0x4001, 0x4002); break;
            case OP_PWR: op_udp_query(&jb, 0x4003, 0x4004); break;
            case OP_STD: op_std(&jb); break;
            case OP_UDS: op_uds(&jb); break;
            case OP_IDENT: op_ident(&jb); break;
            case OP_SCAN: op_scan(&jb); break;
            default: fail("bad op"); break;
        }
        c5_web_host_link_release(true);
        ESP_LOGI(TAG, "op %s: %s", OP_NAME[jb.op], s_res_ok ? "done" : s_res_err);
        finish(jb.op, t0);
        s_items = s_raw = NULL;
        s_rx = NULL;
        free(wb);
    }
}

/* ---------- HTTP ---------- */

static esp_err_t h_diag_page(httpd_req_t *req)
{
    return c5_web_send_gz(req, diag_ui_html_gz, diag_ui_html_gz_len);
}

void *c5_diag_task_handle(void)
{
    return s_task;
}

static bool parse_la(const char *s, uint16_t *out);

/* v10: "1010,1011" / "4000-401F" -> list (max SCAN_MAX); 0 on error */
static int parse_tl(const char *s, uint16_t *out)
{
    int n = 0;
    char tok[12];
    while (*s) {
        while (*s == ' ' || *s == ',' || *s == ';') s++;
        if (!*s) break;
        size_t l = 0;
        while (s[l] && s[l] != ',' && s[l] != ';' && s[l] != ' ' && l < sizeof(tok) - 1) { tok[l] = s[l]; l++; }
        if (s[l] && s[l] != ',' && s[l] != ';' && s[l] != ' ') return 0;
        tok[l] = 0;
        s += l;
        char *dash = strchr(tok, '-');
        uint16_t a, b;
        if (dash) {
            *dash = 0;
            if (!parse_la(tok, &a) || !parse_la(dash + 1, &b) || b < a) return 0;
        } else {
            if (!parse_la(tok, &a)) return 0;
            b = a;
        }
        for (uint32_t x = a; x <= b; x++) {
            if (n >= SCAN_MAX) return 0;
            out[n++] = (uint16_t)x;
        }
    }
    return n;
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* hex string (spaces allowed) -> bytes; -1 on error */
static int parse_hex(const char *s, uint8_t *out, size_t cap)
{
    size_t n = 0;
    int hi = -1;
    for (; *s; s++) {
        if (*s == ' ') continue;
        int v = hexval(*s);
        if (v < 0) return -1;
        if (hi < 0) hi = v;
        else {
            if (n >= cap) return -1;
            out[n++] = (uint8_t)((hi << 4) | v);
            hi = -1;
        }
    }
    return hi < 0 ? (int)n : -1;
}

/* 1..4 hex digits -> 16-bit logical address */
static bool parse_la(const char *s, uint16_t *out)
{
    size_t n = strlen(s);
    if (n < 1 || n > 4) return false;
    uint16_t v = 0;
    for (size_t i = 0; i < n; i++) {
        int h = hexval(s[i]);
        if (h < 0) return false;
        v = (uint16_t)((v << 4) | h);
    }
    *out = v;
    return true;
}

static bool parse_ip(const char *s, uint8_t ip[4])
{
    unsigned a, b, c, d;
    char tail;
    if (sscanf(s, "%u.%u.%u.%u%c", &a, &b, &c, &d, &tail) != 4 || a > 255 || b > 255 || c > 255 || d > 255) return false;
    ip[0] = a; ip[1] = b; ip[2] = c; ip[3] = d;
    return true;
}

/* v11.1: the page builds the query with URLSearchParams: ',' -> %2C, space -> '+'.
 * Without decoding, "1010,1011" and "22 F1 87" never parse. In-place, dst <= src. */
static void url_dec(char *s)
{
    char *d = s;
    for (const char *p = s; *p; p++) {
        if (p[0] == '%' && p[1] && p[2]) {
            int h = hexval(p[1]), l = hexval(p[2]);
            if (h >= 0 && l >= 0) { *d++ = (char)((h << 4) | l); p += 2; continue; }
        }
        *d++ = (*p == '+') ? ' ' : *p;
    }
    *d = 0;
}

static esp_err_t send_json(httpd_req_t *req, const char *s)
{
    httpd_resp_set_type(req, "application/json; charset=utf-8");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    return httpd_resp_sendstr(req, s);
}

static esp_err_t h_diag_post(httpd_req_t *req)
{
    /* v11.1: q[200]/v[80] truncated a 32-address list (159 chars) and any UDS with separators;
     * httpd_query_key_value() returns ESP_ERR_HTTPD_RESULT_TRUNC and leaves the buffer untouched. */
    char q[512] = "", v[80], big[200];
    if (httpd_req_get_url_query_str(req, q, sizeof(q)) != ESP_OK) {
        return send_json(req, "{\"ok\":false,\"err\":\"query missing or too long\"}");
    }
    job_t jb;
    memset(&jb, 0, sizeof(jb));
    if (httpd_query_key_value(q, "op", v, sizeof(v)) != ESP_OK) return send_json(req, "{\"ok\":false,\"err\":\"no op\"}");
    if (!strcmp(v, "disc")) jb.op = OP_DISC;
    else if (!strcmp(v, "ent")) jb.op = OP_ENT;
    else if (!strcmp(v, "pwr")) jb.op = OP_PWR;
    else if (!strcmp(v, "std")) jb.op = OP_STD;
    else if (!strcmp(v, "uds")) jb.op = OP_UDS;
    else if (!strcmp(v, "ident")) jb.op = OP_IDENT;
    else if (!strcmp(v, "scan")) jb.op = OP_SCAN;
    else return send_json(req, "{\"ok\":false,\"err\":\"bad op\"}");
    if (httpd_query_key_value(q, "ip", v, sizeof(v)) == ESP_OK && v[0]) {
        if (!parse_ip(v, jb.ip)) return send_json(req, "{\"ok\":false,\"err\":\"bad ip\"}");
        if (jb.ip[0] != 192 || jb.ip[1] != 168 || jb.ip[2] != 61 || jb.ip[3] == 250 || jb.ip[3] == 0) {
            return send_json(req, "{\"ok\":false,\"err\":\"ip must be in 192.168.61.x (C5 has no route to other subnets)\"}");
        }
        jb.ip_set = true;
    }
    uint16_t la;
    if (httpd_query_key_value(q, "ta", v, sizeof(v)) == ESP_OK && v[0]) {
        if (!parse_la(v, &la)) return send_json(req, "{\"ok\":false,\"err\":\"bad ECU address\"}");
        jb.ta = la;
    }
    if (httpd_query_key_value(q, "sa", v, sizeof(v)) == ESP_OK && v[0]) {
        if (!parse_la(v, &la)) return send_json(req, "{\"ok\":false,\"err\":\"bad tester address\"}");
        if (la < 0x0E00 || la > 0x0FFF) return send_json(req, "{\"ok\":false,\"err\":\"tester address must be 0E00..0FFF\"}");
        jb.sa = la;
    }
    jb.pv = 2;
    if (httpd_query_key_value(q, "pv", v, sizeof(v)) == ESP_OK && v[0]) {
        if (!strcmp(v, "3") || !strcmp(v, "03")) jb.pv = 3;
        else if (strcmp(v, "2") && strcmp(v, "02")) return send_json(req, "{\"ok\":false,\"err\":\"bad DoIP version\"}");
    }
    if (jb.op == OP_SCAN) {
        if (httpd_query_key_value(q, "tl", big, sizeof(big)) != ESP_OK || !big[0]) return send_json(req, "{\"ok\":false,\"err\":\"no address list (max 32) or list too long\"}");
        url_dec(big);
        int n = parse_tl(big, jb.tl);
        if (n < 1) return send_json(req, "{\"ok\":false,\"err\":\"bad address list (max 32)\"}");
        jb.tl_n = (uint8_t)n;
    }
    if (jb.op == OP_UDS) {
        if (httpd_query_key_value(q, "uds", big, sizeof(big)) != ESP_OK) return send_json(req, "{\"ok\":false,\"err\":\"no UDS request\"}");
        url_dec(big);
        int n = parse_hex(big, jb.uds, UDS_MAX);
        if (n < 1) return send_json(req, "{\"ok\":false,\"err\":\"bad hex\"}");
        jb.uds_len = (uint8_t)n;
        if (!uds_allowed(jb.uds, jb.uds_len)) {
            return send_json(req, "{\"ok\":false,\"err\":\"blocked: only read services 22, 19, 3E 00/80, 10 03 are allowed\"}");
        }
    }
    esp_err_t r = ESP_OK;
    xSemaphoreTake(s_mtx, portMAX_DELAY);
    if (s_state == 1) {
        r = ESP_ERR_INVALID_STATE;
    } else {
        s_state = 1;
        s_cur_op = jb.op;
        s_seq++;
        s_t0_ms = esp_timer_get_time() / 1000;
        if (xQueueSend(s_q, &jb, 0) != pdTRUE) { s_state = 0; r = ESP_FAIL; }
    }
    xSemaphoreGive(s_mtx);
    if (r == ESP_ERR_INVALID_STATE) return send_json(req, "{\"ok\":false,\"err\":\"busy\"}");
    if (r != ESP_OK) return send_json(req, "{\"ok\":false,\"err\":\"queue full\"}");
    return send_json(req, "{\"ok\":true}");
}

static esp_err_t h_diag_get(httpd_req_t *req)
{
    size_t cap = 0;
    char *b = (char *)c5_web_io_buf(&cap);            /* v10: httpd scratch buffer, no malloc */
    uint32_t hf, hm, hl;
    c5_heap_stats(&hf, &hm, &hl);
    xSemaphoreTake(s_mtx, portMAX_DELAY);
    int n = snprintf(b, cap, "{\"state\":%d,\"op\":\"%s\",\"seq\":%lu,\"ms\":%lld,"
                     "\"heap\":{\"free\":%lu,\"min\":%lu,\"lfb\":%lu},\"res\":%s}", s_state,
                     OP_NAME[s_cur_op], (unsigned long)s_seq,
                     (long long)(s_state == 2 ? s_dur_ms : (esp_timer_get_time() / 1000 - s_t0_ms)),
                     (unsigned long)hf, (unsigned long)hm, (unsigned long)hl,
                     (s_state == 2 && s_res) ? s_res : (s_state == 2 ? "{\"ok\":false,\"err\":\"no memory\",\"items\":[],\"raw\":[]}" : "null"));
    xSemaphoreGive(s_mtx);
    if (n < 0 || (size_t)n >= cap) {
        /* v11.1: a cut response is invalid JSON; answer with a short valid one instead */
        n = snprintf(b, cap, "{\"state\":2,\"op\":\"none\",\"seq\":0,\"ms\":0,"
                     "\"res\":{\"ok\":false,\"err\":\"response too long\",\"items\":[],\"raw\":[]}}");
        if (n < 0) n = 0;
        if ((size_t)n >= cap) n = (int)cap - 1;
    }
    httpd_resp_set_type(req, "application/json; charset=utf-8");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    return httpd_resp_send(req, b, n);
}

void c5_diag_register(void *handle)
{
    httpd_handle_t srv = (httpd_handle_t)handle;
    if (!s_mtx) s_mtx = xSemaphoreCreateMutex();
    if (!s_q) s_q = xQueueCreate(1, sizeof(job_t));
    if (!s_mtx || !s_q) return;
    static bool started;
    if (!started) {
        started = true;
        xTaskCreate(diag_task, "c5_diag", 5120, NULL, 3, &s_task);
    }
    static const httpd_uri_t uris[] = {
        { "/diag", HTTP_GET, h_diag_page, NULL },
        { "/api/diag", HTTP_GET, h_diag_get, NULL },
        { "/api/diag", HTTP_POST, h_diag_post, NULL },
    };
    for (size_t i = 0; i < sizeof(uris) / sizeof(uris[0]); i++) httpd_register_uri_handler(srv, &uris[i]);
}
