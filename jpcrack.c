/*
 * jpcrack.c - jphide dictionary attack for Linux (v3 + v5).
 *
 * Decodes the cover JPEG once, then tries each wordlist candidate against both
 * the v3 (JPHS 0.3) and v5 (JPHSWIN 0.5) header checks -- the same validation
 * stegbreak uses, reconstructed from break_jphide.c and the jpseek.exe decompile.
 * On a hit it reports the version and passphrase; with -o it also extracts the
 * payload (delegating to the same logic as jpseek5, LZO1X included).
 *
 * The per-candidate cost is dominated by Blowfish_ExpandUserKey (~30k/s/core),
 * which is the throughput ceiling; jpcrack parallelises across cores to beat it.
 *
 * Build: gcc -O2 -pthread -o jpcrack jpcrack.c bf.o minilzo.o -ljpeg
 * Usage: ./jpcrack [-t N] [-o out.bin] stego.jpg wordlist
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <jpeglib.h>
#include "bf.h"
#include "ltable.h"
#include "minilzo.h"
#include <time.h>

static int g_rules_on = 1;             /* -n disables rule mangling */
static int g_prog_interval = 0;        /* -p N: auto status line every N s (0 = Ctrl-C only) */
static long g_total_cands = 0;         /* wordlist size after rule expansion -> % and ETA denominator */
static volatile sig_atomic_t g_show_progress;
static double g_wall_start;
static char g_last_word[256];          /* most recent candidate, display only */
static double now_sec(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec+t.tv_nsec/1e9; }
static void on_sigint(int sig){ (void)sig; g_show_progress=1; }

#define NKSTREAMS 4

/* ---- shared read-only cover data (decoded once) ---- */
static int g_hib[3], g_wib[3];
static unsigned char g_iv[8];
static long g_bits;   /* image coefficient capacity = sum(hib*wib*64); v5 length must fit */

/* cached coefficients in ltab-walk order (position-only; keystream applied per candidate) */
#define CACHE_MAX 300000
static short g_y[CACHE_MAX];
static short g_mode[CACHE_MAX];
static unsigned char g_ok0[CACHE_MAX];
static int g_cache_len;

/* ---- per-thread crypto state ---- */
typedef struct {
    Blowfish_Key bkey;
    Blowfish_Data cdata[NKSTREAMS];
    unsigned int cpos[NKSTREAMS];
    int mode, tail, ton, d42;
    int cpos_cache;
} ctx_t;

static int gcb(ctx_t *c, int k) {
    unsigned int a, b, cc; unsigned char x, z;
    b = c->cpos[k] & 63;
    if (b == 0) L_Blowfish_Encrypt(c->cdata[k], c->cdata[k], c->bkey);
    a = b >> 3; x = ((unsigned char*)(c->cdata[k]))[a]; cc = b & 7; z = x << cc; z = z >> 7;
    c->cpos[k]++; return z;
}
static int gw(ctx_t *c, int *v) {
    int ok;
    for (;;) {
        if (c->cpos_cache >= g_cache_len) return 1;
        short y = g_y[c->cpos_cache];
        c->mode = g_mode[c->cpos_cache];
        ok = g_ok0[c->cpos_cache];
        c->cpos_cache++;
        if (ok) {
            if (c->mode < 0) {
                if ((y > -c->mode) || (y < c->mode)) { ok = gcb(c,0); ok <<= 1; ok |= gcb(c,0); } else ok = 0;
            } else {
                if (c->mode == 3) ok = gcb(c,0); else ok = 1;
                if (ok) {
                    if ((y > 1) || (y < -1)) ok = 0; else { ok = gcb(c,0); if (c->mode) { ok <<= 1; ok |= gcb(c,0); } }
                    if (ok) ok = 0; else { if (c->mode > 1) ok = gcb(c,0); else ok = 1; }
                }
            }
        }
        if (ok && c->d42) ok = gcb(c,2);
        if (ok && c->ton > 0) ok = gcb(c,2);
        if (ok && c->ton > 1) ok = gcb(c,2);
        if (ok && c->ton > 2) ok = gcb(c,2);
        if (ok) { *v = y; return 0; }
    }
}
static int gb(ctx_t *c) {
    int y;
    if (gw(c, &y)) return -1;
    if (y < 0) y = -y;
    if (c->mode < 0) { y &= 2; y >>= 1; } else y &= 1;
    return y;
}
static void ks_init(ctx_t *c, const unsigned char *rawiv, unsigned char *iv_out) {
    unsigned char iv[9]; int i, j;
    memcpy(iv, rawiv, 8);
    for (i = 0; i < NKSTREAMS; i++) {
        c->cpos[i] = 0;
        memcpy(c->cdata + i, iv, 8);
        L_Blowfish_Encrypt(c->cdata[i], c->cdata[i], c->bkey);
        iv[8] = iv[0]; for (j = 0; j < 8; j++) iv[j] = iv[j+1];
    }
    if (iv_out) memcpy(iv_out, iv, 8);   /* iv after 4 rotations, as jphide leaves it */
    c->cpos_cache = 0; c->tail = 0; c->ton = 0; c->d42 = 0;
}

/* returns 3 or 5 on match, 0 on no match */

/* --- wordlist rule engine (JtR-style common mangles) ---
   For each base word, generate high-value variants that crack weak passphrases:
   the base itself, case changes, appended/prepended digits and symbols, a few
   leetspeak swaps, reverse, and duplicate. This mirrors a default rules.ini and
   reproduces stegbreak results like kaosmon -> Kaosmon0. Disable with -n. */
typedef int (*cand_cb)(ctx_t *c, const char *word);

static int rules_apply(ctx_t *c, const char *base, cand_cb cb) {
    char buf[300]; int L = strlen(base), i;
    if (L == 0 || L > 250) return 0;

    /* :  the word as-is */
    if (cb(c, base)) return 1;
    if (!g_rules_on) return 0;

    /* c  capitalize first letter */
    strcpy(buf, base);
    if (buf[0] >= 'a' && buf[0] <= 'z') { buf[0] -= 32; if (cb(c, buf)) return 1; }

    /* u  uppercase all */
    for (i = 0; i < L; i++) buf[i] = (base[i] >= 'a' && base[i] <= 'z') ? base[i] - 32 : base[i];
    buf[L] = 0; if (cb(c, buf)) return 1;

    /* l  lowercase all (in case base has caps) */
    for (i = 0; i < L; i++) buf[i] = (base[i] >= 'A' && base[i] <= 'Z') ? base[i] + 32 : base[i];
    buf[L] = 0; if (cb(c, buf)) return 1;

    /* $N  append each digit 0-9, to base AND to capitalized base */
    for (int cap = 0; cap < 2; cap++) {
        strcpy(buf, base);
        if (cap) { if (buf[0] >= 'a' && buf[0] <= 'z') buf[0] -= 32; else continue; }
        for (char d = '0'; d <= '9'; d++) { buf[L] = d; buf[L+1] = 0; if (cb(c, buf)) return 1; }
    }

    /* $$  append common two-digit / symbol suffixes */
    { const char *suf[] = {"23","1","12","123","1234","12345","!","@","#","01","007","69","111","2020","2021","2022","2023","2024","00", NULL};
      for (int cap = 0; cap < 2; cap++) {
          char b2[300]; strcpy(b2, base);
          if (cap) { if (b2[0] >= 'a' && b2[0] <= 'z') b2[0] -= 32; else continue; }
          for (int k = 0; suf[k]; k++) { snprintf(buf, sizeof(buf), "%s%s", b2, suf[k]); if (cb(c, buf)) return 1; } } }

    /* ^N  prepend each digit 0-9 */
    for (char d = '0'; d <= '9'; d++) { buf[0] = d; strcpy(buf+1, base); if (cb(c, buf)) return 1; }

    /* r  reverse */
    for (i = 0; i < L; i++) buf[i] = base[L-1-i]; buf[L] = 0; if (cb(c, buf)) return 1;

    /* d  duplicate */
    if (L * 2 < (int)sizeof(buf)) { strcpy(buf, base); strcpy(buf+L, base); if (cb(c, buf)) return 1; }

    /* leetspeak: a->@ a->4 e->3 i->1 o->0 s->$ (single global swap each) */
    { struct { char f, t; } sw[] = {{'a','@'},{'a','4'},{'e','3'},{'i','1'},{'o','0'},{'s','$'},{'s','5'},{'t','7'}};
      for (int k = 0; k < 8; k++) { int changed = 0; for (i = 0; i < L; i++) { char ch = base[i]; if (ch == sw[k].f) { buf[i] = sw[k].t; changed = 1; } else buf[i] = ch; } buf[L] = 0; if (changed && cb(c, buf)) return 1; } }

    return 0;
}

/* Number of candidates rules_apply() emits for `base`, computed WITHOUT running
   any crypto. This is the progress denominator; it MUST stay in lockstep with
   rules_apply() above -- every rule that calls cb() there is counted here.
   On an exhausted run, sum(count_variants) == g_count exactly, which is a live
   proof the two agree (see the "exhausted" line in main). */
static long count_variants(const char *base) {
    int L = (int)strlen(base);
    if (L == 0 || L > 250) return 0;           /* rules_apply bails before cb() */
    if (!g_rules_on) return 1;                 /* -n: base word only */
    int lc = (base[0] >= 'a' && base[0] <= 'z');   /* lowercase-initial? */
    long n = 1;                 /* :  base as-is */
    if (lc) n += 1;             /* c  capitalize (only if lowercase-initial) */
    n += 2;                     /* u + l  upper-all and lower-all (always emitted) */
    n += lc ? 20 : 10;          /* $N append digit 0-9, doubled for capitalized base */
    n += lc ? 38 : 19;          /* $$ append 19 suffixes, doubled (keep 19 == suf[] count) */
    n += 10;                    /* ^N prepend digit 0-9 */
    n += 1;                     /* r  reverse */
    if (L * 2 < 300) n += 1;    /* d  duplicate (buf is char[300]) */
    /* leet: one candidate per rule whose source char is present; a and s twice */
    int a=0,e=0,i1=0,o=0,s=0,t=0, i;
    for (i = 0; i < L; i++) {
        char ch = base[i];
        if (ch=='a') a=1; else if (ch=='e') e=1; else if (ch=='i') i1=1;
        else if (ch=='o') o=1; else if (ch=='s') s=1; else if (ch=='t') t=1;
    }
    n += 2*a + e + i1 + o + 2*s + t;
    return n;
}

static void fmt_hms(double sec, char *out, size_t n) {
    if (sec < 0 || sec > 3.15e8) { snprintf(out, n, "--:--:--"); return; }
    long s = (long)(sec + 0.5);
    snprintf(out, n, "%ld:%02ld:%02ld", s / 3600, (s / 60) % 60, s % 60);
}

static int test_candidate(ctx_t *c, const char *word) {
    unsigned char key[128], iv[9], hdr[16]; int i, j;
    int wl = strlen(word);
    if (wl > 120) wl = 120;

    /* --- v5: key = iv[0..5] || word --- */
    memcpy(key, g_iv, 6);
    memcpy(key + 6, word, wl);
    Blowfish_ExpandUserKey((char*)key, wl + 6, c->bkey);
    ks_init(c, g_iv, iv);
    unsigned char h[16];
    int v5_ok = 1;
    for (i = 0; i < 16; i++) {
        unsigned char v = 0;
        for (j = 0; j < 8; j++) { int b = gb(c); if (b < 0) { v5_ok = 0; break; } v |= (b << j); }
        if (!v5_ok) break; h[i] = v;
    }
    if (v5_ok) {
        /* full break_jphide_v5 validation (5 layers, ~2^-64 false-positive rate) */
        unsigned char iv_enc[8], iv2[8], b0[8], b1[8];
        memcpy(b0, h, 8);     { Blowfish_Data t; memcpy(t, b0, 8); L_Blowfish_Decrypt(t, t, c->bkey); memcpy(b0, t, 8); }
        if (b0[3] <= 3) {
            int length = (b0[0] << 16) | (b0[1] << 8) | b0[2];
            if ((long)length * 8 < g_bits) {          /* layer 3: fits in image */
                memcpy(iv_enc, iv, 8); { Blowfish_Data t; memcpy(t, iv_enc, 8); L_Blowfish_Encrypt(t, t, c->bkey); memcpy(iv_enc, t, 8); }
                if (memcmp(iv_enc + 5, b0 + 5, 3) == 0) {   /* layer 2: iv[5..7] vs decrypted block0 */
                    memcpy(b1, h + 8, 8); { Blowfish_Data t; memcpy(t, b1, 8); L_Blowfish_Decrypt(t, t, c->bkey); memcpy(b1, t, 8); }
                    if (b1[1] == b0[1] && b1[2] == b0[2]) {   /* layer 4: block1 cross-check */
                        int rlength = (b0[4] << 16) | (b1[0] << 8) | b1[3];
                        if (!(rlength && (rlength < length || rlength > 20 * length))) {  /* layer 5a */
                            memcpy(iv2, iv_enc, 8); { Blowfish_Data t; memcpy(t, iv2, 8); L_Blowfish_Encrypt(t, t, c->bkey); memcpy(iv2, t, 8); }
                            if (memcmp(iv2 + 4, b1 + 4, 4) == 0)   /* layer 5b: iv2[4..7] vs decrypted block1 */
                                return 5;
                        }
                    }
                }
            }
        }
    }

try_v3:
    /* --- v3: key = word --- */
    Blowfish_ExpandUserKey((char*)word, wl, c->bkey);
    ks_init(c, g_iv, iv);           /* iv now holds the rotated iv */
    for (i = 0; i < 8; i++) {
        unsigned char v = 0;
        for (j = 0; j < 8; j++) { int b = gb(c); if (b < 0) return 0; v |= (b << j); }
        hdr[i] = v;
    }
    { Blowfish_Data t; memcpy(t, hdr, 8); L_Blowfish_Decrypt(t, t, c->bkey); memcpy(hdr, t, 8); }
    { Blowfish_Data t; memcpy(t, iv, 8); L_Blowfish_Encrypt(t, t, c->bkey); memcpy(iv, t, 8); }
    int v3len = (hdr[0] << 16) | (hdr[1] << 8) | hdr[2];
    if ((long)v3len * 8 >= g_bits) return 0;    /* v3 length must fit too */
    for (i = 3; i < 8; i++) if (hdr[i] != iv[i]) return 0;
    return 3;
}

/* ---- wordlist feeding (mmap-free, simple shared file with a mutex) ---- */
static FILE *g_wl;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static volatile int g_found;
static volatile int g_done;
static char g_found_word[256];
static int g_found_ver;
static volatile long g_count;

static int next_word(char *buf, int bufsz) {
    int ret = 0;
    pthread_mutex_lock(&g_lock);
    if (!g_found && fgets(buf, bufsz, g_wl)) {
        int L = strlen(buf);
        while (L > 0 && (buf[L-1] == '\n' || buf[L-1] == '\r')) buf[--L] = 0;
        ret = (L > 0) ? 1 : 2;   /* 2 = empty line, skip but keep going */
    }
    pthread_mutex_unlock(&g_lock);
    return ret;
}

/* callback: test one mangled candidate; record it and count it */
static int try_one(ctx_t *c, const char *word) {
    __atomic_add_fetch(&g_count, 1, __ATOMIC_RELAXED);
    strncpy(g_last_word, word, sizeof(g_last_word)-1);   /* benign race, display only */
    int ver = test_candidate(c, word);
    if (ver) {
        pthread_mutex_lock(&g_lock);
        if (!g_found) { g_found = 1; g_found_ver = ver; strncpy(g_found_word, word, sizeof(g_found_word)-1); }
        pthread_mutex_unlock(&g_lock);
        return 1;
    }
    return 0;
}


/* progress reporter: prints a status line on SIGINT, and -- if -p N was given --
   automatically every N seconds. Percentage/ETA use g_total_cands as denominator. */
static void *progress_reporter(void *arg) {
    (void)arg;
    double last_auto = now_sec();
    while (!g_done) {
        double tnow = now_sec();
        int due = g_show_progress ||
                  (g_prog_interval > 0 && tnow - last_auto >= (double)g_prog_interval);
        if (due) {
            g_show_progress = 0;
            last_auto = tnow;
            double dt = tnow - g_wall_start;
            long n = g_count;
            double rate = n / (dt > 0 ? dt : 1);
            char pctbuf[16], eta[16];
            if (g_total_cands > 0) {
                double pct = 100.0 * (double)n / (double)g_total_cands;
                if (pct > 100.0) pct = 100.0;
                double remain = (double)g_total_cands - (double)n;
                snprintf(pctbuf, sizeof(pctbuf), "%6.3f%%", pct);
                fmt_hms(rate > 0 ? remain / rate : -1, eta, sizeof(eta));
            } else {
                snprintf(pctbuf, sizeof(pctbuf), "   ?.??%%");
                snprintf(eta, sizeof(eta), "--:--:--");
            }
            fprintf(stderr, "Status: %s  %ld/%ld  %.1f c/s  ETA %s: %s\n",
                    pctbuf, n, g_total_cands, rate, eta, g_last_word);
        }
        struct timespec ts = {0, 100000000}; nanosleep(&ts, NULL);  /* 100ms poll */
    }
    return NULL;
}

static void *worker(void *arg) {
    ctx_t c; char base[256];
    (void)arg;
    for (;;) {
        int r = next_word(base, sizeof(base));
        if (r == 0) break;
        if (r == 2) continue;
        if (g_found) break;
        if (rules_apply(&c, base, try_one)) break;
    }
    return NULL;
}

/* ---- coefficient cache build (once) ---- */
static struct jpeg_decompress_struct si;
static struct jpeg_error_mgr je;
static jvirt_barray_ptr *coef_arrays;
static short cv(int cc, int r, int col) {
    JBLOCKARRAY b = (*si.mem->access_virt_barray)((j_common_ptr)&si, coef_arrays[cc], r, 1, FALSE);
    return b[0][col/64][col%64];
}
static void build_cache(void) {
    int c = ltab[0], sp = ltab[1], h = 0, l = sp - 64, t = 0, md = ltab[2];
    g_cache_len = 0;
    for (;;) {
        l += 64;
        if (l > g_wib[c]) {
            l = sp; h++;
            if (!(h < g_hib[c])) {
                t += 3;
                if (ltab[t] < 0) break;
                c = ltab[t]; l = sp = ltab[t+1]; h = 0; md = ltab[t+2];
            }
        }
        if (g_cache_len >= CACHE_MAX) break;
        g_y[g_cache_len] = cv(c, h, l);
        g_mode[g_cache_len] = md;
        g_ok0[g_cache_len] = (c || h || l > 7) ? 1 : 0;
        g_cache_len++;
    }
}

int main(int argc, char **argv) {
    int nthreads = 0, opt;
    char *outfile = NULL;
    while ((opt = getopt(argc, argv, "t:o:np:")) != -1) {
        if (opt == 't') nthreads = atoi(optarg);
        else if (opt == 'o') outfile = optarg;
        else if (opt == 'n') g_rules_on = 0;
        else if (opt == 'p') g_prog_interval = atoi(optarg);
        else { fprintf(stderr, "usage: jpcrack [-t N] [-o out.bin] [-n] [-p SEC] stego.jpg wordlist\n  -n      disable rule mangling (test words verbatim)\n  -p SEC  auto-print a progress line (with %%, c/s, ETA) every SEC seconds\n  Ctrl+C once also prints a progress line.\n"); return 2; }
    }
    if (argc - optind != 2) { fprintf(stderr, "usage: jpcrack [-t N] [-o out.bin] stego.jpg wordlist\n"); return 2; }
    char *jpgfile = argv[optind], *wlfile = argv[optind+1];
    if (nthreads <= 0) { long n = sysconf(_SC_NPROCESSORS_ONLN); nthreads = (n > 0) ? (int)n : 1; }

    if (lzo_init() != LZO_E_OK) { fprintf(stderr, "lzo_init failed\n"); return 2; }
    FILE *fp = fopen(jpgfile, "rb");
    if (!fp) { perror("open jpeg"); return 2; }
    si.err = jpeg_std_error(&je);
    jpeg_create_decompress(&si);
    jpeg_stdio_src(&si, fp);
    jpeg_read_header(&si, TRUE);
    coef_arrays = jpeg_read_coefficients(&si);
    if (si.num_components != 3) { fprintf(stderr, "not a 3-component JPEG\n"); return 2; }
    for (int i = 0; i < 3; i++) { g_hib[i] = si.comp_info[i].height_in_blocks; g_wib[i] = 64 * si.comp_info[i].width_in_blocks - 1; }
    for (int i = 0; i < 8; i++) g_iv[i] = (unsigned char)cv(0, 0, i);
    g_bits = 0;
    for (int i = 0; i < 3; i++) g_bits += (long)si.comp_info[i].height_in_blocks * si.comp_info[i].width_in_blocks * 64;
    build_cache();

    g_wl = fopen(wlfile, "r");
    if (!g_wl) { perror("open wordlist"); return 2; }

    /* Pre-scan the wordlist once (no crypto) to size the progress denominator.
       Uses the SAME buffer and \r\n/empty-line handling as next_word(), so the
       per-word count matches exactly what the workers will feed to rules_apply.
       Skipped (denominator stays 0 -> "?.??%") if the list is not seekable. */
    {
        char lbuf[256];
        g_total_cands = 0;
        while (fgets(lbuf, sizeof(lbuf), g_wl)) {
            int L = (int)strlen(lbuf);
            while (L > 0 && (lbuf[L-1] == '\n' || lbuf[L-1] == '\r')) lbuf[--L] = 0;
            g_total_cands += count_variants(lbuf);
        }
        if (fseek(g_wl, 0, SEEK_SET) != 0) { g_total_cands = 0; rewind(g_wl); }
    }

    fprintf(stderr, "jpcrack: %d threads, cached %d coefficients, %ld candidates to test%s\n",
            nthreads, g_cache_len, g_total_cands, g_rules_on ? "" : " (-n, verbatim)");
    g_wall_start = now_sec();
    struct timespec wt0; clock_gettime(CLOCK_MONOTONIC, &wt0);
    signal(SIGINT, on_sigint);
    pthread_t prog; pthread_create(&prog, NULL, progress_reporter, NULL);

    pthread_t *th = malloc(sizeof(pthread_t) * nthreads);
    for (int i = 0; i < nthreads; i++) pthread_create(&th[i], NULL, worker, NULL);
    for (int i = 0; i < nthreads; i++) pthread_join(th[i], NULL);
    g_done = 1;  /* signal progress thread to stop */
    pthread_join(prog, NULL);

    struct timespec wt1; clock_gettime(CLOCK_MONOTONIC, &wt1);
    double wall = (wt1.tv_sec - wt0.tv_sec) + (wt1.tv_nsec - wt0.tv_nsec) / 1e9;

    if (g_found) {
        printf("FOUND: jphide[v%d](%s)  [%ld candidates, %.2fs, %.0f c/s]\n",
               g_found_ver, g_found_word, g_count, wall, g_count / (wall > 0 ? wall : 1));
        if (outfile) {
            /* delegate extraction to jpseek5 for a clean single-source-of-truth path */
            char cmd[1024];
            snprintf(cmd, sizeof(cmd), "./jpseek5 '%s' '%s' '%s'", jpgfile, g_found_word, outfile);
            fprintf(stderr, "extracting payload -> %s\n", outfile);
            int rc = system(cmd);
            if (rc != 0) fprintf(stderr, "(jpseek5 extraction returned %d)\n", rc);
        }
        return 0;
    }
    printf("exhausted %ld candidates in %.2fs (%.0f c/s), no match\n",
           g_count, wall, g_count / (wall > 0 ? wall : 1));
    return 1;
}
