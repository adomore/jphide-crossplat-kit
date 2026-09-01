/*
 * jpseek5.c - jphide payload extractor for Linux (v3 + v5, auto-detect).
 * Reconstructed from jphs 0.3 jpseek.c (v3) and the JPHSWIN 0.5 jpseek.exe
 * decompile (v5). Tries v5 (key=iv||pass, 16-byte header, LZO1X) first, then
 * v3 (key=pass, 8-byte header, no compression).
 * Build: gcc -O2 -o jpseek5 jpseek5.c bf.o minilzo.o -ljpeg
 * Usage: ./jpseek5 stego.jpg 'passphrase' out.bin
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <jpeglib.h>
#include "bf.h"
#include "ltable.h"
#include "minilzo.h"

#define NKSTREAMS 4
static jvirt_barray_ptr *coef_arrays;
static struct jpeg_decompress_struct srcinfo;
static struct jpeg_error_mgr jsrcerr;
static int hib[3], wib[3];
#define ENC L_Blowfish_Encrypt
#define DEC L_Blowfish_Decrypt
static Blowfish_Key bkey;
static Blowfish_Data cdata[NKSTREAMS];
static unsigned int cpos[NKSTREAMS];
static int coef, mode, spos, lh, lt, lw, tail, tail_on, d42023c;
static unsigned char rawiv[8];

static short coefval(int c, int row, int col) {
    JBLOCKARRAY buf = (*srcinfo.mem->access_virt_barray)
        ((j_common_ptr)&srcinfo, coef_arrays[c], row, 1, FALSE);
    return buf[0][col / 64][col % 64];
}
static int get_code_bit(int k) {
    unsigned int a,b,c; unsigned char x,z;
    b = cpos[k] & 63;
    if (b == 0) ENC(cdata[k], cdata[k], bkey);
    a = b >> 3; x = ((unsigned char*)(cdata[k]))[a]; c = b & 7; z = x << c; z = z >> 7;
    cpos[k]++; return z;
}
static int get_word(int *value) {
    int y, ok;
    for (;;) {
        lw += 64;
        if (lw > wib[coef]) {
            lw = spos; lh++;
            if (!(lh < hib[coef])) {
                lt += 3;
                if (ltab[lt] < 0) return 1;
                if (tail < 0) {
                    if (tail_on == 2) { tail_on = 3; tail = 999999; }
                    if (tail_on == 1) { tail_on = 2; tail = TAIL3; }
                    if (tail_on == 0) { tail_on = 1; tail = TAIL2; }
                }
                coef = ltab[lt]; lw = spos = ltab[lt+1]; lh = 0; mode = ltab[lt+2];
            }
        }
        y = coefval(coef, lh, lw);
        ok = (coef || lh || lw > 7) ? 1 : 0;
        if (ok) {
            if (mode < 0) {
                if ((y > -mode) || (y < mode)) { ok = get_code_bit(0); ok <<= 1; ok |= get_code_bit(0); } else ok = 0;
            } else {
                if (mode == 3) ok = get_code_bit(0); else ok = 1;
                if (ok) {
                    if ((y > 1) || (y < -1)) ok = 0;
                    else { ok = get_code_bit(0); if (mode) { ok <<= 1; ok |= get_code_bit(0); } }
                    if (ok) ok = 0; else { if (mode > 1) ok = get_code_bit(0); else ok = 1; }
                }
            }
        }
        if (ok && d42023c) ok = get_code_bit(2);
        if (ok && tail_on > 0) ok = get_code_bit(2);
        if (ok && tail_on > 1) ok = get_code_bit(2);
        if (ok && tail_on > 2) ok = get_code_bit(2);
        if (ok) { *value = y; return 0; }
    }
}
static int get_bit(void) {
    int y;
    if (get_word(&y)) return -1;
    if (y < 0) y = -y;
    if (mode < 0) { y &= 2; y >>= 1; } else y &= 1;
    return y;
}
/* reset walk + keystream; returns rotated iv in iv_out */
static void setup(const char *word, int v5, unsigned char *iv_out) {
    unsigned char iv[9], key[128]; int i, j, wl = strlen(word);
    if (wl > 120) wl = 120;
    if (v5) { memcpy(key, rawiv, 6); memcpy(key + 6, word, wl); Blowfish_ExpandUserKey((char*)key, wl + 6, bkey); }
    else    { Blowfish_ExpandUserKey((char*)word, wl, bkey); }
    memcpy(iv, rawiv, 8);
    for (i = 0; i < NKSTREAMS; i++) {
        cpos[i] = 0; memcpy(cdata + i, iv, 8); ENC(cdata[i], cdata[i], bkey);
        iv[8] = iv[0]; for (j = 0; j < 8; j++) iv[j] = iv[j+1];
    }
    if (iv_out) memcpy(iv_out, iv, 8);
    coef = ltab[0]; spos = ltab[1]; mode = ltab[2];
    lh = 0; lw = spos - 64; lt = 0; tail = 0; tail_on = 0; d42023c = 0;
}

int main(int argc, char **argv) {
    FILE *fp; int i, j, b;
    unsigned char iv[9], hdr[16];
    if (argc != 4) { fprintf(stderr, "usage: jpseek5 stego.jpg passphrase outfile\n"); return 2; }
    if (lzo_init() != LZO_E_OK) { fprintf(stderr, "lzo_init failed\n"); return 2; }
    if ((fp = fopen(argv[1], "rb")) == NULL) { perror("open"); return 2; }
    srcinfo.err = jpeg_std_error(&jsrcerr);
    jpeg_create_decompress(&srcinfo);
    jpeg_stdio_src(&srcinfo, fp);
    jpeg_read_header(&srcinfo, TRUE);
    coef_arrays = jpeg_read_coefficients(&srcinfo);
    if (srcinfo.num_components != 3) { fprintf(stderr, "not 3-component\n"); return 2; }
    for (i = 0; i < 3; i++) {
        hib[i] = srcinfo.comp_info[i].height_in_blocks;
        wib[i] = 64 * srcinfo.comp_info[i].width_in_blocks - 1;
    }
    for (i = 0; i < 8; i++) rawiv[i] = (unsigned char)coefval(0, 0, i);

    char *word = argv[2];

    /* ---- try v5 ---- */
    setup(word, 1, iv);
    int hdr_ok = 1;
    for (i = 0; i < 16; i++) { unsigned char v = 0; for (j = 0; j < 8; j++) { if ((b = get_bit()) < 0) { hdr_ok = 0; break; } v |= (b << j); } if (!hdr_ok) break; hdr[i] = v; }
    if (hdr_ok) {
        unsigned char h[16]; memcpy(h, hdr, 16);
        { Blowfish_Data t; memcpy(t, h, 8);     DEC(t, t, bkey); memcpy(h, t, 8); }
        { Blowfish_Data t; memcpy(t, h + 8, 8); DEC(t, t, bkey); memcpy(h + 8, t, 8); }
        if (h[1] == h[9] && h[2] == h[10] && h[3] <= 3) {
            int complen = h[2] | (h[1] << 8) | (h[0] << 16);
            int rawlen  = h[11] | (h[8] << 8) | (h[4] << 16);
            fprintf(stderr, "v5 container: compressed=%d uncompressed=%d\n", complen, rawlen);
            if (complen <= 0 || complen > 100000000) { fprintf(stderr, "implausible length\n"); return 1; }
            d42023c = h[3] & 1;
            unsigned char *comp = malloc(complen);
            for (i = 0; i < complen; i++) { unsigned char v = 0; for (j = 0; j < 8; j++) { if ((b = get_bit()) < 0) { fprintf(stderr, "truncated payload\n"); return 1; } b ^= get_code_bit(1); v = (v << 1) | b; } comp[i] = v; }
            FILE *out = fopen(argv[3], "wb"); if (!out) { perror("out"); return 2; }
            if (rawlen) {
                unsigned char *plain = malloc(rawlen); lzo_uint ol = rawlen;
                int r = lzo1x_decompress_safe(comp, complen, plain, &ol, NULL);
                if (r != LZO_E_OK || ol != (lzo_uint)rawlen) { fprintf(stderr, "decompress failed (rc=%d got %lu want %d)\n", r, (unsigned long)ol, rawlen); return 1; }
                fwrite(plain, 1, rawlen, out); fprintf(stderr, "decompressed %d -> %d bytes\n", complen, rawlen);
            } else { fwrite(comp, 1, complen, out); fprintf(stderr, "wrote %d bytes (uncompressed)\n", complen); }
            fclose(out); fprintf(stderr, "extracted to %s\n", argv[3]); return 0;
        }
    }

    /* ---- try v3 ---- */
    setup(word, 0, iv);
    for (i = 0; i < 8; i++) { unsigned char v = 0; for (j = 0; j < 8; j++) { if ((b = get_bit()) < 0) { fprintf(stderr, "pass phrase wrong / not jphide\n"); return 1; } v |= (b << j); } hdr[i] = v; }
    { Blowfish_Data t; memcpy(t, hdr, 8); DEC(t, t, bkey); memcpy(hdr, t, 8); }
    { Blowfish_Data t; memcpy(t, iv, 8);  ENC(t, t, bkey); memcpy(iv, t, 8); }
    for (i = 3; i < 8; i++) if (hdr[i] != iv[i]) { fprintf(stderr, "pass phrase wrong / not jphide\n"); return 1; }
    int length = hdr[2] | (hdr[1] << 8) | (hdr[0] << 16);
    fprintf(stderr, "v3 container: payload=%d bytes\n", length);
    if (length <= 0 || length > 100000000) { fprintf(stderr, "implausible length\n"); return 1; }
    tail = length * 8 - TAIL1; tail_on = 0;
    FILE *out = fopen(argv[3], "wb"); if (!out) { perror("out"); return 2; }
    for (i = 0; i < length; i++) {
        unsigned char v = 0;
        for (j = 0; j < 8; j++) { if ((b = get_bit()) < 0) { fprintf(stderr, "truncated payload\n"); return 1; } b ^= get_code_bit(1); v = (v << 1) | b; tail--; }
        fputc(v, out);
    }
    fclose(out); fprintf(stderr, "wrote %d bytes (v3, uncompressed)\nextracted to %s\n", length, argv[3]); return 0;
}
