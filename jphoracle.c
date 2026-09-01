/*
 * jphoracle.c - independent verifier for the jphide container format.
 *
 * Reimplements the header validation of stegdetect's break_jphide.c
 * (Niels Provos) so that a stego JPEG can be classified as
 *   jphide v3   (key = passphrase)            <- jphs 0.3 / h3xx/jphs
 *   jphide v5   (key = iv[0..5] || passphrase) <- JPHS 0.5 / JPHSWIN
 * and, independently, as using big-endian or little-endian Blowfish
 * data ordering.
 *
 * Build: gcc -O2 -o jphoracle jphoracle.c bf.o -ljpeg
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <jpeglib.h>
#include "bf.h"

#include "ltable.h"   /* ltab[771], TAIL1/2/3 - byte-identical to stegdetect's jphide_table.c */

#define NKSTREAMS 4

static jvirt_barray_ptr *coef_arrays;
static struct jpeg_decompress_struct srcinfo;
static struct jpeg_error_mgr jsrcerr;
static int hib[3], wib[3];

/* selected Blowfish flavour */
typedef void (*bf_fn)(uint32_t *, uint32_t *, const Blowfish_Key);
static bf_fn ENC, DEC;

static Blowfish_Key bkey;
static Blowfish_Data cdata[NKSTREAMS];
static unsigned int cpos[NKSTREAMS];
static int coef, mode, spos, lh, lt, lw, tail, tail_on;

static short coefval(int c, int row, int col)
{
    JBLOCKARRAY buf = (*srcinfo.mem->access_virt_barray)
        ((j_common_ptr)&srcinfo, coef_arrays[c], row, 1, FALSE);
    return buf[0][col / 64][col % 64];
}

static int get_code_bit(int k)
{
    unsigned int a, b, c;
    unsigned char x, z;
    b = cpos[k] & 63;
    if (b == 0) ENC(cdata[k], cdata[k], bkey);
    a = b >> 3;
    x = ((unsigned char *)(cdata[k]))[a];
    c = b & 7;
    z = x << c;
    z = z >> 7;
    cpos[k]++;
    return z;
}

/* identical control flow to jpseek.c get_word() / break_jphide.c get_word() */
static int get_word(int *value)
{
    int y, ok;
    for (;;) {
        lw += 64;
        if (lw > wib[coef]) {
            lw = spos;
            lh++;
            if (!(lh < hib[coef])) {
                lt += 3;
                if (ltab[lt] < 0) return 1;
                if (tail < 0) {
                    if (tail_on == 2) { tail_on = 3; tail = 999999; }
                    if (tail_on == 1) { tail_on = 2; tail = TAIL3; }
                    if (tail_on == 0) { tail_on = 1; tail = TAIL2; }
                }
                coef = ltab[lt];
                lw = spos = ltab[lt + 1];
                lh = 0;
                mode = ltab[lt + 2];
            }
        }
        y = coefval(coef, lh, lw);
        ok = (coef || lh || lw > 7) ? 1 : 0;
        if (ok) {
            if (mode < 0) {
                if ((y > -mode) || (y < mode)) {
                    ok = get_code_bit(0); ok <<= 1; ok |= get_code_bit(0);
                } else ok = 0;
            } else {
                if (mode == 3) ok = get_code_bit(0); else ok = 1;
                if (ok) {
                    if ((y > 1) || (y < -1)) ok = 0;
                    else {
                        ok = get_code_bit(0);
                        if (mode) { ok <<= 1; ok |= get_code_bit(0); }
                    }
                    if (ok) ok = 0;
                    else { if (mode > 1) ok = get_code_bit(0); else ok = 1; }
                }
            }
        }
        if (ok && tail_on > 0) ok = get_code_bit(2);
        if (ok && tail_on > 1) ok = get_code_bit(2);
        if (ok && tail_on > 2) ok = get_code_bit(2);
        if (ok) { *value = y; return 0; }
    }
}

static int get_bit(void)
{
    int y;
    if (get_word(&y)) return -1;
    if (y < 0) y = -y;
    if (mode < 0) { y &= 2; y >>= 1; }
    else y &= 1;
    return y;
}

static int getbytes(unsigned char *out, int len)
{
    int i, j, b;
    unsigned char v;
    for (i = 0; i < len; i++) {
        v = 0;
        for (j = 0; j < 8; j++) {
            if ((b = get_bit()) < 0) return -1;
            v |= (b << j);
        }
        out[i] = v;
    }
    return 0;
}

static void setup(unsigned char *iv9)
{
    unsigned char iv[9];
    int i, j;
    for (i = 0; i < 8; i++) iv[i] = (unsigned char)coefval(0, 0, i);
    memcpy(iv9, iv, 8);
    for (i = 0; i < NKSTREAMS; i++) {
        cpos[i] = 0;
        memcpy(cdata + i, iv, 8);
        ENC(cdata[i], cdata[i], bkey);
        iv[8] = iv[0];
        for (j = 0; j < 8; j++) iv[j] = iv[j + 1];
    }
    memcpy(iv9, iv, 8);          /* iv after 4 rotations, as jphide/jpseek leave it */
    coef = ltab[0]; spos = ltab[1]; mode = ltab[2];
    lh = 0; lw = spos - 64; lt = 0; tail = 0; tail_on = 0;
}

/* --- stegdetect break_jphide_v3: key = passphrase, single 8-byte header --- */
static int try_v3(const char *pass, int *outlen)
{
    unsigned char iv[9], lendata[8];
    int i, length;
    Blowfish_ExpandUserKey(pass, strlen(pass), bkey);
    setup(iv);
    if (getbytes(lendata, 8) == -1) return 0;
    DEC((uint32_t *)lendata, (uint32_t *)lendata, bkey);
    length = (lendata[0] << 16) | (lendata[1] << 8) | lendata[2];
    ENC((uint32_t *)iv, (uint32_t *)iv, bkey);
    for (i = 3; i < 8; i++)
        if (lendata[i] != iv[i]) return 0;
    *outlen = length;
    return 1;
}

/* --- stegdetect break_jphide_v5: key = iv[0..5]||passphrase, 16-byte header --- */
static int try_v5(const char *pass, int *outlen)
{
    unsigned char iv[9], iv2[8], lendata[16], key[56], rawiv[8];
    int i, length, rlength;
    for (i = 0; i < 8; i++) rawiv[i] = (unsigned char)coefval(0, 0, i);
    memcpy(key, rawiv, 6);
    memcpy(key + 6, pass, strlen(pass));
    Blowfish_ExpandUserKey((char *)key, strlen(pass) + 6, bkey);
    setup(iv);
    if (getbytes(lendata, 8) == -1) return 0;
    DEC((uint32_t *)lendata, (uint32_t *)lendata, bkey);
    if (lendata[3] > 3) return 0;
    length = (lendata[0] << 16) | (lendata[1] << 8) | lendata[2];
    ENC((uint32_t *)iv, (uint32_t *)iv, bkey);
    if (memcmp(iv + 5, lendata + 5, 3)) return 0;
    if (getbytes(lendata + 8, 8) == -1) return 0;
    DEC((uint32_t *)(lendata + 8), (uint32_t *)(lendata + 8), bkey);
    if (lendata[9] != lendata[1] || lendata[10] != lendata[2]) return 0;
    rlength = (lendata[4] << 16) | (lendata[8] << 8) | lendata[11];
    if (rlength && (rlength < length || rlength > 20 * length)) return 0;
    memcpy(iv2, iv, 8);
    ENC((uint32_t *)iv2, (uint32_t *)iv2, bkey);
    if (memcmp(iv2 + 4, lendata + 12, 4)) return 0;
    *outlen = length;
    return 1;
}

int main(int argc, char **argv)
{
    FILE *fp;
    int i, len;
    const char *flav[2] = { "big-endian", "little-endian" };
    bf_fn encs[2] = { B_Blowfish_Encrypt, L_Blowfish_Encrypt };
    bf_fn decs[2] = { B_Blowfish_Decrypt, L_Blowfish_Decrypt };

    if (argc != 3) { fprintf(stderr, "usage: jphoracle file.jpg passphrase\n"); return 2; }
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

    printf("file: %s   passphrase: \"%s\"\n", argv[1], argv[2]);
    for (i = 0; i < 2; i++) {
        ENC = encs[i]; DEC = decs[i];
        if (try_v3(argv[2], &len))
            printf("  MATCH  jphide v3  Blowfish=%-13s  payload length = %d bytes\n", flav[i], len);
        if (try_v5(argv[2], &len))
            printf("  MATCH  jphide v5  Blowfish=%-13s  payload length = %d bytes\n", flav[i], len);
    }
    printf("  (no further lines above = no header match for that combination)\n");
    return 0;
}
