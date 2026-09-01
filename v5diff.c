/*
 * v5diff.c - jphide v5 payload differential analyzer.
 *
 * JPHSWIN 0.5's v5 payload transform is undocumented (the author's own Readme
 * confirms v5 is format-incompatible with v3, and no 0.5 source exists). This
 * tool reverse-engineers it from known-plaintext samples: it extracts the raw
 * embedded bits from a v5 container in several interpretations at once, so that
 * comparing against a known plaintext reveals which transform JPHSWIN applied.
 *
 * The v5 HEADER logic (key = iv[0..5]||passphrase, length field, position
 * advance) is proven correct against stegbreak. Only the PAYLOAD transform is
 * unknown; this tool isolates it.
 *
 * Build: gcc -O2 -o v5diff v5diff.c bf.o -ljpeg
 * Usage: ./v5diff stego.jpg 'passphrase' [known_plaintext_file]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <jpeglib.h>
#include "bf.h"
#include "ltable.h"

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

static int get_word(int *value)
{
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
                coef = ltab[lt]; lw = spos = ltab[lt + 1]; lh = 0; mode = ltab[lt + 2];
            }
        }
        y = coefval(coef, lh, lw);
        ok = (coef || lh || lw > 7) ? 1 : 0;
        if (ok) {
            if (mode < 0) {
                if ((y > -mode) || (y < mode)) { ok = get_code_bit(0); ok <<= 1; ok |= get_code_bit(0); }
                else ok = 0;
            } else {
                if (mode == 3) ok = get_code_bit(0); else ok = 1;
                if (ok) {
                    if ((y > 1) || (y < -1)) ok = 0;
                    else { ok = get_code_bit(0); if (mode) { ok <<= 1; ok |= get_code_bit(0); } }
                    if (ok) ok = 0; else { if (mode > 1) ok = get_code_bit(0); else ok = 1; }
                }
            }
        }
        if (ok && tail_on > 0) ok = get_code_bit(2);
        if (ok && tail_on > 1) ok = get_code_bit(2);
        if (ok && tail_on > 2) ok = get_code_bit(2);
        if (ok) { *value = y; return 0; }
    }
}

static int payload_bit(void)   /* the raw data bit, no stream-1 xor */
{
    int y;
    if (get_word(&y)) return -1;
    if (y < 0) y = -y;
    if (mode < 0) { y &= 2; y >>= 1; }
    else y &= 1;
    return y;
}

static void hexdump(const char *label, unsigned char *d, int n)
{
    printf("%s", label);
    for (int i = 0; i < n && i < 32; i++) printf("%02x", d[i]);
    printf("%s\n", n > 32 ? "..." : "");
}

int main(int argc, char **argv)
{
    FILE *fp;
    int i, j, b, length;
    unsigned char raw[8], key[56], iv[9], lendata[16];

    if (argc < 3) {
        fprintf(stderr, "usage: v5diff stego.jpg passphrase [plaintext_file]\n");
        return 2;
    }
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

    for (i = 0; i < 8; i++) raw[i] = (unsigned char)coefval(0, 0, i);
    memcpy(key, raw, 6);
    memcpy(key + 6, argv[2], strlen(argv[2]));
    Blowfish_ExpandUserKey((char *)key, strlen(argv[2]) + 6, bkey);

    memcpy(iv, raw, 8);
    for (i = 0; i < NKSTREAMS; i++) {
        cpos[i] = 0;
        memcpy(cdata + i, iv, 8);
        ENC(cdata[i], cdata[i], bkey);
        iv[8] = iv[0];
        for (j = 0; j < 8; j++) iv[j] = iv[j + 1];
    }
    coef = ltab[0]; spos = ltab[1]; mode = ltab[2];
    lh = 0; lw = spos - 64; lt = 0; tail = 0; tail_on = 0;

    /* header: 16 bytes, LSB-packed (matches stegbreak) */
    for (i = 0; i < 16; i++) {
        unsigned char v = 0;
        for (j = 0; j < 8; j++) { if ((b = payload_bit()) < 0) { fprintf(stderr, "trunc\n"); return 1; } v |= (b << j); }
        lendata[i] = v;
    }
    { Blowfish_Data t; memcpy(t, lendata, 8); DEC(t, t, bkey); memcpy(lendata, t, 8); }
    length = (lendata[0] << 16) | (lendata[1] << 8) | lendata[2];
    printf("=== v5 header (validated) ===\n");
    printf("iv (first 8 DCT coeffs): ");
    for (i = 0; i < 8; i++) printf("%02x ", raw[i]);
    printf("\npayload length: %d bytes\n\n", length);

    if (length <= 0 || length > 100000) { fprintf(stderr, "implausible length\n"); return 1; }

    /* capture the raw payload bit sequence once */
    int nbits = length * 8;
    unsigned char *bits = malloc(nbits);
    unsigned char *ks1  = malloc(nbits);   /* stream-1 keystream, in lockstep */
    for (i = 0; i < nbits; i++) {
        int pb = payload_bit();
        if (pb < 0) { nbits = i; break; }
        bits[i] = pb;
        ks1[i] = get_code_bit(1);          /* advance stream 1 exactly as jpseek does */
    }

    /* build several interpretations */
    int nb = nbits / 8;
    unsigned char *msb_raw = calloc(nb, 1), *lsb_raw = calloc(nb, 1);
    unsigned char *msb_xor = calloc(nb, 1), *lsb_xor = calloc(nb, 1);
    for (i = 0; i < nb; i++) {
        for (j = 0; j < 8; j++) {
            int bit = bits[i * 8 + j];
            int bx  = bit ^ ks1[i * 8 + j];
            msb_raw[i] = (msb_raw[i] << 1) | bit;
            lsb_raw[i] |= (bit << j);
            msb_xor[i] = (msb_xor[i] << 1) | bx;
            lsb_xor[i] |= (bx << j);
        }
    }

    printf("=== payload interpretations (first 32 bytes each) ===\n");
    hexdump("MSB, raw (no xor) : ", msb_raw, nb);
    hexdump("LSB, raw (no xor) : ", lsb_raw, nb);
    hexdump("MSB, xor stream-1 : ", msb_xor, nb);
    hexdump("LSB, xor stream-1 : ", lsb_xor, nb);

    if (argc >= 4) {
        FILE *pf = fopen(argv[3], "rb");
        if (pf) {
            unsigned char pt[100000];
            int pn = fread(pt, 1, sizeof(pt), pf);
            fclose(pf);
            printf("\n=== known plaintext (%d bytes) ===\n", pn);
            hexdump("plaintext         : ", pt, pn);
            printf("\n=== derived keystream (plaintext XOR each interpretation) ===\n");
            printf("This is what stream would have to be to explain the plaintext.\n");
            int m = pn < nb ? pn : nb;
            unsigned char *ks = malloc(m);
            for (i = 0; i < m; i++) ks[i] = pt[i] ^ msb_raw[i];
            hexdump("pt ^ MSBraw       : ", ks, m);
            for (i = 0; i < m; i++) ks[i] = pt[i] ^ lsb_raw[i];
            hexdump("pt ^ LSBraw       : ", ks, m);
            printf("\nIf any row above matches a known Blowfish keystream, that's the transform.\n");
            printf("If plaintext == any interpretation row, there is NO payload encryption.\n");
        }
    }
    return 0;
}
