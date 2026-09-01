# v5 payload format — SOLVED

The JPHSWIN 0.5 v5 payload transform is fully recovered and implemented in
`jpseek5.c`, verified byte-exact against eight known-plaintext samples. This
records how it works and how it was found.

## The format

A v5 container's payload is produced by:

1. **Bit embedding** — identical to v3's inner loop. A Blowfish keystream
   (key = `iv[0..5] || passphrase`, iv = first 8 DCT coefficients) drives the
   `ltab` coefficient walk; each payload data bit is XORed with keystream 1.

2. **Two-length header** — 16 bytes, read LSB-first, decrypted as two separate
   Blowfish blocks. Block 0 holds the compressed length (bytes 2,1,0); block 1
   holds the uncompressed length (bytes 11,8,4). Validity: `b[1]==b[9]`,
   `b[2]==b[10]`, `b[3]<=3`.

3. **Conditional LZO1X** — if the uncompressed length is nonzero, the extracted
   bytes are LZO1X-compressed and are decompressed to that length; if zero, they
   are the plaintext as-is. JPHSWIN compresses only when it saves space, so
   incompressible payloads are stored raw. The compressor is LZO 1.01 / minilzo
   (`LZO_BYTE_ORDER=1234`), from the binary's embedded version string. LZO1X is
   version-stable, so current minilzo decodes it.

4. **The v5 tail flag** — `dword_42023C = header_byte[3] & 1`. When set, the
   coefficient-acceptance loop consumes one extra keystream-2 bit per accepted
   coefficient (`sub_401878(2)`), on top of v3's existing tail gates. This is the
   one detail that makes v5 desync from v3 partway through the payload.

## Why differential analysis alone could not finish it

The tail flag lives in the encrypted header (byte 3, bit 0). It is invisible in
any input/output pair: two samples with the same passphrase and cover have the
same flag, so it never varies across the differential set, yet it shifts the
keystream alignment of every coefficient after the header. Recovering it required
reading the extraction routine itself — `sub_401035` in `jpseek.exe`, via its
Hex-Rays decompile. The decompile also gave the two-length header layout and the
`sub_403266 -> lzo1x_decompress` call directly.

## Verification

`selftest.sh` extracts all seven controlled samples (`fixtures/v5_samples/`) and
the real `jeremy23` sample and checks each against its known plaintext — eight
gates, all green. Coverage spans both paths: compressed (s03/s05/s06, exercising
LZO) and uncompressed (s01/s02/s04/s07 and the real sample).

## Provenance

`jpseek5.c` is an independent reimplementation from the decompiled algorithm;
`minilzo.c/.h` are Oberhumer's minilzo (LZO, GPL-compatible). The mapping of
`sub_*` names to roles (get_code_bit = sub_401878, get_word = sub_40198A,
decompress = sub_403266) is recorded in the source comments.
