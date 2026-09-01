<div align="center">

<h1>jphide-crossplat-kit</h1>

<p><b>Cross-platform JPHide steganography diagnostics &amp; payload extraction</b></p>

<p>Diagnostic kit for cross-platform failures between <b>JPHS on Windows</b> and<br><b><code>h3xx/jphs</code> + <code>stegdetect</code> on Kali / Debian 12</b>.</p>

<p>
<a href="https://github.com/adomore/jphide-crossplat-kit/releases/latest"><img alt="release" src="https://img.shields.io/github/v/release/adomore/jphide-crossplat-kit?style=flat-square&label=release&color=1793d1"></a>
<a href="LICENSE"><img alt="license" src="https://img.shields.io/github/license/adomore/jphide-crossplat-kit?style=flat-square&color=blue"></a>
<img alt="platform" src="https://img.shields.io/badge/platform-Kali%20%2F%20Debian%2012-1793d1?style=flat-square">
<img alt="lang" src="https://img.shields.io/badge/lang-C%20%2B%20Python-555?style=flat-square">
<img alt="selftest" src="https://img.shields.io/badge/selftest-29%2F29%20green-2ea44f?style=flat-square">
</p>

<p><a href="README.md">中文</a> · <b>English</b>　·　Author: Anonymous　·　Version: 2.3</p>

</div>

---

**At a glance**

- **Classify** — `jphoracle`: identify container version (v3 / v5) and Blowfish byte order (big / little-endian)
- **Extract** — `jpseek5`: recover v3/v5 payloads natively on Linux (Blowfish + LZO1X, byte-exact verified), no Wine
- **Crack** — `jpcrack`: multi-threaded dictionary attack; `-o` extracts the plaintext on a hit
- **Repair** — `crlf_check.py`: detect and repair Windows text-mode (CRLF) damage
- **Build** — `build-stegdetect-kali.sh`: build `stegdetect` / `stegbreak` from source on Kali / Debian (with toolchain probing)
- **Self-test** — `selftest.sh`: 29 reproducible gates

> [!TIP]
> **Prebuilt Kali (amd64) bundle** — download `jphide-crossplat-kit-2.3-kali-amd64.tar.gz` from [Releases](https://github.com/adomore/jphide-crossplat-kit/releases/latest); after unpacking, `./selftest.sh` should report 29/29 all green.

> [!NOTE]
> **Documentation.** New users should start with [`GETTING_STARTED.md`](GETTING_STARTED.md) (Chinese [`GETTING_STARTED_zh.md`](GETTING_STARTED_zh.md)); the full reference is [`USER_MANUAL.md`](USER_MANUAL.md) (Chinese [`USER_MANUAL_zh.md`](USER_MANUAL_zh.md)). This README records the verified cross-platform findings the kit was built to prove. The mirrored Chinese edition is [`README.md`](README.md); the two files are maintained in lockstep, section by section.

<div align="center">

[**What this is**](#1-what-this-is) · [**Verified findings**](#2-verified-findings) · [**Contents**](#3-contents) · [**Build**](#4-build) · [**Usage**](#5-usage) · [**Gate suite**](#6-gate-suite) · [**Portability patch**](#7-the-portability-patch) · [**Limits**](#8-what-this-kit-does-not-solve) · [**Provenance &amp; license**](#9-provenance-and-licensing)

</div>

---

## 1. What this is

The common report is: a JPEG carrying a jphide payload made on Windows hides and
seeks perfectly on Windows, but on Kali neither `stegdetect` flags it nor
`jpseek` extracts it. The usual first guess is Windows line-ending translation.

This kit exists to replace that guess with a measurement. It answers three
questions about a specific file:

- Which jphide container version is it, **v3** or **v5**?
- Which Blowfish data byte order was used, **big-endian** or **little-endian**?
- Was the file damaged by a Windows text-mode stream, and can it be repaired?

---

## 2. Verified findings

Everything below was reproduced in a container, not inferred from documentation.

### `h3xx/jphs` and Windows JPHS are two incompatible container formats

`h3xx/jphs` carries `HS_MINOR_VERSION 3`; the Windows package (`JPHSWIN.EXE`,
`jphs05.zip`) is JPHS 0.5. `stegdetect`'s `break_jphide.c` implements the two as
separate validation paths. In v3 the Blowfish key is the passphrase alone and
the header is one 8-byte block. In v5 the key is the first 6 bytes of the
DCT-derived IV concatenated with the passphrase, and the header is two blocks
with a redundant length field and a second IV check. Different key derivation
plus different header layout means a v3 reader cannot even recover the length
field of a v5 container.

### The default Blowfish byte order in `h3xx/jphs` is wrong (proven, not inferred)

`bf_config.h` defaults to `B_Blowfish_Encrypt` (big-endian), and the
repository's own `TODO` admits the question was never settled. A 32-bit
`stegbreak` built from the reference sources, given a wordlist containing the
correct passphrase, returns:

```text
stego_v3_le.jph : jphide[v3](TestPass123)     cracked
stego_v3_be.jph : negative                    not recognised at all
cover_clean.jph : negative                    correct negative control
```

The reference implementation accepts the little-endian container and rejects the
big-endian one outright. It also labels the version itself, independently
confirming the v3 classification. Build `h3xx/jphs` with `-DBF_LE` or its output
is unreadable by every other jphide tool.

### `jpseek.c` does not compile on Debian 12 / Kali

`open(seekfilename, O_WRONLY|O_TRUNC|O_CREAT)` omits the mode argument; with
`_FORTIFY_SOURCE` active under `-O2`, glibc raises `__open_missing_mode` as a
hard error.

### The stock Makefile cannot link, and the resulting binary aborts at runtime

`LDFLAGS` is placed before the object files, which GNU ld ignores. Once the link
order is fixed, `-I./jpeg-8a` combined with `-ljpeg` (libjpeg-turbo on Debian)
gives `JPEG parameter struct mismatch: library thinks size is 656, caller
expects 712`.

### `stegdetect` needs `-fcommon` on x86-64 and its jphide verdict is unstable

Without it the link fails on `multiple definition of 'progname'`. Once built,
the clean cover image in `fixtures/` is reported as `f5[1.69](***)` — a false
positive. `stego_v3_be.jpg` is flagged `jphide(*)`, while `stego_v3_le.jpg` —
same tool, same payload, same cover — is missed at default sensitivity and only
appears at `-s 3`. The detector is a chi-squared test with fixed thresholds, and
it returns silently when the image is too small.

### jphide v5 identification is verified byte-exact against a real JPHSWIN 0.5 sample

The kit ships `fixtures/stego_v5_real.jpg`, made by JPHS 0.5 on Windows
with passphrase `jeremy23`. `jphoracle` classifies it as `jphide v5 /
little-endian` and reads its payload length as 105 bytes; Windows
`stegbreak.exe` independently reports `jphide[v5](jeremy23)` on the same file.
The v5 header logic — key = `iv[0..5]||passphrase`, two-block header, the
redundant length field and both IV cross-checks — matches the reference
implementation exactly. The four v5 gates in `selftest.sh` assert this against
the real sample.

### v5 payload extraction is fully solved and native on Linux

The transform was
recovered from the `jpseek.exe` decompile and verified byte-exact against eight
known-plaintext samples (seven controlled in `fixtures/v5_samples/`, plus the
real `jeremy23` sample). The v5 payload is:

1. a bit-embedded byte stream, identical to v3's inner loop (Blowfish keystream
   selects DCT coefficients, each data bit XORed with keystream 1);
2. a 16-byte header carrying **two** lengths — a compressed length (block 0) and
   an uncompressed length (block 1). If the uncompressed length is nonzero the
   payload is LZO1X-compressed and is decompressed; if zero it is stored raw.
   The compressor is LZO 1.01 / minilzo (confirmed from the binary's version
   string); the LZO1X format is version-stable, so current minilzo reads it.
3. governed by a v5-only tail flag `hdr[3] & 1` that, when set, consumes one
   extra keystream-2 bit per accepted coefficient. This single bit is what makes
   v5 desync from v3 mid-payload, and is why the format could not be recovered
   from input/output pairs alone — it is invisible outside the header ciphertext.

`jpseek5` implements the whole path and extracts v5 payloads on Kali without
Wine. `v5-findings.md` records the derivation.

### Dictionary attack is included: `jpcrack`

It decodes the cover once, then
tries each wordlist candidate against both the v3 and v5 header checks — the same
validation `stegbreak` uses — and reports the version and passphrase on a hit.
With `-o` it chains straight into `jpseek5` and writes the extracted payload, so
a single command goes from an unknown-passphrase container to the plaintext:

```sh
./jpcrack -o out.bin stego.jpg wordlist.txt
```

`-t N` sets the thread count (default: all cores). Like `stegbreak`, `jpcrack`
mangles each wordlist entry with JtR-style rules before testing — capitalisation,
appended and prepended digits, common suffixes, leetspeak, reverse, duplicate —
so a base word like `jeremy` also tries `Jeremy`, `jeremy1`, `jeremy23`, `j3r3my`
and so on. This reproduces stegbreak results such as `kaosmon` cracking as
`Kaosmon0`. Pass `-n` to disable mangling and test words verbatim. Sending SIGINT
once (Ctrl+C) prints a progress line — candidates tried, rate, and the current
candidate — exactly like stegbreak.

The per-candidate cost is dominated by the Blowfish key schedule (~30k/s per
core), which is the throughput ceiling; `jpcrack` parallelises across cores to
raise it. This is a weak-passphrase attack, exactly like `stegbreak`: it recovers
dictionary and short passphrases, and cannot touch a strong random one — jphide's
Blowfish has no exploitable weakness, so passphrase strength is the only attack
surface. Unlike `stegbreak`, which only confirms a passphrase, `jpcrack -o` also
writes out the payload. The v5 match uses the full five-layer `break_jphide_v5`
check (length-fits-image, two IV comparisons against the decrypted blocks, a
block cross-check, and the redundant-length range), so the false-positive rate is
about 2^-64 — a wrong passphrase does not produce a spurious hit even across tens
of millions of candidates.

### Kali does not ship `stegdetect` or `stegbreak`

Kali bug tracker request
#1688, filed 2014-08-23, was closed 2020-02-11 with resolution `won't fix`, the
administrator citing the unmaintained fork and the dead upstream site. Debian
carried the package until the 0.6-5 QA upload of 2008 — `Architecture: source
i386`, never built for amd64 — and later dropped it. `apt install stegdetect`
fails on both. Building from source is the only route; see
`build-stegdetect-kali.sh`.

### `stegbreak` segfaults when handed a JPEG directly

Reproduced in both 32-bit
and 64-bit builds, across `-t p`, `-t o` and `-t j`. The documented `-c`
conversion path works, but it too exits 139: it writes a complete, valid `.jph`
and then crashes during teardown, so the exit code must be ignored. A 2007
Debian bug reported the same class of crash and it was never fixed.

### GCC 14 and later break the build, and the fix is not a fixed flag list

`jpeg-6b` ships an autoconf 2.12 configure whose compiler probe is
literally `main(){return(0);}`. GCC 14 promoted `implicit-int`,
`implicit-function-declaration`, `int-conversion`, `incompatible-pointer-types`
and `return-mismatch` from warnings to errors, so that probe fails and configure
reports `C compiler cannot create executables`, which the parent reports as
`./configure failed for jpeg-6b`. Demoting them with `-Wno-error=` fixes the
whole chain, and the strict-mode binaries still crack the fixtures correctly.
But the flag names are not portable: GCC 13 rejects `-Wno-error=return-mismatch`
with `no option '-Wreturn-mismatch'`, while GCC 14+ needs it. So
`build-stegdetect-kali.sh` probes each flag with a test compile and keeps only
what the local compiler accepts.

### GCC 15 breaks it again, for a different reason

GCC 15 changed the default
from `gnu17` to `gnu23`, and C23 made `true`, `false` and `bool` keywords.
`stegdetect.c` line 765 declares `float f, f2, sum, false;`, so the file stops
being valid C and the build dies with `expected identifier or '(' before
'false'`. `-std=gnu17` fixes it. This is the only collision in the tree:
`rules.c` defines a macro whose parameters are named `true` and `false`, but
macro parameters are preprocessor identifiers and C23 still accepts them, and
`bf.c`, `jphide.c`, `jpseek.c` and `jphoracle.c` are all clean under C23. The
script probes for this too, compiling `float false;` and adding `-std` only when
the default cannot take it. It also preflights the 32-bit compiler before
configuring, since a `gcc-multilib` that does not match the default `gcc`
produces the same misleading "cannot create executables" message from a
completely different cause.

### `stegdetect` never extracts anything

It detects and identifies the
embedding system. `stegbreak` recovers a passphrase but does not write out the
payload. Extraction is `jpseek`'s job only.

### Windows text-mode damage is real but probably not the primary cause here

`jphide.c` opens the JPEG with `fopen(...,"r")` / `fopen(...,"w")` and the
payload with `open(..., O_RDONLY)` — none request binary mode. Simulating the
Windows CRT on a healthy 61,300-byte container inserts 97 CR bytes; the result
still opens as a valid 640x480 image, but `stegdetect` reports `negative` and the
header is gone. That matches the reported symptom exactly. However, the same
container has a `0x1A` byte at offset 731, which a text-mode read treats as EOF
— so if the Windows side really used text mode for the JPEG, Windows-side
`jpseek` would break too. The payload path, which never gets `O_BINARY`, remains
the more plausible place for this defect to bite.

---

## 3. Contents

| Path | Purpose |
|---|---|
| `jphoracle.c` | Container classifier: v3/v5 and big/little-endian |
| `crlf_check.py` | Text-mode damage detector and repairer (containers) |
| `dict_hygiene.py` | Wordlist hygiene checker: BOM, UTF-16, CRLF, trailing spaces |
| `rule_expand.py` | Rule-expansion calculator (mirrors `jpcrack`'s rules) |
| `GETTING_STARTED.md` / `_zh.md` | Newcomer walkthrough (EN/ZH lockstep) |
| `USER_MANUAL.md` / `_zh.md` | Full reference (EN/ZH lockstep) |
| `jphs-portability.patch` | Fixes for `h3xx/jphs` on modern Linux |
| `build-stegdetect-kali.sh` | Source build of stegdetect/stegbreak, with toolchain probing |
| `jpseek5.c` | native v3/v5 payload extractor (Blowfish + LZO1X) — decompile-verified |
| `jpcrack.c` | v3/v5 dictionary attack, multi-threaded; `-o` extracts on a hit |
| `v5diff.c` | v5 payload analyzer: dumps raw bits in all interpretations |
| `v5-findings.md` | how the v5 format works and how it was recovered |
| `selftest.sh` | 29-gate reproducible verification suite |
| `build.sh` | One-line build for `jphoracle` |
| `bf.c`, `bf.h`, `bf_config.h`, `ltable.h` | Support files (see section 9) |
| `fixtures/` | Verified test corpus used by `selftest.sh` |

---

## 4. Build

```sh
apt install build-essential libjpeg-dev
./build.sh
```

`bf_config.h` here deliberately defines nothing, so both `B_Blowfish_*` and
`L_Blowfish_*` entry points stay available and the oracle can test each in turn.

---

## 5. Usage

Classify a container:

```sh
./jphoracle windows_stego.jpg 'your passphrase'
```

A matching line names the version and the byte order and prints the recovered
payload length. No matching line means no combination validated — either the
passphrase is wrong, the file carries nothing, or the container is damaged.

Check for text-mode damage:

```sh
python3 crlf_check.py suspect.jpg [original_cover.jpg]
python3 crlf_check.py --repair suspect.jpg
```

Repair rewrites `0x0D 0x0A` back to `0x0A`. Any truncation caused by a `0x1A`
byte on the Windows side is not recoverable this way.

---

## 6. Gate suite

```sh
./selftest.sh
```

**Twenty-nine gates, all green as shipped**, covering four areas:

- **Identification** (G1–G9): correct v3 big/little-endian classification, correct v3 payload length (860 B), the real v5 sample classified as v5 little-endian with its length read (105 B), no match on the clean cover or the real v5 cover, and no match on a wrong passphrase.
- **v5 extraction** (G10–G17): the seven controlled samples in `fixtures/v5_samples/` plus the real `jeremy23` sample, each extracted to exact plaintext.
- **Dictionary attack** (G18–G24): `jpcrack` finding the passphrase on v3 and v5 containers, end-to-end plaintext via `-o`, a mangled base word cracking through the rule engine, `-n` verbatim mode (base word alone does not crack with rules off), and 50k wrong candidates producing no false positive.
- **Text-mode damage** (G25–G29): CRLF damage flagged, a healthy file not flagged, a damaged file invisible to the oracle before repair, repair byte-identical to the pre-damage container, and the repaired container readable again.

---

## 7. The portability patch

```sh
git clone https://github.com/h3xx/jphs
cd jphs && patch -p1 -i ../jphs-portability.patch
```

It supplies the missing `open()` mode argument, switches every JPEG and payload
stream to binary mode via an `O_BINARY` shim that is a no-op on Linux, moves the
libraries after the objects in the link line, and promotes the endianness choice
to a `BF_ENDIAN` variable defaulting to `-DBF_LE`.

Verified: applies cleanly at `-p1`, the patched tree compiles including
`jpseek.c`, and the patched `jpseek` recovers the fixture payload byte for byte.

---

## 8. What this kit does not solve

The patch does not make `h3xx/jphs` read v5 containers. It is a 0.3 codebase and
stays one. To open a Windows-made container on Kali there are two paths: run
`jphs05`'s `jpseek.exe` under Wine, or write a v5 extractor. For the second
path, `try_v5()` in `jphoracle.c` already reproduces the full v5 header logic —
key derivation, both blocks, the redundant length field and both IV checks — so
the remaining work is the payload loop, not the format.

---

## 9. Provenance and licensing

`bf.c` and `bf.h` are Olaf Titz's public-domain Blowfish. `ltable.h` is marked
public domain and is byte-identical to `jphide_table.c` in `stegdetect`.
`jphoracle.c` is an independent reimplementation of the header validation in
`break_jphide.c` by Niels Provos, which is BSD-licensed; the algorithm is
credited to him. `jphs-portability.patch` targets `h3xx/jphs`, which is GPL.
Fixtures were generated locally and contain no third-party imagery.

---

<div align="center">
<sub>
📘 <a href="GETTING_STARTED.md">Getting started</a> ·
📖 <a href="USER_MANUAL.md">User manual</a> ·
🔬 <a href="v5-findings.md">v5 derivation</a> ·
⬇️ <a href="https://github.com/adomore/jphide-crossplat-kit/releases/latest">Download prebuilt bundle</a> ·
⚖️ <a href="LICENSE">GPL-3.0</a>
</sub>
<br><br>
<sub>Author: Anonymous · Version 2.3 · For security research, digital forensics, and CTF use only</sub>
</div>
