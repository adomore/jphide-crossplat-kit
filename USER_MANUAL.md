# jphide-crossplat-kit — User Manual

Author: Anonymous
Version: 2.3

The mirrored Chinese edition of this document is `USER_MANUAL_zh.md`. The two
files are maintained in lockstep, section by section. If you are new to the kit,
start with `GETTING_STARTED.md`; for the cross-platform findings that motivated
it, see `README_en.md`.

---

## 1. Overview and scope

jphide embeds a payload in the quantised DCT coefficients of a JPEG, selecting
coefficients with a Blowfish keystream driven by a passphrase. Two mutually
incompatible container versions exist:

- **v3** — the `h3xx/jphs` lineage, `HS_MINOR_VERSION 3`, common on Linux.
- **v5** — the `JPHSWIN` / `jphs05` package, JPHS 0.5, common on Windows.

They differ in key derivation, header layout and payload framing (Section 3), so
one version's reader cannot recover even the length field of the other. This kit
provides native Linux tooling to identify, crack and extract both, plus utilities
to diagnose the two failure modes that make a Windows-made container appear empty
on Linux: text-mode byte damage and wordlist encoding faults.

**What the kit does not do.** It is a weak-passphrase attack, exactly like
`stegbreak`: it recovers dictionary and short passphrases and cannot touch a
strong random one. jphide's Blowfish has no exploitable weakness; passphrase
strength is the only attack surface. The kit also does not port `h3xx/jphs`
itself to read v5 — `jpseek5` is a separate native reader that does.

---

## 2. Installation and build

### 2.1 Dependencies

```
sudo apt install build-essential libjpeg-dev
```

Python 3 (already on Kali) is required for the three `.py` tools. Building
`stegdetect`/`stegbreak` additionally needs a 32-bit toolchain (Section 2.3).

### 2.2 Building the C tools

```
./build.sh
```

produces four binaries in the working directory:

| Binary | Role |
|---|---|
| `jphoracle` | classify a container: v3/v5 and big/little-endian |
| `jpseek5` | extract a v3/v5 payload (Blowfish + LZO1X) |
| `jpcrack` | multi-threaded v3/v5 dictionary attack; `-o` extracts on a hit |
| `v5diff` | dump a v5 payload's raw bits in every interpretation |

`build.sh` compiles `bf.c` and `minilzo.c` to objects first, then each tool.
`bf_config.h` deliberately defines nothing so that both the big-endian
(`B_Blowfish_*`) and little-endian (`L_Blowfish_*`) entry points stay available;
`jphoracle` uses this to test each byte order in turn.

### 2.3 Building stegdetect / stegbreak

Kali and current Debian do not package `stegdetect`/`stegbreak`; building from
source is the only route. The kit wraps this:

```
sudo apt install gcc-multilib libc6-dev-i386 git
sh build-stegdetect-kali.sh [target-dir]
```

The sources date from 1996–2001 and do not build cleanly on a modern toolchain.
The script does not hardcode flags — it probes the local compiler and keeps only
what works, because the required flags differ by GCC version:

- A **32-bit build is mandatory.** The x86-64 build links and runs but its
  chi-squared values drift and `stegbreak` corrupts memory; the script preflights
  a working `gcc -m32` and aborts with guidance if none is found.
- **GCC 14+** promoted several legacy-C warnings to errors, which breaks the
  bundled `jpeg-6b` autoconf probe; the script demotes them with probed
  `-Wno-error=` flags.
- **GCC 15** defaults to `gnu23`, where `true`/`false`/`bool` are keywords and
  `stegdetect.c` stops being valid C; the script adds `-std=gnu17` only if the
  default cannot compile a `float false;` probe.
- **`rules.ini`** is required by `stegbreak` and was dropped upstream; the script
  supplies a minimal fallback if none is present.

Two runtime caveats, both documented and both harmless if handled:

- `stegbreak` **segfaults when handed a `.jpg` directly.** Use the `-c`
  conversion path, which writes a valid `.jph` and then exits 139 during
  teardown — ignore the exit code and use the file (append `|| true` in scripts).
- `stegdetect` **never extracts**; it only detects and identifies. Its jphide
  verdict is a chi-squared test with fixed thresholds: it can false-positive on
  clean images and miss real ones at default sensitivity — raise it with `-s`.

---

## 3. The jphide format

### 3.1 v3 (JPHS 0.3 / `h3xx/jphs`)

- **Key:** the passphrase alone.
- **Header:** one 8-byte Blowfish block. After decryption, bytes 0–2 are the
  payload length; bytes 3–7 must equal bytes 3–7 of the (encrypted, rotated) IV.
- **Payload:** a bit stream embedded directly in selected DCT coefficients; each
  data bit is XORed with one keystream bit. Stored uncompressed.

### 3.2 v5 (JPHS 0.5 / `JPHSWIN`)

- **Key:** `iv[0..5] || passphrase`, where `iv` is derived from the first DCT
  coefficients of the cover.
- **Header:** two 8-byte blocks. Block 0 carries a compressed length and the
  first IV check; block 1 carries an uncompressed length and a second IV check,
  plus a cross-check that block 1 bytes 1–2 equal block 0 bytes 1–2. `hdr[3]` must
  be ≤ 3. This redundancy is what gives the v5 match its ~2⁻⁶⁴ false-positive
  rate.
- **Payload:** the same bit-embedding inner loop as v3, but governed by a v5-only
  tail flag `hdr[3] & 1`: when set, one extra keystream-2 bit is consumed per
  accepted coefficient, which is what desynchronises v5 from v3 mid-payload. If
  the uncompressed length is nonzero the payload is **LZO1X-compressed**
  (LZO 1.01 / minilzo; the format is version-stable, so current minilzo reads it)
  and is decompressed; if zero it is stored raw.

### 3.3 Byte order

Blowfish here has two data byte orders. `h3xx/jphs` defaults to big-endian, which
is wrong: the reference `stegbreak` accepts only the little-endian container and
rejects the big-endian one outright (see `README_en.md` §2). All tools in this kit
operate little-endian (`L_Blowfish_*`) for the actual checks; `jphoracle` is the
exception, testing both so it can report which one a file uses.

---

## 4. Tool reference

### 4.1 jphoracle

```
./jphoracle file.jpg passphrase
```

Decodes the JPEG once and tries the passphrase against the full v3 and v5 header
logic in both byte orders. A matching line names the version and byte order and
prints the recovered payload length; no matching line means nothing validated —
wrong passphrase, empty file, or damaged container. Requires a 3-component
(colour) JPEG. This is the diagnostic front end: use it when you already know or
suspect a passphrase and want the container classified.

### 4.2 jpcrack

```
jpcrack [-t N] [-o out.bin] [-n] [-p SEC] stego.jpg wordlist
```

The dictionary attack. It decodes the cover once, caches the coefficient walk,
then feeds each wordlist entry — expanded by the rule engine (Section 5) — to the
same v3 and v5 header checks `jphoracle` uses, across `N` threads. On the first
hit it prints the version and passphrase and stops.

**Options**

- `-t N` — thread count; default is all online cores.
- `-o FILE` — on a hit, extract the payload to `FILE` by delegating to `jpseek5`,
  giving a single unknown-passphrase-to-plaintext command.
- `-n` — disable mangling; test each word verbatim (base word only, no rules).
- `-p SEC` — auto-print a progress line every `SEC` seconds (0 = only on SIGINT).

**Validation.** v3: key = passphrase, single block, length-fits-image and the
`hdr[3..7] == iv[3..7]` tail check. v5: the full five-layer `break_jphide_v5`
check — `hdr[3] ≤ 3`, length fits the image, `iv[5..7]` vs decrypted block 0, the
block-1 cross-check, the redundant-length range, and `iv2[4..7]` vs decrypted
block 1. The combined v5 false-positive rate is about 2⁻⁶⁴, so a wrong passphrase
does not produce a spurious hit even across tens of millions of candidates.

**Progress and the denominator (v2.3).** Before the workers start, `jpcrack`
scans the wordlist once with no cryptography and sums, per base word, the exact
number of candidates the rules will emit for it (`count_variants`). That sum is
the denominator printed as `N candidates to test` and used for the percentage and
ETA. This scan is fast (about a second on rockyou) because it does no Blowfish.
A useful invariant follows: on an exhausted run the tested-candidate counter
equals that denominator exactly, because every candidate the generator emits is
counted once — so `count_variants` and the rule engine are proven to agree at
runtime, and a divergence would mean the two drifted out of sync.

**Progress line format**

```
Status: 42.087%  437408912/1039482318  180431.5 c/s  ETA 0:53:41: sunshine23
```

percent · done/total · rate · ETA (from the current rate) · current candidate.
Printed on each Ctrl+C, and automatically every `SEC` seconds under `-p`.

**Throughput.** The per-candidate cost is dominated by the Blowfish key schedule,
about 30k candidates/sec/core; the tool parallelises across cores to raise the
ceiling. See Section 9.

### 4.3 jpseek5

```
./jpseek5 stego.jpg passphrase outfile
```

The native extractor. Given the correct passphrase, it recovers the payload for
both versions: v3 is written uncompressed; v5 is LZO1X-decompressed when the
header's uncompressed length is nonzero, otherwise written raw. It is the
single-source-of-truth extraction path that `jpcrack -o` calls. The v5 transform
was recovered from the `jpseek.exe` decompile and verified byte-exact against
eight known-plaintext samples; `v5-findings.md` records the derivation.

### 4.4 v5diff

```
./v5diff stego.jpg passphrase [plaintext_file]
```

A v5 payload analyser: it dumps the raw embedded bits under every candidate
interpretation, optionally diffing against a known plaintext file. This is an
investigation and format-verification tool, not part of the normal
identify → crack → extract path.

### 4.5 stegdetect / stegbreak (built separately)

Once built (Section 2.3):

- `stegdetect [-s SENS] -t p file.jpg` — detect and identify the embedding
  system. Raise `-s` if a real embedding is missed at default sensitivity.
- `stegbreak -r rules.ini -f wordlist -t p file.jph` — recover a passphrase
  (convert a `.jpg` to `.jph` first with `-c`; ignore the exit-139 on teardown).

**stegbreak's progress percentage, for contrast.** `stegbreak` is *rule-major*:
its outer loop is the rule set and, for each rule, it rewinds and streams the
whole wordlist. Its status percentage (from `stegbreak.c`) is
`(rule_number * 100 + part_file) / rule_count`, where `rule_count` is the total
number of expanded wordlist rules and `part_file` is the byte-offset percentage
through the wordlist for the *current* rule pass. So the denominator is the rule
count, not the total candidate count, and a mangled variant can appear at a high
percentage simply because it belongs to a late rule pass. `jpcrack` is the
opposite — *word-major*, one pass over the wordlist with all rules applied per
word — so it cannot use that formula; its percentage is candidate-count based
(Section 4.2).

### 4.6 dict_hygiene.py

```
python3 dict_hygiene.py FILE [FILE ...]
python3 dict_hygiene.py --fix FILE           # write FILE.clean
python3 dict_hygiene.py --quiet FILE ...     # print only files with issues
python3 dict_hygiene.py --fix --strip-trailing FILE
```

Screens a wordlist, byte by byte, for the encoding faults that silently break a
byte-oriented cracker. Findings are graded:

- **FAIL** (breaks candidates): a UTF-8/16/32 **BOM** (a leading BOM corrupts the
  first candidate); a **UTF-16/32** encoding, detected by the NUL-per-character
  pattern with or without a BOM (`fgets`/`strlen` truncate at the first NUL, so
  the whole list is unreadable); **mixed** CRLF+LF (a Unix file with lines
  appended by a Windows editor, where only the appended lines carry a hidden
  `\r`).
- **WARN** (suspicious): whole-file **CRLF** (jpcrack strips the trailing `\r`,
  but hashcat/john may not); **lone CR**; lines ending in **space/tab**
  (`pw ` ≠ `pw`, but a trailing space may be intentional, so it is flagged, not
  removed); control bytes inside a line.
- **INFO**: no newline after the last line.

Exit status is 0 only if every file is clean, so it can gate a pipeline. `--fix`
writes a normalised copy (UTF-16 → UTF-8, BOM stripped, CRLF/CR → LF); it does
**not** touch trailing whitespace unless `--strip-trailing` is given, because a
trailing space can be part of a real passphrase.

### 4.7 rule_expand.py

```
python3 rule_expand.py WORD [TARGET_VARIANT]
python3 rule_expand.py --selftest
```

An exact replica of `jpcrack`'s `rules_apply`, for reasoning about the rule
engine. It reports how many candidates a base word expands to and, optionally, at
what position a given mangled variant is generated. It carries two independent
code paths — a generator and a closed-form counter — that are cross-checked, so
its numbers match `jpcrack`'s own `count_variants`. Use it to predict whether the
rules will reach a passphrase form, or to understand a total candidate count
(Section 5).

### 4.8 crlf_check.py

```
python3 crlf_check.py suspect.jpg [original_cover.jpg]
python3 crlf_check.py --repair suspect.jpg
```

Decides whether a JPEG was damaged by Windows text-mode I/O — where the CRT
inserts `0x0D` before every `0x0A`, collapses `0x0D 0x0A` on read, and treats
`0x1A` as EOF. Such a file still decodes as an image but its DCT coefficients are
shifted, so nothing is found on Linux. `--repair` rewrites `0x0D 0x0A` back to
`0x0A`; truncation from a `0x1A` byte is not recoverable this way. Note this is
about **containers** (JPEGs); `dict_hygiene.py` is the equivalent for
**wordlists**.

---

## 5. The rule engine and candidate counting

Before testing, `jpcrack` mangles every base word with John-the-Ripper-style
rules, in this fixed order (each emits a candidate; conditions in parentheses):

1. the word as-is;
2. capitalise the first letter (only if it is lowercase);
3. uppercase all; 4. lowercase all;
5. append each digit 0–9, to the word and to its capitalised form (the second
   only if the first letter is lowercase) — up to 20;
6. append 19 common suffixes (`23 1 12 123 1234 12345 ! @ # 01 007 69 111
   2020 2021 2022 2023 2024 00`), likewise doubled — up to 38;
7. prepend each digit 0–9 — 10;
8. reverse; 9. duplicate (for any word short enough to fit the buffer);
10. leetspeak single-character swaps `a→@ a→4 e→3 i→1 o→0 s→$ s→5 t→7`, each
    emitted only if that letter is present.

The count per word is therefore **variable**, because most rules are conditional:

- a lowercase-initial word: **74 + leet(0–8)** candidates;
- a digit- or uppercase-initial word: **44 + leet** (the capitalise and the
  capitalised-append variants are skipped);
- worked example: `smalvilesoker` (lowercase, contains a/e/i/o/s, not t) expands
  to exactly **81** candidates, and `6smalvilesoker` — the prepend-`6` variant —
  is the **69th** in generation order.

There is no fixed multiplier. Over a real run of rockyou, the average worked out
to about **71.5 candidates per base word**: lowercase words (74–82) dominate, and
a large minority of digit-leading passwords (≈44) pull the mean down. `-n`
disables all of this — one candidate per word. `rule_expand.py` computes any of
these figures; `python3 rule_expand.py smalvilesoker` reproduces the 81 / #69
example.

---

## 6. Wordlist hygiene and cross-platform faults

A wordlist authored on Windows can silently defeat a crack. The mechanisms, and
whether `jpcrack` specifically is affected:

- **Trailing CR (CRLF).** `jpcrack`'s reader strips a trailing `\r` and `\n`, so
  a CRLF wordlist does **not** miss a password on `jpcrack`. Other tools (hashcat,
  john) may not strip it, in which case every candidate silently carries a hidden
  `\r`.
- **BOM.** A leading UTF-8 BOM (`EF BB BF`) becomes part of the first candidate,
  which then fails; `jpcrack` does not strip a leading BOM. It only affects the
  first line, so appending at the end is safe, but re-saving a whole file with a
  BOM breaks its original first entry.
- **UTF-16 / "Unicode" save.** Two bytes per character with interleaved NULs;
  `fgets`/`strlen` truncate at the first NUL and the list is effectively dead —
  this breaks `jpcrack` too. Never save a wordlist as UTF-16.
- **Trailing spaces/tabs.** Not stripped by `jpcrack`; `pw ` ≠ `pw`. Manual edits
  introduce these easily.
- **Encoding mismatch for non-ASCII passphrases.** `jpcrack` matches bytes
  literally, so a passphrase with accented or CJK characters must be encoded in
  the wordlist exactly as it was embedded. Pure ASCII is unaffected.

**Best practice.** Add candidates from the Linux side —
`printf '%s\n' 'candidate' >> list.txt` — rather than round-tripping through a
Windows editor; if you must edit on Windows, save as UTF-8 (no BOM) with LF line
endings. Screen any transferred list with `dict_hygiene.py` (Section 4.6); repair
with its `--fix`, or with `dos2unix` for CRLF plus an explicit BOM strip.

---

## 7. The self-test suite

```
./selftest.sh
```

29 gates, all green as shipped; each asserts one factual claim. They cover
`jphoracle` v3 big/little-endian classification and payload length, the negative
controls (clean cover and wrong passphrase), the real JPHSWIN v5 sample
(classification and 105-byte length, plus its negative controls), native v5
extraction against the controlled samples, `jpcrack` finding both v3 and v5
passphrases, the rule engine reaching a mangled passphrase (`jeremy` →
`jeremy23`), false-positive resistance (50k wrong candidates yield no match under
the full five-layer v5 check), and the `crlf_check.py` detect-and-repair path
(damage flagged, healthy file not flagged, damaged file invisible to `jphoracle`,
repair byte-identical, repaired file readable). The run ends with
`ALL 29 GATES GREEN`.

---

## 8. Troubleshooting

- **`./configure failed for jpeg-6b` / `C compiler cannot create executables`**
  when building stegdetect — a GCC 14/15 or multilib-mismatch problem; run
  `build-stegdetect-kali.sh`, which probes and demotes the offending flags and
  preflights the 32-bit compiler. See Section 2.3.
- **`stegbreak` exits 139** — expected on the `-c` conversion path; the `.jph` is
  written correctly before the teardown crash. Ignore it.
- **`JPEG parameter struct mismatch: library thinks size is 656, caller expects
  712`** — an `h3xx/jphs` build mixing its bundled `jpeg-8a` headers with the
  system `libjpeg`; the portability patch and this kit's own `build.sh` avoid it.
- **`not 3-component` / `not a 3-component JPEG`** — the tools require a colour
  (3-component) JPEG; a greyscale image is unsupported.
- **`no match` from `jpcrack`** — see `GETTING_STARTED.md` §8: passphrase not in
  the list, a strong passphrase, or a damaged/non-v3-v5 container.
- **A wordlist that "should" contain the passphrase still fails** — screen it with
  `dict_hygiene.py`; a BOM, UTF-16 save or trailing space is the usual cause.

---

## 9. Performance and limitations

Throughput is bounded by Blowfish's key schedule, about 30k candidates/sec/core;
`jpcrack` scales across cores, so wall time is roughly
`total_candidates / (30k × cores)`. With the rule engine adding ~71.5× per base
word (Section 5), a 14-million-line wordlist is on the order of a billion
candidates — hours on a typical multi-core machine, which is why the percentage
and ETA (v2.3) exist. `-n` cuts that to one candidate per word when you already
have exact passphrases.

The hard limit is passphrase strength. This is a weak-passphrase attack: it
recovers dictionary and short passphrases and cannot recover a strong random one.
jphide's Blowfish has no exploitable weakness, so there is no shortcut around the
key schedule and no attack surface other than the passphrase itself.

---

## 10. Provenance and licensing

`bf.c` and `bf.h` are Olaf Titz's public-domain Blowfish. `ltable.h` is marked
public domain and is byte-identical to `jphide_table.c` in `stegdetect`. The
header-validation logic in `jphoracle`, `jpcrack`, `jpseek5` and `v5diff` is an
independent reimplementation of `break_jphide.c` by Niels Provos (BSD-licensed);
the algorithm is credited to him. `minilzo` is Markus Oberhumer's LZO under the
GPL. `jphs-portability.patch` targets `h3xx/jphs`, which is GPL. The Python
tools (`dict_hygiene.py`, `rule_expand.py`, `crlf_check.py`) and all fixtures were
produced locally by Anonymous and contain no third-party imagery.
