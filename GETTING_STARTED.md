# jphide-crossplat-kit — Getting Started

Author: Anonymous
Version: 2.3

The mirrored Chinese edition of this document is `GETTING_STARTED_zh.md`. The two
files are maintained in lockstep, section by section. For the full reference see
`USER_MANUAL.md`; for the diagnostic findings behind the kit see `README_en.md`.

This guide takes a newcomer from a fresh clone to a first successful crack in a
few minutes, using only the test files that ship with the kit. It assumes no
prior knowledge of jphide.

---

## 1. What this kit does

jphide hides a payload inside the DCT coefficients of a JPEG. Two incompatible
versions exist in the wild: **v3** (the `h3xx/jphs` lineage on Linux) and **v5**
(the `JPHSWIN` package on Windows). They differ in key derivation, header layout
and payload framing, so a tool that reads one cannot read the other.

This kit lets you, on Linux, without Wine:

- **identify** which version a JPEG carries and in which byte order (`jphoracle`),
- **crack** a weak/dictionary passphrase against both v3 and v5 (`jpcrack`),
- **extract** the recovered payload, including LZO-compressed v5 (`jpseek5`),
- **check** a JPEG for Windows text-mode damage (`crlf_check.py`),
- **check** a wordlist for the encoding faults that silently break a crack
  (`dict_hygiene.py`).

It is a weak-passphrase toolkit: it recovers dictionary and short passphrases. A
strong random passphrase is out of reach — jphide's Blowfish has no exploitable
weakness, so passphrase strength is the only attack surface.

---

## 2. Requirements

A Debian 12 / Kali (or similar) system with a C toolchain and libjpeg headers:

```
sudo apt install build-essential libjpeg-dev
```

Python 3 is needed for `dict_hygiene.py`, `rule_expand.py` and `crlf_check.py`;
it is already present on Kali. Building `stegdetect`/`stegbreak` themselves is
optional and needs a 32-bit toolchain — see `USER_MANUAL.md`, it is not required
for anything below.

---

## 3. Build

```
./build.sh
```

This compiles four tools into the current directory:

```
built: ./jphoracle    (v3/v5 + endianness identifier)
built: ./jpseek5      (v3/v5 payload extractor, native)
built: ./jpcrack      (v3/v5 dictionary attack, multi-threaded)
built: ./v5diff       (v5 payload analysis tool)
```

To confirm everything is wired correctly, run the gate suite — 29 checks, all
green as shipped:

```
./selftest.sh
```

---

## 4. A five-minute walkthrough

The kit ships a real JPHSWIN v5 sample, `fixtures/stego_v5_real.jpg`, made on
Windows with the passphrase `jeremy23`. We will pretend we do not know that
passphrase and recover it.

### 4.1 Identify the container

If you already know the passphrase, `jphoracle` tells you the version, byte order
and payload length:

```
./jphoracle fixtures/stego_v5_real.jpg jeremy23
```

It reports `jphide v5 / little-endian` and a payload length of 105 bytes. A run
with a wrong passphrase prints no matching line — that is the expected "nothing
validated" result, not an error.

### 4.2 Crack the passphrase

In practice you do not have the passphrase; that is what `jpcrack` is for. Make a
small wordlist and drop the answer somewhere inside it:

```
printf 'letmein\nhunter2\njeremy23\npassword\n' > demo.txt
./jpcrack fixtures/stego_v5_real.jpg demo.txt
```

Expected result:

```
jpcrack: N threads, cached 300000 coefficients, 305 candidates to test
FOUND: jphide[v5](jeremy23)  [3 candidates, 0.10s, ... c/s]
```

`jpcrack` tests each word against both the v3 and v5 header checks and stops on
the first hit. Even a base word of just `jeremy` would have worked here: before
testing, `jpcrack` applies John-the-Ripper-style rules to every entry —
capitalisation, appended/prepended digits, common suffixes, leetspeak, reverse,
duplicate — so `jeremy` also produces `jeremy23` as one of its variants.

### 4.3 Crack and extract in one command

Add `-o` and `jpcrack` chains straight into `jpseek5` on a hit, writing the
decrypted (and, for v5, LZO-decompressed) payload:

```
./jpcrack -o out.bin fixtures/stego_v5_real.jpg demo.txt
cat out.bin
```

You now have the plaintext the container was hiding, recovered end-to-end on
Linux from an unknown passphrase.

---

## 5. Reading jpcrack's output

The startup line states the thread count and, after a one-pass scan of the
wordlist, the exact number of candidates it will test (base words times the rules
applied to each):

```
jpcrack: 8 threads, cached 300000 coefficients, 1039482318 candidates to test
```

Press Ctrl+C once at any time, or pass `-p SEC`, to print a progress line:

```
Status: 42.087%  437408912/1039482318  180431.5 c/s  ETA 0:53:41: sunshine23
```

That is percent complete, candidates done / total, current rate, an ETA computed
from the rate, and the candidate in flight. On a hit you get the `FOUND` line
above; if the wordlist is exhausted with no hit:

```
exhausted 1039482318 candidates in 5761.44s (180431 c/s), no match
```

---

## 6. The flags you'll actually use

- `-t N` — number of threads. Default is every core. Throughput is bounded by
  Blowfish's key schedule (~30k candidates/sec/core), so more cores is faster.
- `-o FILE` — on a hit, extract the payload to `FILE` (chains `jpseek5`).
- `-n` — no mangling: test each word verbatim, skipping the rules. Use this when
  your wordlist already contains exact passphrases, or to test one specific
  string.
- `-p SEC` — auto-print a progress line every `SEC` seconds. Without it, progress
  prints only when you press Ctrl+C.

Full synopsis:

```
jpcrack [-t N] [-o out.bin] [-n] [-p SEC] stego.jpg wordlist
```

---

## 7. Check your wordlist first

A wordlist edited or created on Windows can silently break a crack: a leading BOM
corrupts the first candidate, a UTF-16 save makes the whole file unreadable to a
byte-oriented tool, and a stray trailing space turns `pw` into `pw ` so it never
matches. Screen a wordlist before a long run:

```
python3 dict_hygiene.py rockyou.txt
```

It reports each fault with a severity (FAIL / WARN / INFO) and exits non-zero if
anything is wrong, so it can gate a script. `--fix` writes a normalised
`rockyou.txt.clean` (UTF-16 → UTF-8, BOM stripped, CRLF → LF). The safest habit
is to add candidates from the Linux side rather than round-tripping through a
Windows editor:

```
printf '%s\n' 'a candidate you think is right' >> rockyou.txt
```

`jpcrack` itself strips a trailing `\r`, so a plain CRLF wordlist will not miss
your password — but other tools (hashcat, john) may not, and BOM/UTF-16/trailing
spaces bite `jpcrack` too. `dict_hygiene.py` catches all of them.

---

## 8. When jpcrack finds nothing

`no match` has three common causes, in order of likelihood:

1. **The passphrase is not in your wordlist (or its rule variants).** Try a
   larger list, or confirm the rules reach the form you expect with
   `python3 rule_expand.py yourword`.
2. **The passphrase is strong.** A random passphrase cannot be recovered by any
   dictionary attack; this is a property of jphide, not a limitation of the tool.
3. **The container is damaged or is not jphide v3/v5.** If the JPEG came from
   Windows and may have passed through a text-mode stream, check it:

   ```
   python3 crlf_check.py suspect.jpg [original_cover.jpg]
   python3 crlf_check.py --repair suspect.jpg
   ```

   Repair rewrites `0x0D 0x0A` back to `0x0A`. Truncation caused by a `0x1A`
   (Ctrl-Z) byte on the Windows side is not recoverable this way.

---

## 9. Next steps

- `USER_MANUAL.md` — the full reference: every tool and flag, the jphide v3/v5
  format, the rule engine and candidate-count arithmetic, the self-test suite,
  troubleshooting, performance and limits.
- `README_en.md` — the verified cross-platform findings the kit was built to prove.
- `v5-findings.md` — how the v5 payload format was recovered from the decompile.
