#!/bin/sh
# selftest.sh - reproducible gate suite for jphide-crossplat-kit.
# Every gate asserts one factual claim made in the README.
# Exit 0 = all green.

set -u
PASS="TestPass123"
FX="fixtures"
FAIL=0
N=0
TMP_EXTRACT=$(mktemp -d)
trap 'rm -rf "$TMP_EXTRACT"' EXIT

green() { N=$((N+1)); printf "  G%-2d %-58s PASS\n" "$N" "$1"; }
red()   { N=$((N+1)); printf "  G%-2d %-58s FAIL\n" "$N" "$1"; FAIL=$((FAIL+1)); }

check() { # <label> <expected-substring> <command...>
    label="$1"; want="$2"; shift 2
    got=$("$@" 2>&1)
    case "$got" in
        *"$want"*) green "$label" ;;
        *)         red   "$label"; printf "        wanted: %s\n        got   : %s\n" "$want" "$(echo "$got" | tr '\n' '|')" ;;
    esac
}

nocheck() { # <label> <forbidden-substring> <command...>
    label="$1"; bad="$2"; shift 2
    got=$("$@" 2>&1)
    case "$got" in
        *"$bad"*) red   "$label"; printf "        must not contain: %s\n" "$bad" ;;
        *)        green "$label" ;;
    esac
}

echo "jphide-crossplat-kit selftest"
echo

if [ ! -x ./jphoracle ]; then
    echo "  ./jphoracle not built - run ./build.sh first" >&2
    exit 2
fi

echo "-- jphoracle: format and endianness discrimination"
check "v3 + big-endian container is classified correctly" \
      "jphide v3  Blowfish=big-endian" \
      ./jphoracle "$FX/stego_v3_be.jpg" "$PASS"

check "v3 + little-endian container is classified correctly" \
      "jphide v3  Blowfish=little-endian" \
      ./jphoracle "$FX/stego_v3_le.jpg" "$PASS"

check "recovered payload length matches the real payload (860 B)" \
      "payload length = 860 bytes" \
      ./jphoracle "$FX/stego_v3_le.jpg" "$PASS"

echo
echo "-- jphoracle: negative controls (no false positives)"
nocheck "clean cover yields no header match" \
        "MATCH" \
        ./jphoracle "$FX/cover_clean.jpg" "$PASS"

nocheck "wrong passphrase yields no header match" \
        "MATCH" \
        ./jphoracle "$FX/stego_v3_le.jpg" "WrongPass999"

echo
echo "-- jphoracle: real JPHSWIN v5 sample (ground truth: passphrase jeremy23)"
check "real v5 stego is classified as v5 little-endian" \
      "jphide v5  Blowfish=little-endian" \
      ./jphoracle "$FX/stego_v5_real.jpg" jeremy23

check "real v5 payload length is read correctly (105 B)" \
      "payload length = 105 bytes" \
      ./jphoracle "$FX/stego_v5_real.jpg" jeremy23

nocheck "real v5 cover (pre-embedding) yields no match" \
        "MATCH" \
        ./jphoracle "$FX/cover_v5_real.jpg" jeremy23

nocheck "real v5 stego with wrong passphrase yields no match" \
        "MATCH" \
        ./jphoracle "$FX/stego_v5_real.jpg" wrongpass

echo
echo "-- jpseek5: native v5 payload extraction (decompile-verified)"
for n in 01 02 03 04 05 06 07; do
    if ./jpseek5 "$FX/v5_samples/s$n.jpg" test "$TMP_EXTRACT/o$n.bin" >/dev/null 2>&1 \
       && cmp -s "$TMP_EXTRACT/o$n.bin" "$FX/v5_samples/p$n.bin"; then
        green "v5 sample s$n extracts to exact plaintext"
    else
        red "v5 sample s$n extracts to exact plaintext"
    fi
done
if ./jpseek5 "$FX/stego_v5_real.jpg" jeremy23 "$TMP_EXTRACT/oreal.bin" >/dev/null 2>&1 \
   && cmp -s "$TMP_EXTRACT/oreal.bin" "$FX/payload_v5_plaintext.txt"; then
    green "real v5 sample (jeremy23) extracts to exact plaintext"
else
    red "real v5 sample (jeremy23) extracts to exact plaintext"
fi

echo
echo "-- jpcrack: dictionary attack (v3 + v5)"
CRACK_WL="$TMP_EXTRACT/wl.txt"
printf 'wrong1\nwrong2\ntest\nTestPass123\n' > "$CRACK_WL"
if ./jpcrack "$FX/v5_samples/s03.jpg" "$CRACK_WL" 2>/dev/null | grep -q 'jphide\[v5\](test)'; then
    green "v5 container: dictionary attack finds the passphrase"
else
    red "v5 container: dictionary attack finds the passphrase"
fi
if ./jpcrack "$FX/stego_v3_le.jpg" "$CRACK_WL" 2>/dev/null | grep -q 'jphide\[v3\](TestPass123)'; then
    green "v3 container: dictionary attack finds the passphrase"
else
    red "v3 container: dictionary attack finds the passphrase"
fi
printf 'nope1\nnope2\nnope3\n' > "$CRACK_WL.none"
if ./jpcrack "$FX/v5_samples/s03.jpg" "$CRACK_WL.none" 2>/dev/null | grep -q 'no match'; then
    green "wrong wordlist yields no match (no false positive)"
else
    red "wrong wordlist yields no match (no false positive)"
fi
if ./jpcrack -o "$TMP_EXTRACT/cracked.bin" "$FX/stego_v5_real.jpg" "$FX/v5_samples/../real_wl.txt" 2>/dev/null | grep -q 'jphide\[v5\](jeremy23)' 2>/dev/null; then
    :
fi
printf 'wrong\njeremy23\n' > "$TMP_EXTRACT/rwl.txt"
if ./jpcrack -o "$TMP_EXTRACT/cracked.bin" "$FX/stego_v5_real.jpg" "$TMP_EXTRACT/rwl.txt" >/dev/null 2>&1 \
   && cmp -s "$TMP_EXTRACT/cracked.bin" "$FX/payload_v5_plaintext.txt"; then
    green "crack + extract (-o) yields exact plaintext end-to-end"
else
    red "crack + extract (-o) yields exact plaintext end-to-end"
fi

# rule engine: base word + mangling reaches a mangled passphrase (jeremy -> jeremy23)
printf 'jeremy\n' > "$TMP_EXTRACT/base.txt"
if ./jpcrack "$FX/stego_v5_real.jpg" "$TMP_EXTRACT/base.txt" 2>/dev/null | grep -q 'jphide\[v5\](jeremy23)'; then
    green "rule engine: mangled base word cracks the passphrase"
else
    red "rule engine: mangled base word cracks the passphrase"
fi
# -n disables rules: base 'jeremy' alone must NOT crack jeremy23
if ./jpcrack -n "$FX/stego_v5_real.jpg" "$TMP_EXTRACT/base.txt" 2>/dev/null | grep -q 'no match'; then
    green "-n verbatim mode: base word alone does not crack (rules off)"
else
    red "-n verbatim mode: base word alone does not crack (rules off)"
fi

# false-positive resistance: 50k wrong candidates must yield no match (full 5-layer v5 check)
python3 -c "import random,string;open('$TMP_EXTRACT/fp.txt','w').write(chr(10).join(''.join(random.choices(string.ascii_lowercase,k=8)) for _ in range(50000)))"
if ./jpcrack -n "$FX/stego_v5_real.jpg" "$TMP_EXTRACT/fp.txt" 2>/dev/null | grep -q 'no match'; then
    green "50k wrong candidates yield no false positive (full v5 validation)"
else
    red "50k wrong candidates yield no false positive (full v5 validation)"
fi

echo
echo "-- crlf_check: Windows text-mode damage"
check "CRLF-mangled file is flagged as text-mode damage" \
      "TEXT-mode stream" \
      python3 crlf_check.py "$FX/stego_v3_le_textmode_damaged.jpg"

nocheck "healthy binary file is NOT flagged" \
        "TEXT-mode stream" \
        python3 crlf_check.py "$FX/stego_v3_le.jpg"

nocheck "damaged file is invisible to jphoracle before repair" \
        "MATCH" \
        ./jphoracle "$FX/stego_v3_le_textmode_damaged.jpg" "$PASS"

echo
echo "-- crlf_check: repair path"
TMP=$(mktemp -d)
cp "$FX/stego_v3_le_textmode_damaged.jpg" "$TMP/d.jpg"
python3 crlf_check.py --repair "$TMP/d.jpg" >/dev/null 2>&1
if cmp -s "$TMP/d.repaired.jpg" "$FX/stego_v3_le.jpg"; then
    green "repair is byte-identical to the pre-damage container"
else
    red   "repair is byte-identical to the pre-damage container"
fi
check "repaired container is readable again" \
      "jphide v3  Blowfish=little-endian" \
      ./jphoracle "$TMP/d.repaired.jpg" "$PASS"
rm -rf "$TMP"

echo
if [ "$FAIL" -eq 0 ]; then
    echo "ALL $N GATES GREEN"
    exit 0
else
    echo "$FAIL of $N GATES FAILED"
    exit 1
fi
