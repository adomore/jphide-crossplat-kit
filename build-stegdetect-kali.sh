#!/bin/sh
# build-stegdetect-kali.sh  (v2)
#
# Kali does not ship stegdetect or stegbreak. The Kali bug tracker request
# (#1688, filed 2014) was closed "won't fix" in 2020. Debian carried the
# package until the 0.6-5 QA upload of 2008, i386 only, and later dropped it.
# Building from source is the only route.
#
# The sources are from 1996-2001 and predate several things modern toolchains
# now enforce. This script probes for what the local compiler needs rather than
# hardcoding flags, because the required flag names differ between GCC
# versions: GCC 13 rejects -Wno-error=return-mismatch outright, GCC 14+ needs
# it. Everything below was found by hitting the failure first.
#
# Usage:  sh build-stegdetect-kali.sh [target-dir]
# Env:    CC32=...          override the 32-bit compiler command
#         EXTRA_CFLAGS=...  injected first, for testing
#
# Result: <target-dir>/stegdetect and <target-dir>/stegbreak

set -e
DIR="${1:-stegdetect-build}"
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

echo "== 0. dependencies"
echo "   sudo apt install build-essential gcc-multilib libc6-dev-i386 git"
echo

# ---------------------------------------------------------------- preflight
echo "== 1. preflight: locate a working 32-bit compiler"
echo 'int main(void){return 0;}' > "$T/t.c"
FOUND=""
for c in ${CC32:-} "gcc -m32" "gcc-15 -m32" "gcc-14 -m32" "gcc-13 -m32" "gcc-12 -m32"; do
    [ -n "$c" ] || continue
    if $c -o "$T/t" "$T/t.c" 2>/dev/null && "$T/t" 2>/dev/null; then
        FOUND="$c"; break
    fi
done
if [ -z "$FOUND" ]; then
    echo "   FAILED: no working 32-bit compiler." >&2
    echo "   Upstream requires a 32-bit build: the x86-64 build links and runs," >&2
    echo "   but its chi-squared values drift and stegbreak corrupts memory." >&2
    echo >&2
    echo "   Diagnose with:" >&2
    echo "     gcc --version" >&2
    echo "     printf 'int main(void){return 0;}' > /tmp/t.c" >&2
    echo "     gcc -m32 -o /tmp/t /tmp/t.c      # read the actual error" >&2
    echo "   If gcc -m32 cannot find crt or libgcc, the multilib package does" >&2
    echo "   not match your default gcc. Install the matching one, e.g." >&2
    echo "     sudo apt install gcc-\$(gcc -dumpversion)-multilib" >&2
    exit 1
fi
CC32="$FOUND"
echo "   using: $CC32"

echo "== 2. preflight: probe which legacy-C escape hatches this gcc accepts"
# GCC 14 promoted implicit-int, implicit-function-declaration, int-conversion,
# incompatible-pointer-types and return-mismatch from warnings to errors. The
# autoconf 2.12 probe inside jpeg-6b is literally  main(){return(0);}  so its
# configure reports "C compiler cannot create executables" and the whole build
# dies. Demote them. Probe each flag: older gcc errors on unknown -Wno-error
# names, so a hardcoded list is not portable.
COMPAT=""
for f in -Wno-error=implicit-int \
         -Wno-error=implicit-function-declaration \
         -Wno-error=int-conversion \
         -Wno-error=incompatible-pointer-types \
         -Wno-error=return-mismatch \
         -Wno-error=declaration-missing-parameter-type; do
    if $CC32 ${EXTRA_CFLAGS:-} $f -o "$T/t" "$T/t.c" 2>/dev/null; then
        COMPAT="$COMPAT $f"
    fi
done
echo "   accepted:$COMPAT"

echo "== 3. preflight: pick a C standard the 2001 sources still parse under"
# GCC 15 changed the default from gnu17 to gnu23, and C23 made true, false and
# bool into keywords. stegdetect.c line 765 declares  float f, f2, sum, false;
# so it stops being valid C and step 8 dies with
#   error: expected identifier or '(' before 'false'
# Probe with that exact pattern and add -std only if the default cannot take it.
cat > "$T/c23.c" <<'PROBE'
int main(void){ float false; false = 1; return false > 0; }
PROBE
STD=""
for s in "" -std=gnu17 -std=gnu11 -std=gnu99; do
    if $CC32 ${EXTRA_CFLAGS:-} $s -w -o "$T/c" "$T/c23.c" 2>/dev/null; then
        STD="$s"; break
    fi
done
if [ -z "$STD" ]; then
    echo "   default standard is fine, no -std needed"
else
    echo "   using: $STD"
fi

# -fcommon: gcc 10+ defaults to -fno-common and the tree has tentative
# definitions that then collide (multiple definition of 'progname').
CF="${EXTRA_CFLAGS:-} -O2 -w -fcommon -m32 $STD $COMPAT"
echo "   CFLAGS: $CF"

# ---------------------------------------------------------------- build
if [ ! -d "$DIR" ]; then
    echo "== 4. fetch the 0.6 sources"
    git clone --depth 1 https://github.com/abeluck/stegdetect.git "$DIR"
fi
cd "$DIR"

echo "== 5. stop automake from regenerating"
# aclocal-1.15 is long gone, and the shipped 'missing' script is too old to
# answer --is-lightweight. Touching the generated files keeps make from trying,
# and stubbing 'missing' silences a confusing warning during configure.
touch aclocal.m4 configure config.h.in Makefile.in stamp-h.in
printf '#!/bin/sh\nexit 0\n' > missing && chmod +x missing

echo "== 6. configure (top level, propagates CFLAGS into the subdirs)"
if ! linux32 ./configure --without-x CC="$CC32" CFLAGS="$CF" > "$T/cfg.log" 2>&1; then
    echo "   FAILED. Last lines of configure output:" >&2
    tail -20 "$T/cfg.log" >&2
    [ -f config.log ] && { echo "   --- config.log tail ---" >&2; tail -30 config.log >&2; }
    exit 1
fi

echo "== 7. build the bundled, patched jpeg-6b"
# It carries stego_mcu_order / stego_natural_order hooks that stegdetect links
# against. The system libjpeg does not have them, so this cannot be skipped.
( cd jpeg-6b && linux32 ./configure CC="$CC32" CFLAGS="$CF" >/dev/null 2>&1
  make libjpeg.a CFLAGS="$CF" >/dev/null )

echo "== 8. build the bundled libfile"
( cd file && make libfile.a CFLAGS="$CF" >/dev/null )

echo "== 9. build the binaries"
linux32 make stegdetect stegbreak CFLAGS="$CF" >/dev/null

echo "== 10. supply rules.ini"
# stegbreak needs John the Ripper wordlist rules. Upstream dropped the file
# from 0.6 and never restored it, so stegbreak aborts on fopen without one.
[ -f rules.ini ] || printf '[List.Rules:Wordlist]\n:\n-c l\n-c u\n-c c\n' > rules.ini

echo
echo "built:"
ls -l stegdetect stegbreak
echo
cat <<'EOF'
SMOKE TEST (fixtures ship with this kit)

  cp ../fixtures/stego_v3_le.jpg .
  ./stegdetect -s 3 -t p stego_v3_le.jpg        expect: jphide(*)
  ./stegbreak -c -t p stego_v3_le.jpg || true   expect: converted to .jph
                                                (exit 139 is normal, see below)
  printf 'wrong\nTestPass123\n' > w.txt
  ./stegbreak -r rules.ini -f w.txt -t p stego_v3_le.jph
                                                expect: jphide[v3](TestPass123)

NOTES

  stegdetect detects; it never extracts. Its jphide verdict is a chi-squared
  test with fixed thresholds: false positives on clean images, misses at
  default sensitivity. Raise it with -s.

  stegbreak segfaults when handed a .jpg directly, in both 32- and 64-bit
  builds. The documented -c conversion path works, but it too exits 139: it
  writes a complete, valid .jph and then crashes during teardown. Ignore the
  exit code and use the file. In a script, append || true.
  It recovers a passphrase and the container version, not the payload.
EOF
