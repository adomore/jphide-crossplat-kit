#!/bin/sh
# make-kali-release.sh -- assemble a ready-to-run Kali binary release of
# jphide-crossplat-kit from an already-built source tree.
#
# Run this ON the Kali machine where you built the kit, from inside the kit
# directory, i.e. after both builds have succeeded:
#   ./build.sh                    -> jpcrack jphoracle jpseek5 v5diff
#   sh build-stegdetect-kali.sh   -> stegdetect-build/{stegdetect,stegbreak,rules.ini}
#
# Result: jphide-crossplat-kit-<VER>-kali-amd64.tar.gz  (unpack and run).
#
# Usage:  sh make-kali-release.sh [stegdetect-build-dir]

set -e
VER=2.3
SD_DIR="${1:-stegdetect-build}"                 # output dir of build-stegdetect-kali.sh
REL="jphide-crossplat-kit-${VER}-kali-amd64"

rm -rf "$REL"; mkdir "$REL"

# --- native 64-bit tools (required) ---
for f in jpcrack jphoracle jpseek5 v5diff; do
    [ -x "$f" ] || { echo "ERROR: ./$f not found -- run ./build.sh first" >&2; exit 1; }
    cp "$f" "$REL"/
done

# --- python tools (standard library only, no third-party deps) ---
cp dict_hygiene.py rule_expand.py crlf_check.py "$REL"/

# --- documentation (README pair + both manuals, EN/ZH) ---
cp README.md README_en.md \
   GETTING_STARTED.md GETTING_STARTED_zh.md \
   USER_MANUAL.md USER_MANUAL_zh.md "$REL"/

# --- test corpus + gate suite, so recipients can verify on their own machine ---
cp -r fixtures selftest.sh "$REL"/

# --- stegdetect / stegbreak (32-bit) + rules.ini (included if present) ---
if [ -x "$SD_DIR/stegbreak" ] && [ -x "$SD_DIR/stegdetect" ]; then
    cp "$SD_DIR/stegdetect" "$SD_DIR/stegbreak" "$SD_DIR/rules.ini" "$REL"/
    HAVE_SD=1
else
    echo "note: $SD_DIR/{stegdetect,stegbreak} not found -- skipping them." >&2
    echo "      build them first with:  sh build-stegdetect-kali.sh" >&2
    HAVE_SD=0
fi

chmod +x "$REL"/jpcrack "$REL"/jphoracle "$REL"/jpseek5 "$REL"/v5diff "$REL"/*.py
[ "$HAVE_SD" = 1 ] && chmod +x "$REL"/stegdetect "$REL"/stegbreak

# --- strip binaries to shrink the release (delete these two lines to keep symbols) ---
strip "$REL"/jpcrack "$REL"/jphoracle "$REL"/jpseek5 "$REL"/v5diff 2>/dev/null || true
[ "$HAVE_SD" = 1 ] && { strip "$REL"/stegdetect "$REL"/stegbreak 2>/dev/null || true; }

# --- runtime notes shipped inside the bundle ---
cat > "$REL/INSTALL.txt" <<'EOF'
jphide-crossplat-kit 2.3 — Kali Linux (amd64) 预编译发布包 / prebuilt release

本包在 Kali Linux (amd64) 上编译，给同版本 Kali 直接运行，无需重新编译。
Built on Kali Linux (amd64); runs as-is on the same Kali version, no rebuild.

--------------------------------------------------------------------
依赖 / Requirements
--------------------------------------------------------------------
[中文]
- 原生工具 jpcrack / jphoracle / jpseek5 / v5diff：依赖 glibc（系统自带）与
  libjpeg（Kali 上为 libjpeg.so.62，由 libjpeg62-turbo 提供，几乎每台 Kali
  都已安装）。若运行时提示缺 libjpeg：
      sudo apt install libjpeg62-turbo
- Python 工具 dict_hygiene.py / rule_expand.py / crlf_check.py：只需 python3
  （Kali 自带），仅用标准库，无第三方依赖。
- stegdetect / stegbreak 是 32 位程序，需要 32 位 glibc（amd64 Kali 默认没有）：
      sudo dpkg --add-architecture i386
      sudo apt update
      sudo apt install libc6:i386
  它们自带静态 jpeg，不额外依赖 libjpeg；rules.ini 是它们的规则数据文件。

[English]
- Native tools jpcrack/jphoracle/jpseek5/v5diff: need glibc (present) and libjpeg
  (libjpeg.so.62 on Kali, from libjpeg62-turbo, present on nearly every install).
  If libjpeg is missing at runtime:  sudo apt install libjpeg62-turbo
- Python tools: python3 only (present on Kali), standard library, no third-party deps.
- stegdetect/stegbreak are 32-bit and need 32-bit glibc (not default on amd64):
      sudo dpkg --add-architecture i386 && sudo apt update && sudo apt install libc6:i386
  They bundle jpeg statically (no libjpeg needed); rules.ini is their rule data file.

--------------------------------------------------------------------
验证 / Verify
--------------------------------------------------------------------
  ./selftest.sh          # 29 道门禁；原生工具在本机可运行则全绿
                         # 29 gates; all green if the native tools run here

--------------------------------------------------------------------
快速开始 / Quick start
--------------------------------------------------------------------
  printf 'letmein\njeremy23\n' > demo.txt
  ./jpcrack -o out.bin fixtures/stego_v5_real.jpg demo.txt && cat out.bin

文档 / Docs:  GETTING_STARTED.md · USER_MANUAL.md   （中文：*_zh.md）
EOF

# --- checksums + tarball ---
( cd "$REL" && find . -type f ! -name SHA256SUMS | LC_ALL=C sort | xargs sha256sum > SHA256SUMS )
tar czf "$REL.tar.gz" "$REL"

echo
echo "built: $REL.tar.gz  ($(du -h "$REL.tar.gz" | cut -f1))"
[ "$HAVE_SD" = 1 ] || echo "  (stegdetect/stegbreak were NOT included -- see the note above)"
sha256sum "$REL.tar.gz"
echo
echo "Attach $REL.tar.gz to a GitHub Release. Recipients:  tar xzf $REL.tar.gz && cd $REL && ./selftest.sh"
