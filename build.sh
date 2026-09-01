#!/bin/sh
# Build the kit's C tools on Kali / Debian 12.
#   apt install build-essential libjpeg-dev
gcc -O2 -w -c bf.c -o bf.o || exit 1
gcc -O2 -w -c minilzo.c -o minilzo.o -I. || exit 1
gcc -O2 -w -c jphoracle.c -o jphoracle.o && gcc -o jphoracle jphoracle.o bf.o -ljpeg \
    && echo "built: ./jphoracle    (v3/v5 + endianness identifier)"
gcc -O2 -w -I. -c jpseek5.c -o jpseek5.o && gcc -o jpseek5 jpseek5.o bf.o minilzo.o -ljpeg \
    && echo "built: ./jpseek5      (v3/v5 payload extractor, native)"
gcc -O2 -w -pthread -I. -c jpcrack.c -o jpcrack.o && gcc -o jpcrack jpcrack.o bf.o minilzo.o -ljpeg -pthread \
    && echo "built: ./jpcrack      (v3/v5 dictionary attack, multi-threaded)"
gcc -O2 -w -c v5diff.c -o v5diff.o && gcc -o v5diff v5diff.o bf.o -ljpeg \
    && echo "built: ./v5diff       (v5 payload analysis tool)"
