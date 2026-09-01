#!/usr/bin/env python3
"""
crlf_check.py - decide whether a JPEG was damaged by Windows text-mode I/O.

jphide/jpseek open the JPEG with fopen(...,"r") / fopen(...,"w") and the payload
with open(..., O_RDONLY) -- none of them request binary mode.  On Linux that is
harmless; on Windows the CRT then

  * inserts 0x0D before every 0x0A on write,
  * collapses 0x0D 0x0A back to 0x0A on read,
  * treats 0x1A (Ctrl-Z) as end-of-file on read.

A file mangled that way still decodes as an image, but its DCT coefficients are
shifted, so neither jpseek nor stegdetect can find anything on Linux.

Usage:  python3 crlf_check.py suspect.jpg [original_cover.jpg]
"""
import sys
import subprocess


def scan(path):
    d = open(path, "rb").read()
    lf = d.count(b"\x0a")
    crlf = d.count(b"\x0d\x0a")
    sub = d.find(b"\x1a")
    return d, lf, crlf, sub


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2

    path = sys.argv[1]
    d, lf, crlf, sub = scan(path)

    print(f"file            : {path}")
    print(f"size            : {len(d)} bytes")
    print(f"SOI/EOI         : {d[:2].hex()} .. {d[-2:].hex()}"
          f"   {'ok' if d[:2] == b'\xff\xd8' and d[-2:] == b'\xff\xd9' else 'SUSPECT'}")
    print(f"0x0A bytes      : {lf}")
    print(f"0x0D 0x0A pairs : {crlf}")
    print(f"first 0x1A      : {sub if sub >= 0 else 'none'}")

    print()
    if lf and crlf == lf:
        print("VERDICT: every 0x0A is preceded by 0x0D.")
        print("  -> almost certainly written through a Windows TEXT-mode stream.")
        print("  -> repair with:  python3 crlf_check.py --repair " + path)
    elif crlf > lf * 0.5 and lf > 8:
        print("VERDICT: suspiciously many CRLF pairs for binary JPEG data.")
        print("  -> likely text-mode damage; try the repair and re-run jpseek.")
    else:
        print("VERDICT: CR/LF distribution looks like normal binary data.")
        print("  -> text-mode corruption is NOT the explanation here.")

    # a second, independent signal: extraneous bytes before markers
    try:
        out = subprocess.run(["djpeg", "-outfile", "/dev/null", path],
                             capture_output=True, text=True).stderr.strip()
        if out:
            print(f"\nlibjpeg says   : {out}")
            if "extraneous bytes" in out:
                print("  -> inserted bytes confirmed inside the entropy-coded stream.")
    except FileNotFoundError:
        pass

    if len(sys.argv) > 2 and sys.argv[2] != "--repair":
        c = open(sys.argv[2], "rb").read()
        print(f"\ncover           : {sys.argv[2]}  ({len(c)} bytes)")
        print(f"size delta      : {len(d) - len(c):+d}")
    return 0


def repair(path):
    d = open(path, "rb").read()
    out = d.replace(b"\x0d\x0a", b"\x0a")
    new = path.rsplit(".", 1)[0] + ".repaired.jpg"
    open(new, "wb").write(out)
    print(f"wrote {new}  ({len(d)} -> {len(out)} bytes)")
    print("re-run jpseek / stegdetect against it; note that any 0x1A truncation "
          "on the Windows side is NOT recoverable this way.")


if __name__ == "__main__":
    if "--repair" in sys.argv:
        repair(sys.argv[sys.argv.index("--repair") + 1])
    else:
        sys.exit(main())
