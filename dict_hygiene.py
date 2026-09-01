#!/usr/bin/env python3
"""
dict_hygiene.py -- detect the ways a wordlist edited/created on Windows can
silently break a cracker that matches passphrases byte-for-byte (jpcrack,
stegbreak, hashcat, john...).

It flags, per file:
  * BOM            UTF-8 (EF BB BF) or UTF-16/32 byte-order marks -- a leading
                   BOM becomes part of the FIRST candidate and makes it fail.
  * UTF-16/UTF-32  wide encodings (NUL bytes between characters) -- fgets()/
                   strlen() truncate at the first NUL, so the list is dead.
  * CRLF / lone CR Windows (\\r\\n) or old-Mac (\\r) line endings -- a trailing
                   \\r rides along on every candidate if the tool splits on \\n
                   only. (jpcrack strips it; many tools do NOT.)
  * trailing space words ending in space/tab before the newline -- 'pw ' != 'pw'.
                   NOT auto-removed: a trailing space can be part of a real
                   passphrase. Flagged so you decide.
  * control chars  other non-tab control bytes inside a line (corruption / bad
                   transcode).
  * no final EOL   last line has no newline (informational; usually harmless).

Exit status is 0 only if every file is clean, so it can gate a pipeline.

Usage:
  python3 dict_hygiene.py rockyou.txt [more.txt ...]
  python3 dict_hygiene.py --fix rockyou.txt      # write rockyou.txt.clean
       (--fix normalizes encoding->UTF-8, strips BOM, CRLF/CR->LF.
        It does NOT touch trailing spaces unless you add --strip-trailing.)
  python3 dict_hygiene.py --quiet rockyou.txt     # only print files with issues
"""
import sys, os

SAMPLE = 5          # how many offending line numbers to show per category
SCAN_CAP = 5_000_000  # cap line-level scan (byte-level checks always full-file)

def classify_bom(head):
    if head.startswith(b'\xff\xfe\x00\x00'): return ("UTF-32-LE BOM", 4)
    if head.startswith(b'\x00\x00\xfe\xff'): return ("UTF-32-BE BOM", 4)
    if head.startswith(b'\xef\xbb\xbf'):     return ("UTF-8 BOM", 3)
    if head.startswith(b'\xff\xfe'):         return ("UTF-16-LE BOM", 2)
    if head.startswith(b'\xfe\xff'):         return ("UTF-16-BE BOM", 2)
    return (None, 0)

def looks_wide(data):
    """UTF-16 ASCII text has a NUL for every other byte. Distinguish a genuinely
    wide-encoded file from a binary blob by the ~50% NUL ratio in alternating
    positions rather than a raw NUL count."""
    if len(data) < 4:
        return None
    nul = data.count(0)
    if nul == 0:
        return None
    even_nul = data[0::2].count(0)
    odd_nul  = data[1::2].count(0)
    n = len(data)
    if odd_nul > 0.4 * (n // 2) and even_nul < 0.05 * (n // 2):
        return "UTF-16-LE (NULs in high bytes)"
    if even_nul > 0.4 * (n // 2) and odd_nul < 0.05 * (n // 2):
        return "UTF-16-BE (NULs in high bytes)"
    if nul > 0.10 * n:
        return "wide/binary (many NUL bytes)"
    return None

def check(path):
    issues = []          # (severity, message)
    with open(path, 'rb') as f:
        data = f.read()
    size = len(data)
    if size == 0:
        return [("WARN", "file is empty")]

    bom, bomlen = classify_bom(data[:4])
    if bom:
        issues.append(("FAIL", f"{bom} at offset 0 -> corrupts the FIRST candidate "
                               f"(and, for UTF-16/32, the whole file)"))
    wide = looks_wide(data)
    if wide:
        issues.append(("FAIL", f"looks like {wide} -> fgets()/strlen() truncate at "
                               f"the first NUL; wordlist is effectively unreadable"))

    # ---- line-ending census (byte level, whole file) ----
    crlf = data.count(b'\r\n')
    cr_total = data.count(b'\r')
    lone_cr = cr_total - crlf            # \r not part of \r\n
    lf_total = data.count(b'\n')
    lf_only = lf_total - crlf            # bare \n
    if crlf and lf_only == 0:
        issues.append(("WARN", f"CRLF line endings ({crlf} lines) -- Windows text mode. "
                               f"jpcrack strips the trailing \\r; hashcat/john may not."))
    elif crlf and lf_only:
        issues.append(("FAIL", f"MIXED line endings: {crlf} CRLF + {lf_only} LF -- typically "
                               f"a Unix file with lines appended by a Windows editor. The "
                               f"appended lines carry a hidden trailing \\r."))
    if lone_cr:
        issues.append(("WARN", f"{lone_cr} lone CR (\\r without \\n) -- classic-Mac endings; "
                               f"some tools treat the whole file as one line."))

    # ---- line-level checks (skip if the file is wide/binary: bytes are not lines) ----
    if not wide:
        body = data[bomlen:]
        # normalize only for iteration; report raw findings
        text = body.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
        lines = text.split(b'\n')
        # split() leaves a trailing '' if the file ends in newline; track "no final EOL"
        no_final_eol = bool(text) and not text.endswith(b'\n')
        trailing_ws = []
        ctrl = []
        for i, ln in enumerate(lines, 1):
            if ln == b'' :
                continue
            if ln[-1:] in (b' ', b'\t'):
                if len(trailing_ws) < SAMPLE:
                    trailing_ws.append(i)
                elif len(trailing_ws) == SAMPLE:
                    trailing_ws.append(-1)  # marker: "and more"
            # control bytes other than tab
            if any((b < 0x20 and b != 0x09) for b in ln):
                if len(ctrl) < SAMPLE:
                    ctrl.append(i)
            if i > SCAN_CAP:
                break
        if trailing_ws:
            more = trailing_ws and trailing_ws[-1] == -1
            nums = ", ".join(str(x) for x in trailing_ws if x != -1)
            issues.append(("WARN", f"lines ending in space/tab (e.g. lines {nums}"
                                   f"{', ...' if more else ''}) -- 'pw ' won't match 'pw'. "
                                   f"Left as-is: a trailing space may be intentional."))
        if ctrl:
            nums = ", ".join(map(str, ctrl))
            issues.append(("WARN", f"control bytes inside lines (e.g. lines {nums}) -- "
                                   f"possible corruption or bad transcode."))
        if no_final_eol:
            issues.append(("INFO", "no newline after the last line (harmless for jpcrack; "
                                   "some tools drop the final candidate)."))
    return issues

def fix(path, strip_trailing=False):
    with open(path, 'rb') as f:
        data = f.read()
    out = path + ".clean"
    bom, bomlen = classify_bom(data[:4])
    wide = looks_wide(data)
    if wide and wide.startswith("UTF-16"):
        enc = 'utf-16'   # Python handles the BOM/endianness
        text = data.decode(enc, errors='replace')
        body = text.encode('utf-8')
    else:
        body = data[bomlen:]   # drop any UTF-8/32 BOM
    # normalize newlines
    body = body.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
    if strip_trailing:
        body = b'\n'.join(ln.rstrip(b' \t') for ln in body.split(b'\n'))
    with open(out, 'wb') as f:
        f.write(body)
    print(f"  wrote {out}  ({len(body)} bytes)"
          + ("  [trailing whitespace stripped]" if strip_trailing else ""))

def main(argv):
    do_fix = "--fix" in argv
    quiet  = "--quiet" in argv
    strip  = "--strip-trailing" in argv
    files = [a for a in argv if not a.startswith("-")]
    if not files:
        print(__doc__.strip()); return 2
    any_issue = False
    for p in files:
        if not os.path.isfile(p):
            print(f"{p}: not a file"); any_issue = True; continue
        issues = check(p)
        fails = [m for s, m in issues if s == "FAIL"]
        warns = [m for s, m in issues if s in ("WARN",)]
        clean = not issues or all(s == "INFO" for s, _ in issues)
        if clean and quiet:
            continue
        tag = "CLEAN" if clean else ("BROKEN" if fails else "SUSPECT")
        print(f"[{tag}] {p}  ({os.path.getsize(p):,} bytes)")
        for sev, msg in issues:
            print(f"    {sev:4}  {msg}")
        if issues and not clean:
            any_issue = True
        if do_fix and not clean:
            fix(p, strip_trailing=strip)
    return 1 if any_issue else 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
