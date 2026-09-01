#!/usr/bin/env python3
"""
rule_expand.py -- exact replica of jpcrack.c rules_apply(), for reasoning about
how many candidates one base word expands to, and where a given mangled variant
falls in the generation order.

Two independent code paths are provided and cross-checked:
  gen(base)   -- generates the candidates in the SAME ORDER jpcrack emits them
  count(base) -- a closed-form count that must equal len(gen(base))

Usage:
  python3 rule_expand.py smalvilesoker            # count + where '6'+word lands
  python3 rule_expand.py smalvilesoker 6smalvilesoker
  python3 rule_expand.py --selftest
"""
import sys

SUFFIXES = ["23","1","12","123","1234","12345","!","@","#","01",
            "007","69","111","2020","2021","2022","2023","2024","00"]
LEET = [('a','@'),('a','4'),('e','3'),('i','1'),('o','0'),('s','$'),('s','5'),('t','7')]

def _cap(w):
    return (chr(ord(w[0])-32) + w[1:]) if w and 'a' <= w[0] <= 'z' else None

def gen(base, rules_on=True):
    """Emit candidates in jpcrack's exact order. Note: jpcrack does NOT dedupe,
    so strings that coincide (e.g. lowercase-all of an already-lowercase word)
    are still emitted and still counted -- we replicate that faithfully."""
    L = len(base)
    out = []
    if L == 0 or L > 250:
        return out
    out.append(base)                                   # : base as-is
    if not rules_on:
        return out
    c = _cap(base)
    if c is not None:                                  # c capitalize
        out.append(c)
    out.append(''.join(chr(ord(x)-32) if 'a'<=x<='z' else x for x in base))  # u upper (always)
    out.append(''.join(chr(ord(x)+32) if 'A'<=x<='Z' else x for x in base))  # l lower (always)
    for cap in (0, 1):                                 # $N append digit, base + capitalized
        b = base if cap == 0 else _cap(base)
        if b is None:
            continue
        for d in '0123456789':
            out.append(b + d)
    for cap in (0, 1):                                 # $$ append suffixes, base + capitalized
        b = base if cap == 0 else _cap(base)
        if b is None:
            continue
        for s in SUFFIXES:
            out.append(b + s)
    for d in '0123456789':                             # ^N prepend digit
        out.append(d + base)
    out.append(base[::-1])                             # r reverse
    if L * 2 < 300:                                    # d duplicate (buf is char[300])
        out.append(base + base)
    for f, t in LEET:                                  # leet: emitted only if it changes something
        if f in base:
            out.append(base.replace(f, t))
    return out

def count(base, rules_on=True):
    """Closed form -- must equal len(gen(base)). This is the exact logic to port
    into jpcrack as count_variants() for the progress denominator."""
    L = len(base)
    if L == 0 or L > 250:
        return 0
    if not rules_on:
        return 1
    lc = 'a' <= base[0] <= 'z'
    n = 1                       # base
    if lc: n += 1               # capitalize
    n += 2                      # upper + lower (always)
    n += 20 if lc else 10       # append digit (x2 caps if lowercase-initial)
    n += 2*len(SUFFIXES) if lc else len(SUFFIXES)   # append suffixes (x2 caps)
    n += 10                     # prepend digit
    n += 1                      # reverse
    if L * 2 < 300: n += 1      # duplicate
    present = set(ch for ch in base)
    n += (2 if 'a' in present else 0) + (1 if 'e' in present else 0) \
       + (1 if 'i' in present else 0) + (1 if 'o' in present else 0) \
       + (2 if 's' in present else 0) + (1 if 't' in present else 0)
    return n

def analyze(base, target=None):
    g = gen(base)
    n = len(g)
    assert n == count(base), f"gen/count mismatch for {base!r}: {n} vs {count(base)}"
    print(f"base word          : {base!r}  (len {len(base)}, "
          f"{'lowercase-initial' if base and 'a'<=base[0]<='z' else 'non-lowercase-initial'})")
    print(f"variants generated : {n}   (verbatim/-n mode: {count(base, rules_on=False)})")
    if target is None:
        target = ('6' + base)
    if target in g:
        idx = g.index(target) + 1   # 1-based
        print(f"variant {target!r}")
        print(f"  -> appears at position {idx} of {n} in the generation order")
    else:
        print(f"variant {target!r} is NOT produced by the rules for this base")

def selftest():
    # exact numbers cited for the s06 crack
    b = "smalvilesoker"
    g = gen(b)
    assert len(g) == 81, len(g)
    assert len(g) == count(b)
    assert g.index("6smalvilesoker") + 1 == 69, g.index("6smalvilesoker") + 1
    # cross-check gen==count on a spread of shapes
    for w in ["a", "abc", "Password", "123456", "1q2w3e", "!bang", "aeios",
              "smalvilesoker", "x"*149, "x"*150, "x"*251, "", "kaosmon"]:
        assert len(gen(w)) == count(w), (w, len(gen(w)), count(w))
    # theoretical envelope
    lo_lc  = count("bcdfg")      # lowercase word, no leet letters at all
    hi_lc  = count("aeioast")    # lowercase word hitting every leet rule (a,e,i,o,s,t)
    dig    = count("12345")      # digit-initial (numeric passwords, very common in rockyou)
    print("SELFTEST OK")
    print(f"  smalvilesoker           -> 81 variants, '6smalvilesoker' at #69")
    print(f"  lowercase, no leet      -> {lo_lc} variants  (e.g. 'bcdfg')")
    print(f"  lowercase, all leet     -> {hi_lc} variants  (e.g. 'aeioast')")
    print(f"  digit-initial word      -> {dig} variants  (e.g. '12345')")

if __name__ == "__main__":
    args = sys.argv[1:]
    if not args or args[0] == "--selftest":
        selftest()
    else:
        analyze(args[0], args[1] if len(args) > 1 else None)
