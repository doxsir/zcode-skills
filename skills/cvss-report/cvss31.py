#!/usr/bin/env python3
# cvss 3.1 base score. таблицы весов из спеки FIRST, не выдуманы
import sys, math, re

AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
AC = {"L": 0.77, "H": 0.44}
PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}
UI = {"N": 0.85, "R": 0.62}
CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

def roundup(x):
    # спека требует roundup до 1 знака, а float 4.0 может быть 4.000000001
    i = int(round(x * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0

def parse(vector):
    m = dict(re.findall(r"(AV|AC|PR|UI|S|C|I|A):([A-Za-z])", vector))
    needed = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    if set(m) != needed:
        missing = needed - set(m)
        sys.exit("no metrics in vector: %s" % ", ".join(sorted(missing)))
    return m

def score(m):
    av, ac = AV[m["AV"]], AC[m["AC"]]
    ui = UI[m["UI"]]
    scope_changed = m["S"] == "C"
    pr = (PR_C if scope_changed else PR_U)[m["PR"]]
    c, i, a = CIA[m["C"]], CIA[m["I"]], CIA[m["A"]]

    isc = min(1 - (1 - c) * (1 - i) * (1 - a), 0.915)
    expl = 8.22 * av * ac * pr * ui

    if not scope_changed:
        impact = 6.42 * isc
        base = min(impact + expl, 10)
    else:
        impact = 7.52 * (isc - 0.029) - 3.25 * (isc - 0.02) ** 15
        base = min(1.08 * (impact + expl), 10)

    if impact <= 0:
        return 0.0
    return roundup(base)

def severity(s):
    if s == 0: return "none"
    if s <= 3.9: return "low"
    if s <= 6.9: return "medium"
    if s <= 8.9: return "high"
    return "critical"

def main():
    if len(sys.argv) != 2:
        sys.exit("usage: cvss31.py AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    m = parse(sys.argv[1].upper())
    s = score(m)
    print("vector  : CVSS:3.1/" + sys.argv[1].upper())
    print("score   : %.1f (%s)" % (s, severity(s)))

if __name__ == "__main__":
    main()
