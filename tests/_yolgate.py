#!/usr/bin/env python3
"""deep_verify icin: audit kayitlarindaki yol boslugu olcumcusu.

Yalnizca bu kapinin urettigi kayitlara bakar (surec=cat, dizin
bileseni "yolkapisi"). Uretilen sayim "toplam bos kirpilan"
seklinde stdout'a yazilir; deep_verify.sh bunu okur.
"""
import glob
import json
import sys

TOPLAM = 0
BOS = 0
KIRPILAN = 0

for yol in glob.glob("/var/log/axlinux/audit-*.jsonl"):
    try:
        dosya = open(yol, encoding="utf-8", errors="replace")
    except OSError:
        continue
    with dosya:
        for satir in dosya:
            satir = satir.strip()
            if not satir or "yolkapisi" not in satir:
                continue
            try:
                kayit = json.loads(satir)
            except ValueError:
                continue
            if (kayit.get("subject") or {}).get("comm") != "cat":
                continue
            nesne = kayit.get("object") or {}
            yol_deger = nesne.get("path") or ""
            TOPLAM += 1
            if not yol_deger:
                BOS += 1
            if nesne.get("truncated"):
                KIRPILAN += 1

sys.stdout.write("%d %d %d\n" % (TOPLAM, BOS, KIRPILAN))