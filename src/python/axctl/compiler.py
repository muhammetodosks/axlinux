"""Politika derleyici - YAML → iç politika formatı."""

import os

from axctl.exceptions import PolicyError
from axctl.validator import validate_policy, _expand_subject


def expand_path(path: str) -> str:
    """Kullanici yolunu mutlak yola cevirir.

    "~" ve "~/..." ifadeleri cekirdekte cozulmez; kernel her zaman
    mutlak yol gorur ("~/.ssh" ile "/home/mami/.ssh" esit degildir).
    Burada genisletilmezse kural hicbir zaman eslesmez ve kullanici
    yanlislikla korumayi etkin oldugunu sanir.
    """
    if not path:
        return path
    if path == "~":
        return os.path.expanduser("~")
    if path.startswith("~/"):
        return os.path.expanduser(path)
    return path


def compile_policy(policy: dict) -> dict:
    """Politikayı doğrular ve iç formata derler."""
    validate_policy(policy)

    labels = policy.get("labels", {})
    rules = policy.get("rules", [])
    mode = policy.get("mode", "enforcing")

    compiled_rules = []
    for i, rule in enumerate(rules):
        subjects = _expand_subject(rule.get("subject", ""), labels)

        priority = _calculate_priority(rule, i)

        # "~" cekirdekte cozulmez; mutlak yola cevir.
        obj = expand_path(rule.get("object", ""))

        compiled_rules.append({
            "id": f"rule_{i + 1:03d}",
            "name": rule.get("name", ""),
            "subject": subjects,
            "object": obj,
            "action": rule.get("action", ""),
            "effect": rule.get("effect", ""),
            "port": rule.get("port"),
            "priority": priority,
        })

    compiled_rules.sort(key=lambda r: (r["effect"] != "deny", r["priority"]))

    return {
        "version": 1,
        "mode": mode,
        "labels": labels,
        "rules": compiled_rules,
    }


def _calculate_priority(rule: dict, index: int) -> int:
    """Kural önceliği hesaplar. Düşük sayı = yüksek öncelik."""
    priority = 100

    if rule.get("effect") == "deny":
        priority -= 50

    obj = rule.get("object", "")
    if obj and obj != "/":
        depth = obj.count("/")
        priority -= depth * 10

    priority += index

    return max(0, priority)
