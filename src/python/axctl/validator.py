"""Politika doğrulayıcı."""

from axctl.exceptions import PolicyError


VALID_MODES = {"enforcing", "permissive", "disabled"}
VALID_ACTIONS = {
    "file.read", "file.write", "file.execute", "file.delete", "file.create",
    "net.connect", "net.bind", "net.accept", "process.exec",
}
VALID_EFFECTS = {"allow", "deny"}


def validate_policy(policy: dict) -> list:
    """Politikayı doğrular, hata listesi döndürür."""
    errors = []

    if not isinstance(policy, dict):
        raise PolicyError("Politika bir sözlük olmalı")

    version = policy.get("version")
    if version != 1:
        errors.append(f"version: 1 olmalı, {version} verildi")

    mode = policy.get("mode", "enforcing")
    if mode not in VALID_MODES:
        errors.append(f"mode: {VALID_MODES} değerlerinden biri olmalı, '{mode}' verildi")

    labels = policy.get("labels", {})
    if not isinstance(labels, dict):
        errors.append("labels: sözlük olmalı")
        labels = {}

    rules = policy.get("rules", [])
    if not isinstance(rules, list):
        errors.append("rules: liste olmalı")
        rules = []

    seen_rules = set()
    for i, rule in enumerate(rules):
        rule_errors = _validate_rule(rule, i, labels)
        errors.extend(rule_errors)

        rule_key = _rule_key(rule)
        if rule_key in seen_rules:
            errors.append(f"Kural {i+1}: Yinelenen kural ({rule_key})")
        seen_rules.add(rule_key)

    conflicts = _detect_conflicts(rules, labels)
    errors.extend(conflicts)

    if errors:
        raise PolicyError(f"Politika doğrulama başarısız: {len(errors)} hata", errors)

    return errors


def _validate_rule(rule: dict, index: int, labels: dict) -> list:
    """Tek kuralı doğrular."""
    errors = []
    prefix = f"Kural {index+1}"

    if not isinstance(rule, dict):
        return [f"{prefix}: sözlük olmalı"]

    name = rule.get("name")
    if not name or not isinstance(name, str):
        errors.append(f"{prefix}: 'name' gerekli ve string olmalı")

    subject = rule.get("subject")
    if not subject:
        errors.append(f"{prefix}: 'subject' gerekli")
    elif subject != "*":
        if subject in labels:
            pass
        elif isinstance(subject, str) and subject:
            pass
        else:
            errors.append(f"{prefix}: '{subject}' tanımlı bir etiket değil")

    action = rule.get("action")
    if not action:
        errors.append(f"{prefix}: 'action' gerekli")
    elif action not in VALID_ACTIONS:
        errors.append(f"{prefix}: geçersiz aksiyon '{action}'. Geçerli: {sorted(VALID_ACTIONS)}")

    effect = rule.get("effect")
    if not effect:
        errors.append(f"{prefix}: 'effect' gerekli")
    elif effect not in VALID_EFFECTS:
        errors.append(f"{prefix}: geçersiz etki '{effect}'. Geçerli: {sorted(VALID_EFFECTS)}")

    if action and action.startswith("file.") and not rule.get("object"):
        errors.append(f"{prefix}: file.* aksiyonları için 'object' gerekli")

    return errors


def _rule_key(rule: dict) -> tuple:
    """Kural benzersiz anahtarı.

    ``port`` da anahtara dahil edilir: ayni islem icin
    ``net.bind port: 80`` ve ``net.bind port: 443`` iki ayri
    kuraldir, aksi halde ikincisi yinelenen sayilir.
    """
    return (
        rule.get("subject", ""),
        rule.get("object", ""),
        rule.get("action", ""),
        rule.get("port", ""),
    )


def _detect_conflicts(rules: list, labels: dict) -> list:
    """Çakışan kuralları tespit eder."""
    conflicts = []
    expanded = []

    for i, rule in enumerate(rules):
        subjects = _expand_subject(rule.get("subject", ""), labels)
        for subj in subjects:
            expanded.append((
                subj,
                rule.get("object", ""),
                rule.get("action", ""),
                rule.get("port", ""),
                rule.get("effect", ""),
                i + 1,
            ))

    for i in range(len(expanded)):
        for j in range(i + 1, len(expanded)):
            s1, o1, a1, p1, e1, idx1 = expanded[i]
            s2, o2, a2, p2, e2, idx2 = expanded[j]
            if s1 == s2 and o1 == o2 and a1 == a2 and p1 == p2 and e1 != e2:
                target = f"{s1} {a1} {o1}".strip()
                if p1 != "":
                    target += f" port={p1}"
                conflicts.append(
                    f"Çakışma: Kural {idx1} ({e1}) ile Kural {idx2} ({e2}) "
                    f"aynı hedefe farklı etki uyguluyor: {target}"
                )

    return conflicts


def _expand_subject(subject: str, labels: dict) -> list:
    """Etiketleri gerçek işlem adlarına çevirir."""
    if subject == "*":
        return ["*"]
    if subject in labels:
        return labels[subject]
    return [subject]
