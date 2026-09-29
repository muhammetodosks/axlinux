"""Politika doğrulayıcı."""

from axctl.exceptions import PolicyError


VALID_MODES = {"enforcing", "permissive", "disabled"}

# SÖZLESME: bu liste, LSM kancalarinin gercekten UYGULADIGI
# aksiyonlardir. Buradaki her deger icin AXlinux'ta en az bir kanca
# vardir ve o kanca anahtari uretir.
#
# Once file.delete, file.create ve net.accept de bu listedeydi.
# Hicbir kanca bu aksiyonlari uretmez (bkz. compiler.
# UNIMPLEMENTED_ACTIONS), yani kurallar sessizce islevsizdi.
# Simdilik listeden cikarildilar; uygulama eklendiginde geri
# alinabilir. Tek dogruluk kaynagi bu dosya olmali, derleyici
# UNIMPLEMENTED_ACTIONS ile ayni seyi soylememeli.
VALID_ACTIONS = {
    "file.read", "file.write", "file.execute",
    "net.connect", "net.bind", "process.exec",
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
    elif subject == "*":
        pass
    elif isinstance(subject, str):
        # Tek etiket adi ya da tek surec adi. Ikisi de gecerli.
        pass
    elif isinstance(subject, (list, tuple)):
        # En yaygin bicim: surec listesi. Go tarafi Subject'i
        # []string olarak bekliyor, yani liste yasal ve asil yoldur.
        #
        # Onceki kod bu bicimi hiç ele almıyordu ve dogrudan
        # "subject in labels" diyordu. labels bir sozluk oldugu icin
        # liste aranamaz ve Python "unhashable type: 'list'" ile
        # cokuyordu: en sik kullanilan kural bicimi dogrulamayi
        # tamamen cokturuyordu. (Diger kontroller de hic calismiyordu;
        # bir TypeError butun dogrulamayi oldurur.)
        if not subject:
            errors.append(f"{prefix}: 'subject' bos liste olamaz")
        for s in subject:
            if not isinstance(s, str) or not s.strip():
                errors.append(
                    f"{prefix}: 'subject' ogeleri bos olamayan string "
                    f"olmali, {s!r} gecersiz"
                )
    else:
        errors.append(
            f"{prefix}: 'subject' '*', bir etiket adi veya surec "
            f"listesi olmali, {type(subject).__name__} gecersiz"
        )

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

    # YOL GEREKSINIMI
    #
    # Once her file.* aksiyonu icin object zorunluydu. Bu hem
    # yanlisti: file.read yolsuz (surec bazli) bir kural gecerlidir
    # ve Go tarafi kabul eder, hem de Go ile celisiyordu.
    #
    # Iki ayri kural turu var:
    #   - yol bazli:   subject + object + action  -> /etc/shadow
    #   - surec bazli: subject + action           -> "nginx hicbir
    #     sey calistiramaz", yol bilinerek bos birakilir
    # Ikincisi Go'da ValidateRule tarafindan kabul edilir; burada
    # da kabul edilmeli, yoksa Python derleyici gecerli bir
    # politikayi reddeder. Bu yuzden object artık zorunlu DEGIL.
    #
    # file.execute de iki bicimde yazilabilir: "bu yolu calistirma"
    # (object verilir) ve "hicbir sey calistirma" (object bos).
    # Ikincisi de gecerlidir.

    # AG KURALLARI
    #
    # net.bind / net.connect portla calisir. Port yoksa anahtar
    # "p:0" olarak uretilir ve HICBIR baglantiyi tutmaz; kural
    # yuklendigi halde etkisiz kalir. Bu, sessiz basarisizligin
    # en yaygin bicimidir: kullanici "nginx aga cikamasin" yazip
    # gonderiyor, kurallar yukleniyor, nginx cikiyor.
    if action in ("net.bind", "net.connect", "net.accept"):
        port = rule.get("port")
        if port in (None, "", 0):
            errors.append(
                f"{prefix}: '{action}' aksiyonu 'port' gerektirir. "
                f"Port vermeden yazılan kural HİÇBİR bağlantıyı "
                f"etkilemez (sessizce işlevsiz kalır).")
        elif not isinstance(port, int) or not (0 < port < 65536):
            errors.append(
                f"{prefix}: 'port' 1-65535 aralığında tam sayı olmalı, "
                f"'{port}' verildi")

    return errors


def _rule_key(rule: dict) -> tuple:
    """Kural benzersiz anahtarı.

    ``port`` da anahtara dahil edilir: ayni islem icin
    ``net.bind port: 80`` ve ``net.bind port: 443`` iki ayri
    kuraldir, aksi halde ikincisi yinelenen sayilir.

    Her bilesen HASHABLE olmak zorunda, cunku anahtar bir ``set``
    icinde tutuluyor. ``subject`` dogrudan yazilinca liste oldugu
    icin ("firefox", "nginx") Python "unhashable type: 'list'" ile
    cokuyordu; en sik kullanilan kural bicimi oldugu icin bu,
    pratikte her politikanin dogrulanmasini olduruyordu.

    Subject bu yuzden sirali bir tuple'a duzgunlestirilir: boylece
    ``["a", "b"]`` ile ``["b", "a"]`` de ayni kural sayilir.
    """
    subject = rule.get("subject", "")
    if isinstance(subject, (list, tuple)):
        subject = tuple(sorted(str(s) for s in subject))
    else:
        subject = str(subject)
    return (
        subject,
        str(rule.get("object", "")),
        str(rule.get("action", "")),
        str(rule.get("port", "")),
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


def _expand_subject(subject, labels: dict) -> list:
    """Etiketleri gerçek işlem adlarına çevirir.

    ``subject`` üç biçimde gelir ve ÜÇÜ de yasaldır:

    * ``"*"``            - joker
    * ``"web"``          - ``labels`` sözlüğündeki bir etiket
    * ``["a", "b"]``     - doğrudan süreç listesi (Go tarafı
      ``Subject []string`` bekler, yani en yaygın biçim)

    Etiket listeleri de özyinelemeli olarak çözülür, aksi halde
    ``web: [browser, "www"]`` gibi bir etiket ikinci adımda
    süreç adı sanılır ve kural hiçbir şeyle eşleşmez.

    Daha önce liste biçimi hiç ele alınmıyordu: sözlükte arama
    yapıldığı için Python "unhashable type: 'list'" ile çöküyordu
    ve çakışma denetimi, en sık kullanılan kural biçiminde hiç
    çalışmıyordu.
    """
    if subject == "*":
        return ["*"]
    if isinstance(subject, (list, tuple)):
        out = []
        for s in subject:
            # Her ogge kendi etiketi olabilir; duz surec adlari da
            # ayni yoldan gecer ve etiket bulunamazsa kendisi kalir.
            for expanded in _expand_subject(s, labels):
                if expanded not in out:
                    out.append(expanded)
        return out
    if isinstance(subject, str) and subject in labels:
        value = labels[subject]
        if isinstance(value, (list, tuple)):
            return [str(v) for v in value]
        return [str(value)]
    return [subject] if not isinstance(subject, str) else [subject]
