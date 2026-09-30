"""Politika simülatörü."""

from axctl.compiler import PROTECTED_PROCESSES, compile_policy
from axctl.exceptions import PolicyError
from axctl.policy import load_policy


def simulate_policy(path: str | None = None) -> dict:
    """Politikanın etkilerini simüle eder.

    Simülasyon yalnizca DERLEME mantigini taklit eder, enforcement'i
    degil. Yine de kritik bir ayrimi gostermelidir: korumali bir
    surece yazilan kural gercekte UYGULANMAZ. Simulatör bunu
    "uygulanacak" diye gosterirse kullanici politikayi yukler,
    daemon reddeder ve kullanici neden calismadigini anlamaz.
    """
    policy = load_policy(path)

    # Simulaturun isi ACIKLAMAKTIR. Politika derlenemiyorsa
    # (korumali surece yazilmis kural, uygulanamaz yol) komut
    # olmak yerine neyin yanlis oldugunu soylemelidir.
    #
    # Once burada dogrudan compile_policy cagriliyordu ve hata
    # yukseliyordu; kullanici yalnizca "PolicyError" goruyordu.
    # Simule etmeye calistigi seyi tam olarak gormek isteyen
    # operator icin bu, ozellikle ise yaramaz.
    try:
        compiled = compile_policy(policy)
    except PolicyError as e:
        return {
            "error": str(e),
            "mode": policy.get("mode", "enforcing"),
            "total_rules": len(policy.get("rules", []) or []),
            "total_labels": len(policy.get("labels", {}) or {}),
            "rules": [],
            "conflicts": [],
            "affected_processes": set(),
            "ineffective_rules": [],
        }

    simulation = {
        "mode": compiled["mode"],
        "total_rules": len(compiled["rules"]),
        "total_labels": len(compiled["labels"]),
        "rules": [],
        "conflicts": [],
        "affected_processes": set(),
        "ineffective_rules": [],
    }

    for rule in compiled["rules"]:
        subjects = rule["subject"]
        simulation["affected_processes"].update(subjects)

        # Korumali surecler kurala tabi DEGILDIR. Kural yazilmis
        # olabilir ama etkisi sifirdir; bunu sessizce gecmek
        # yaniltici olur.
        blocked = [s for s in subjects if s in PROTECTED_PROCESSES]
        if blocked:
            simulation["ineffective_rules"].append({
                "id": rule["id"],
                "name": rule["name"],
                "blocked_subjects": sorted(blocked),
                "reason": (
                    "Bu surecler korumali (kurtarma yolu). AXlinux "
                    "guvenlik geregi hicbir kural uygulamaz; kural "
                    "yazilmis olsa da etkisiz kalir."
                ),
            })

        rule_sim = {
            "id": rule["id"],
            "name": rule["name"],
            "subjects": subjects,
            "object": rule["object"] or "(tüm)",
            "action": rule["action"],
            "effect": rule["effect"].upper(),
            "priority": rule["priority"],
        }
        if blocked:
            rule_sim["effective"] = False
        else:
            rule_sim["effective"] = True
        simulation["rules"].append(rule_sim)

    simulation["affected_processes"] = sorted(simulation["affected_processes"])
    return simulation
