"""Politika simülatörü."""

from axctl.compiler import compile_policy
from axctl.exceptions import PolicyError
from axctl.policy import load_policy


def simulate_policy(path: str | None = None) -> dict:
    """Politikanın etkilerini simüle eder."""
    policy = load_policy(path)
    compiled = compile_policy(policy)

    simulation = {
        "mode": compiled["mode"],
        "total_rules": len(compiled["rules"]),
        "total_labels": len(compiled["labels"]),
        "rules": [],
        "conflicts": [],
        "affected_processes": set(),
    }

    for rule in compiled["rules"]:
        subjects = rule["subject"]
        simulation["affected_processes"].update(subjects)

        rule_sim = {
            "id": rule["id"],
            "name": rule["name"],
            "subjects": subjects,
            "object": rule["object"] or "(tüm)",
            "action": rule["action"],
            "effect": rule["effect"].upper(),
            "priority": rule["priority"],
        }
        simulation["rules"].append(rule_sim)

    simulation["affected_processes"] = sorted(simulation["affected_processes"])
    return simulation
