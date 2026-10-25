"""Device-level metrics, with uncaught episodes retained in denominators."""
from collections import defaultdict
from math import ceil
from statistics import median


def ratio(numerator, denominator):
    return numerator / denominator if denominator else None


def summarize(records: list[dict]) -> dict:
    groups = defaultdict(list)
    for row in records:
        groups[(row["mode"], row["deviceId"])].append(row)
    output = {}
    for mode in sorted({key[0] for key in groups}):
        attack_count = eligible = caught = caught_10 = benign_count = false_positives = pre_attack = 0
        caught_rounds, escalation_rounds, latencies = [], [], []
        by_strategy = defaultdict(lambda: {"eligible": 0, "caught": 0, "caughtWithin10": 0})
        for (group_mode, _), rows in groups.items():
            if group_mode != mode:
                continue
            rows = sorted(rows, key=lambda item: item["round"])
            latencies.extend(row["latencyMs"] for row in rows)
            first = next((row for row in rows if row["action"] == "quarantine"), None)
            scenario = rows[0]["scenario"]
            if scenario == "benign":
                benign_count += 1
                false_positives += int(first is not None)
                continue
            attack_count += 1
            if first is not None and first["phase"] == "warmup":
                pre_attack += 1
                continue
            eligible += 1
            by_strategy[scenario]["eligible"] += 1
            if first is None:
                continue
            caught += 1
            by_strategy[scenario]["caught"] += 1
            caught_rounds.append(first["attackRound"])
            within_ten = int(first["attackRound"] <= 10)
            caught_10 += within_ten
            by_strategy[scenario]["caughtWithin10"] += within_ten
            first_indicator = next((row for row in rows if row["phase"] == "attack"
                                    and (row["isProbe"] or row["action"] == "quarantine")), None)
            if first_indicator is not None:
                escalation_rounds.append(first["attackRound"] - first_indicator["attackRound"])
        latencies.sort()
        output[mode] = {
            "attackDevices": attack_count,
            "preAttackQuarantines": pre_attack,
            "eligibleAttackDevices": eligible,
            "caughtAttackDevices": caught,
            "uncaughtAttackDevices": eligible - caught,
            "evasionCatchRate": ratio(caught, eligible),
            "caughtWithin10Rounds": caught_10,
            "evasionCatchRateWithin10Rounds": ratio(caught_10, eligible),
            "benignDevices": benign_count,
            "falsePositiveDevices": false_positives,
            "falsePositiveRate": ratio(false_positives, benign_count),
            "medianRoundsToQuarantineAmongCaught": median(caught_rounds) if caught_rounds else None,
            "medianIndicatorToQuarantineRoundsAmongCaught": median(escalation_rounds) if escalation_rounds else None,
            "p95ComputeLatencyMs": latencies[max(0, ceil(0.95 * len(latencies)) - 1)] if latencies else None,
            "byStrategy": dict(by_strategy),
        }
    return output

