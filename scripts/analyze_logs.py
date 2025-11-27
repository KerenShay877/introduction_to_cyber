import json
from datetime import datetime
from statistics import mean
from collections import defaultdict

def parse_logs(log_file):
    """
    Parse JSON lines log file into structured entries.
    Each line should contain:
    timestamp, group_seed, username, hash_mode, protection_flags, result, latency_ms
    """
    results = []
    with open(log_file, "r") as f:
        for line in f:
            try:
                entry = json.loads(line.strip())
                # Convert timestamp string to datetime
                entry["timestamp"] = datetime.fromisoformat(entry["timestamp"])
                results.append(entry)
            except json.JSONDecodeError:
                continue
    return results

def summarize(results, user_categories, keyspace_size=None):
    """
    Summarize metrics across all log entries.
    user_categories: dict mapping username -> category (weak/medium/strong)
    keyspace_size: optional int, used for extrapolation if no success achieved
    """
    summary = {
        "total_attempts": len(results),
        "attempts_per_second": None,
        "time_to_first_success": None,
        "success_rate_by_category": {"weak": 0, "medium": 0, "strong": 0},
        "average_latency_by_hash": {},
        "extrapolation": None
    }

    if not results:
        return summary

    # Attempts per second
    timestamps = [r["timestamp"] for r in results]
    total_time = (max(timestamps) - min(timestamps)).total_seconds()
    if total_time > 0:
        summary["attempts_per_second"] = len(results) / total_time

    # Time to first success
    successes = [r for r in results if r["result"] == "SUCCESS"]
    if successes:
        first_attempt_time = min(timestamps)
        first_success_time = min(r["timestamp"] for r in successes)
        summary["time_to_first_success"] = (first_success_time - first_attempt_time).total_seconds()

    # Success rate by category
    attempts_by_cat = defaultdict(int)
    successes_by_cat = defaultdict(int)
    for r in results:
        cat = user_categories.get(r["username"], "unknown")
        attempts_by_cat[cat] += 1
        if r["result"] == "SUCCESS":
            successes_by_cat[cat] += 1
    for cat in ["weak", "medium", "strong"]:
        if attempts_by_cat[cat] > 0:
            summary["success_rate_by_category"][cat] = successes_by_cat[cat] / attempts_by_cat[cat]

    # Average latency per hash_mode
    latencies_by_hash = defaultdict(list)
    for r in results:
        latencies_by_hash[r["hash_mode"]].append(r.get("latency_ms", 0))
    for h, vals in latencies_by_hash.items():
        summary["average_latency_by_hash"][h] = mean(vals)

    # Extrapolation if full crack not achieved
    if keyspace_size and summary["attempts_per_second"]:
        if not successes:  # no success achieved
            est_time = keyspace_size / summary["attempts_per_second"]
            summary["extrapolation"] = f"Estimated {est_time/3600:.2f} hours to crack (assuming keyspace={keyspace_size})"

    return summary

if __name__ == "__main__":
    # Example: load user categories from users.json
    with open("users.json", "r") as f:
        users = json.load(f)
    user_categories = {u["username"]: u["category"] for u in users}

    logs = parse_logs("logs/attempts.log")
    # Provide keyspace_size if you want extrapolation (e.g., 2**40 for strong passwords)
    report = summarize(logs, user_categories, keyspace_size=2**40)

    print("=== Experiment Summary ===")
    print(f"Total attempts: {report['total_attempts']}")
    print(f"Attempts per second: {report['attempts_per_second']}")
    print(f"Time to first success (s): {report['time_to_first_success']}")
    print("Success rate by category:")
    for cat, rate in report["success_rate_by_category"].items():
        print(f"  {cat}: {rate:.2f}")
    print("Average latency by hash mode:")
    for h, avg in report["average_latency_by_hash"].items():
        print(f"  {h}: {avg:.2f} ms")
    if report["extrapolation"]:
        print(f"Extrapolation: {report['extrapolation']}")
