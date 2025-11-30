import json
import random
import string
import subprocess
from pathlib import Path
from typing import Dict, Any, List

# Configuration
MAX_MUTATIONS_PER_SEED = 5
TIMEOUT_SEC = 2


def build_stdin(payload: str, input_index: int) -> str:
    """
    Build 4-line stdin to match test.py input() order:
    0 -> Enter command
    1 -> Enter filename
    2 -> Enter username
    3 -> Enter expression
    """
    inputs = [
        "echo safe",    # safe command
        "test_targets/test.py",      # safe filename
        "alice",        # safe username
        "1+1"           # safe expression
    ]

    if 0 <= input_index < len(inputs):
        inputs[input_index] = payload

    return "\n".join(inputs) + "\n"


def mutate_payload(base: str, category: str) -> str:
    """
    Simple mutation engine based on sink type.
    """
    cmd_chars = [";", "&&", "||", "|", "$()", "`", ">", "<", "&"]
    path_parts = ["../", "../../", "/etc/", "..\\", "%2f"]
    sql_parts = ["' OR '1'='1", "--", ";DROP TABLE users", "' OR 1=1 --"]
    eval_parts = ["1/0", "__import__('os').system('ls')", "().__class__", "globals()"]

    strategies = ["append", "prepend", "repeat", "flip"]
    strategy = random.choice(strategies)

    if strategy == "append":
        if category == "command":
            return base + random.choice(cmd_chars)
        if category == "path":
            return base + random.choice(path_parts)
        if category == "sql":
            return base + random.choice(sql_parts)
        if category == "eval":
            return base + random.choice(eval_parts)
        return base + random.choice(string.punctuation)

    if strategy == "prepend":
        if category == "command":
            return random.choice(cmd_chars) + base
        if category == "path":
            return random.choice(path_parts) + base
        return random.choice(string.punctuation) + base

    if strategy == "repeat":
        return (base * random.randint(1, 5))[:200]

    if strategy == "flip":
        if not base:
            return base
        chars = list(base)
        for _ in range(random.randint(1, max(1, len(chars)//3))):
            i = random.randint(0, len(chars)-1)
            chars[i] = random.choice(string.printable)
        return "".join(chars)

    return base


def run_program(stdin_data: str) -> Dict[str, Any]:
    """
    Run the vulnerable program and detect crashes.
    """
    try:
        result = subprocess.run(
            ["python", "test_targets/test.py"],
            input=stdin_data,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SEC
        )
    except subprocess.TimeoutExpired:
        return {
            "crashed": False,
            "timeout": True,
            "exit_code": None,
            "stdout": "",
            "stderr": "Timeout"
        }

    crashed = False

    if result.returncode != 0:
        crashed = True

    if "Traceback" in result.stderr or "Exception" in result.stderr:
        crashed = True

    return {
        "crashed": crashed,
        "timeout": False,
        "exit_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr
    }


def fuzz_from_seeds(seeds_file: str, output_file: str):
    seeds = json.loads(Path(seeds_file).read_text())

    all_results = []
    interesting = []

    for seed in seeds:
        seed_id = seed["id"]
        sink = seed["sink"]
        category = seed["category"]
        input_index = seed["input_index"]
        base_payloads = seed["payloads"]

        print(f"[+] Fuzzing {sink} (category={category}, input={input_index})")

        for base in base_payloads:
            # Original payload
            stdin = build_stdin(base, input_index)
            res = run_program(stdin)

            record = {
                "seed_id": seed_id,
                "sink": sink,
                "category": category,
                "payload": base,
                "mutated": False,
                "input_index": input_index,
                "result": res
            }

            all_results.append(record)

            if res["crashed"]:
                interesting.append(record)

            # Mutations
            for _ in range(MAX_MUTATIONS_PER_SEED):
                mutated = mutate_payload(base, category)
                stdin = build_stdin(mutated, input_index)
                res = run_program(stdin)

                record = {
                    "seed_id": seed_id,
                    "sink": sink,
                    "category": category,
                    "payload": mutated,
                    "mutated": True,
                    "input_index": input_index,
                    "result": res
                }

                all_results.append(record)

                if res["crashed"]:
                    interesting.append(record)

    Path(output_file).write_text(json.dumps({
        "all_results": all_results,
        "interesting": interesting
    }, indent=2))

    print(f"\n[✓] Fuzzing finished")
    print(f"    Total runs: {len(all_results)}")
    print(f"    Crashes / errors: {len(interesting)}")
    print(f"    Output saved → {output_file}")


if __name__ == "__main__":
    Path("outputs").mkdir(exist_ok=True)
    fuzz_from_seeds("outputs/seeds.json", "outputs/fuzz_results.json")
