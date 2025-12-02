import json
import random
import string
import subprocess
from pathlib import Path
from typing import Dict, Any, List

# Logging helper
def LOG(msg: str):
    print(f"[FUZZER] {msg}")

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
        LOG(f"Building stdin for input_index={input_index} with payload={repr(payload)}")
        inputs[input_index] = payload
    else:
        LOG(f"Input index {input_index} out of range; using defaults")

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
    LOG(f"Mutating payload. Category={category}, Strategy={strategy}, Base={repr(base)}")

    if strategy == "append":
        if category == "command":
            mutated = base + random.choice(cmd_chars)
        elif category == "path":
            mutated = base + random.choice(path_parts)
        elif category == "sql":
            mutated = base + random.choice(sql_parts)
        elif category == "eval":
            mutated = base + random.choice(eval_parts)
        else:
            mutated = base + random.choice(string.punctuation)
        LOG(f"Append mutation result: {repr(mutated)}")
        return mutated

    if strategy == "prepend":
        if category == "command":
            mutated = random.choice(cmd_chars) + base
        elif category == "path":
            mutated = random.choice(path_parts) + base
        else:
            mutated = random.choice(string.punctuation) + base
        LOG(f"Prepend mutation result: {repr(mutated)}")
        return mutated

    if strategy == "repeat":
        mutated = (base * random.randint(1, 5))[:200]
        LOG(f"Repeat mutation result length={len(mutated)}")
        return mutated

    if strategy == "flip":
        if not base:
            LOG("Flip mutation skipped (empty base)")
            return base
        chars = list(base)
        flips = random.randint(1, max(1, len(chars)//3))
        for _ in range(flips):
            i = random.randint(0, len(chars)-1)
            chars[i] = random.choice(string.printable)
        mutated = "".join(chars)
        LOG(f"Flip mutation applied at {flips} positions")
        return mutated

    LOG("No mutation strategy matched; returning base")
    return base


def run_program(stdin_data: str) -> Dict[str, Any]:
    """
    Run the vulnerable program and detect crashes.
    """
    LOG("Running test_targets/test.py with generated stdin")
    try:
        result = subprocess.run(
            ["python", "test_targets/test.py"],
            input=stdin_data,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SEC
        )
    except subprocess.TimeoutExpired:
        LOG("Execution timed out")
        return {
            "crashed": False,
            "timeout": True,
            "exit_code": None,
            "stdout": "",
            "stderr": "Timeout"
        }

    crashed = False

    if result.returncode != 0:
        LOG(f"Non-zero exit code detected: {result.returncode}")
        crashed = True

    if "Traceback" in result.stderr or "Exception" in result.stderr:
        LOG("Exception/Traceback detected in stderr")
        crashed = True

    return {
        "crashed": crashed,
        "timeout": False,
        "exit_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr
    }


def fuzz_from_seeds(seeds_file: str, output_file: str):
    LOG(f"Loading seeds from {seeds_file}")
    seeds = json.loads(Path(seeds_file).read_text())

    all_results = []
    interesting = []

    LOG(f"Total seed groups: {len(seeds)}")

    for seed in seeds:
        seed_id = seed["id"]
        sink = seed["sink"]
        category = seed["category"]
        input_index = seed["input_index"]
        base_payloads = seed["payloads"]

        LOG(f"Starting fuzzing for seed_id={seed_id}, sink={sink}, category={category}, input_index={input_index}")
        print(f"[+] Fuzzing {sink} (category={category}, input={input_index})")

        for base in base_payloads:
            LOG(f"Using base payload: {repr(base)}")
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
                LOG("Crash detected with original payload")
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
                    LOG(f"Crash detected with mutated payload: {repr(mutated)}")
                    interesting.append(record)

    LOG(f"Writing fuzzing results to {output_file}")
    Path(output_file).write_text(json.dumps({
        "all_results": all_results,
        "interesting": interesting
    }, indent=2))

    print(f"\n[✓] Fuzzing finished")
    print(f"    Total runs: {len(all_results)}")
    print(f"    Crashes / errors: {len(interesting)}")
    print(f"    Output saved → {output_file}")
    LOG(f"Fuzzing finished. Total runs={len(all_results)}, crashes={len(interesting)}")


if __name__ == "__main__":
    Path("outputs").mkdir(exist_ok=True)
    LOG("Outputs directory ensured")
    fuzz_from_seeds("outputs/seeds.json", "outputs/fuzz_results.json")
    LOG("fuzz_from_seeds completed")
