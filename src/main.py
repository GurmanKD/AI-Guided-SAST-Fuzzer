from pathlib import Path
import subprocess


def run(cmd: list[str]):
    print(f"[+] Running: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)


if __name__ == "__main__":
    Path("outputs").mkdir(exist_ok=True)

    # 1) Static analysis
    run(["python", "src/static_analyzer.py"])

    # 2) Seed generation
    run(["python", "src/llm_seed_gen.py"])

    # 3) Fuzzing
    run(["python", "src/fuzzer.py"])

    # 4) Report
    run(["python", "src/reporter.py"])

    print("\n[✓] Full pipeline complete. See outputs/:")
    print("    - analysis.json")
    print("    - seeds.json")
    print("    - fuzz_results.json")
    print("    - report.md")
