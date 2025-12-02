import json
import os
from pathlib import Path
from typing import List, Dict, Any

from dotenv import load_dotenv
import google.generativeai as genai

# ----------------- Logging Helper ----------------- #
def LOG(msg):
    print(f"[LLM_SEED_GEN] {msg}")

LOG("Starting file load")

load_dotenv()
LOG("Environment variables loaded")

genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
LOG("Gemini API configured")

model = genai.GenerativeModel("gemini-flash-latest")
LOG("Gemini model initialized")

def infer_input_index(finding: Dict[str, Any]) -> int:
    """
    Map sink to which input() call in main() we want to fuzz.
    0-based index:
      0 -> first input()   (command)
      1 -> second input()  (filename)
      2 -> third input()   (username)
      3 -> fourth input()  (expression)
    """
    sink = finding.get("sink", "")
    func = finding.get("function", "")

    if sink == "os.system" and func == "execute_system_command":
        return 0  # "Enter command: "
    if sink == "open":
        return 1  # "Enter filename: "
    if sink == "execute":
        return 2  # "Enter username: "
    if sink == "eval":
        return 3  # "Enter expression to evaluate: "
    # default: fuzz first input
    return 0


def sink_category(finding: Dict[str, Any]) -> str:
    """
    Group sinks into categories: command, path, sql, eval, yaml, pickle, xml, other.
    """
    sink = finding.get("sink", "")
    if sink == "os.system":
        return "command"
    if sink == "open":
        return "path"
    if sink == "execute":
        return "sql"
    if sink == "eval":
        return "eval"
    if sink == "pickle.loads":
        return "pickle"
    if sink == "yaml.load":
        return "yaml"
    if sink == "ET.fromstring":
        return "xml"
    return "other"


def build_prompt_for_finding(finding: Dict[str, Any]) -> str:
    """
    Build a sink-specific prompt to get high-quality seeds.
    """
    cat = sink_category(finding)
    func = finding.get("function")
    sink = finding.get("sink")
    tainted_exprs = finding.get("tainted_exprs", [])
    conditions = finding.get("conditions", [])

    cond_text = "\n".join(f"- {c}" for c in conditions) if conditions else "None"
    taint_text = "\n".join(f"- {t}" for t in tainted_exprs) if tainted_exprs else "Unknown"

    base = f"""
You are a security testing assistant. We are fuzzing a Python program.

Function: {func}
Sink: {sink}
Tainted expressions flowing into this sink:
{taint_text}

Conditions guarding this sink (if any):
{cond_text}

Generate a JSON array (list) of 10–15 diverse payload strings that try to trigger security issues and edge cases.
Return ONLY the JSON array, with no extra text.
"""

    # Add category-specific guidance
    if cat == "command":
        base += """
The sink executes shell commands (command injection).
Include:
- simple commands (e.g. "ls")
- chained commands ("ls && whoami", "echo test; id")
- attempts to read sensitive files ("cat /etc/passwd")
- payloads with shell metacharacters: ; && || | & > < ` $ ( ) '
- some invalid commands to trigger errors.
All payloads should be under ~80 characters.
"""
    elif cat == "path":
        base += """
The sink opens files based on user-controlled paths (path traversal).
Include:
- simple filenames ("notes.txt", "data.txt")
- absolute paths ("/etc/passwd")
- relative traversal ("../../../../etc/passwd")
- weird encodings and dots ("..%2f..%2fetc/passwd", "./././config.yaml")
Some should be valid files, others should likely fail.
"""
    elif cat == "sql":
        base += """
The sink executes an SQL query built by string concatenation (possible SQL injection).
Include:
- typical usernames ("alice", "bob")
- injection patterns ("' OR '1'='1", "'; DROP TABLE users;--")
- attempts to comment out rest of query ("admin'--")
- payloads with quotes and semicolons.
All payloads should be relatively short (<80 chars).
"""
    elif cat == "eval":
        base += """
The sink evaluates Python expressions with eval().
Include:
- simple expressions ("1+1", "2**8")
- expressions that raise errors ("1/0", "int('not_a_number')")
- expressions that access builtins or __import__ to run code (if possible).
Keep them as single-line Python expressions.
"""
    # other categories (pickle, yaml, xml) could be expanded if reachable from main()

    LOG(f"Prompt built for sink {sink} in function {func}")
    return base.strip()


def call_llm_for_payloads(prompt: str) -> List[str]:
    """
    Call Gemini; on failure, fall back to some hard-coded seeds.
    Tries to be robust to weird finish_reason values.
    """
    try:
        LOG("Calling Gemini API")

        resp = model.generate_content(
            prompt,
            generation_config={
                "temperature": 0.5,
            },
        )

        if not getattr(resp, "candidates", None):
            print("[WARN] Gemini returned no candidates; using fallback seeds.")
            return []

        cand = resp.candidates[0]
        fr = getattr(cand, "finish_reason", None)
        # Just log, don't automatically treat non-STOP as fatal
        if fr is not None:
            print(f"[INFO] Gemini finish_reason={fr}")

        # Safely pull text from parts
        content = getattr(cand, "content", None)
        parts = getattr(content, "parts", []) if content is not None else []

        texts: List[str] = []
        for p in parts:
            t = getattr(p, "text", None)
            if t:
                texts.append(t)

        if not texts:
            print("[WARN] Gemini returned empty text parts; using fallback seeds.")
            return []

        raw_text = "".join(texts).strip()
        LOG("Raw model output received")

        # Strip ```json fences if the model adds them
        if raw_text.startswith("```"):
            LOG("Stripping markdown fences from model output")
            raw_text = raw_text.strip("`")
            if "\n" in raw_text:
                first, rest = raw_text.split("\n", 1)
                if first.strip().lower().startswith("json"):
                    raw_text = rest.strip()

        data = json.loads(raw_text)

        if isinstance(data, list):
            LOG(f"Parsed {len(data)} payloads")
            return [str(x) for x in data]

        if isinstance(data, dict) and isinstance(data.get("payloads"), list):
            LOG(f"Parsed {len(data['payloads'])} payloads (nested)")
            return [str(x) for x in data["payloads"]]

        print("[WARN] Gemini JSON structure unexpected; using fallback seeds.")
        return []

    except Exception as e:
        print(f"[WARN] Gemini call failed ({e}); using fallback seeds.")
        return []


def fallback_payloads(cat: str) -> List[str]:
    """
    Hard-coded seed payloads if LLM is unavailable.
    """
    LOG(f"Using fallback payloads for category {cat}")

    if cat == "command":
        return [
            "ls",
            "whoami",
            "ls && whoami",
            "echo test; id",
            "; cat /etc/passwd",
            "mkdir /tmp/pwned",
        ]
    if cat == "path":
        return [
            "data.txt",
            "/etc/passwd",
            "../secret.txt",
            "../../../../../etc/shadow",
            "C:\\Windows\\system.ini",
        ]
    if cat == "sql":
        return [
            "alice",
            "admin",
            "' OR '1'='1",
            "admin'--",
            "'; DROP TABLE users;--",
        ]
    if cat == "eval":
        return [
            "1+1",
            "2**16",
            "1/0",
            "int('not_a_number')",
            "__import__('os').system('ls')",
        ]
    return ["test"]


def generate_seeds(analysis_path: str, seeds_path: str):
    LOG(f"Loading analysis file {analysis_path}")

    findings = json.loads(Path(analysis_path).read_text())
    seeds = []

    LOG(f"{len(findings)} findings loaded")

    for i, f in enumerate(findings):
        LOG(f"Processing finding {i}")

        cat = sink_category(f)
        prompt = build_prompt_for_finding(f)

        payloads = call_llm_for_payloads(prompt)
        if not payloads:
            payloads = fallback_payloads(cat)

        seeds.append({
            "id": f"finding-{i}",
            "file": f["file"],
            "function": f.get("function"),
            "sink": f.get("sink"),
            "category": cat,
            "input_index": infer_input_index(f),
            "conditions": f.get("conditions", []),
            "payloads": payloads,
        })

    Path(seeds_path).write_text(json.dumps(seeds, indent=2))
    print(f"[+] Wrote {len(seeds)} seed groups to {seeds_path}")
    return seeds


if __name__ == "__main__":
    analysis_file = "outputs/analysis.json"
    seeds_file = "outputs/seeds.json"
    Path("outputs").mkdir(exist_ok=True)

    LOG("Seed generation started")
    generate_seeds(analysis_file, seeds_file)
    LOG("Seed generation finished")
