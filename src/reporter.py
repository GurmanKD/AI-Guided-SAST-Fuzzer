import json
from pathlib import Path
from typing import Any, Dict, List, Tuple


ANALYSIS_PATH = "outputs/analysis.json"
FUZZ_RESULTS_PATH = "outputs/fuzz_results.json"
REPORT_PATH = "outputs/report.md"


def load_json(path: str) -> Any:
    p = Path(path)
    if not p.exists():
        print(f"[!] {path} not found")
        return None
    return json.loads(p.read_text())


def classify_run(rec: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Decide if a fuzzing run is interesting (vulnerability-relevant),
    and return (is_interesting, reason).
    We look at both crashes and semantic signals in stdout/stderr.
    """
    sink = rec.get("sink")
    payload = rec.get("payload", "")
    res = rec.get("result", {})
    stdout = res.get("stdout", "") or ""
    stderr = res.get("stderr", "") or ""
    crashed = res.get("crashed", False)
    timeout = res.get("timeout", False)

    if timeout:
        return True, "Program timeout (potential hang / DoS)"

    if crashed:
        # First line of stderr is usually the exception type.
        first_line = stderr.strip().splitlines()[0] if stderr else "Crash"
        return True, f"Crash: {first_line}"

    # Even if not crashed, some behaviors are clearly exploitable.

    # Command injection: os.system
    if sink == "os.system":
        # If we see typical sensitive outputs, consider it exploited
        if "uid=" in stdout or "gid=" in stdout or "/etc/passwd" in stdout or "User Database" in stdout:
            return True, "Command injection: shell executed attacker-controlled commands"
        # Also: if stderr shows shell syntax errors, it proves input is interpreted as shell
        if "sh:" in stderr:
            return True, "Shell interpreted input (syntax error shows code execution surface)"

    # Path-related open()
    if sink == "open":
        if "No such file or directory" in stderr or "Permission denied" in stderr:
            return True, "File system probing via attacker-controlled path"

    # SQL execution
    if sink and "execute" in sink:
        if "sqlite3." in stderr:
            return True, "SQL error due to attacker-controlled query string"

    # eval()
    if sink == "eval":
        if "Traceback" in stderr or "Error" in stderr:
            return True, "Eval executed attacker-controlled expression (exception shows code path reached)"

    # pickle / yaml / xml could also be flagged, but your current test.py
    # doesn't yet fuzz those inputs via input(), so we skip here.

    return False, ""


def group_static_by_sink(static_findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for f in static_findings:
        sink = f.get("sink", "unknown")
        grouped.setdefault(sink, []).append(f)
    return grouped


def group_dynamic_by_sink(all_runs: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for rec in all_runs:
        sink = rec.get("sink", "unknown")
        grouped.setdefault(sink, []).append(rec)
    return grouped


def vuln_description_for_sink(sink: str) -> str:
    if sink == "os.system":
        return "Command injection via shell command constructed from untrusted input."
    if sink == "open":
        return "Potential path traversal / arbitrary file read via attacker-controlled filename."
    if sink == "eval":
        return "Arbitrary code execution via eval() on untrusted expression."
    if "execute" in sink:
        return "SQL injection via string-concatenated query and attacker-controlled parameters."
    if sink == "pickle.loads":
        return "Arbitrary code execution via unsafe deserialization (pickle.loads) of untrusted data."
    if sink == "yaml.load":
        return "Unsafe YAML deserialization via yaml.load on untrusted input."
    if sink == "ET.fromstring":
        return "XML parsing on untrusted data (potential XXE or parser abuse)."
    return "Suspicious sink called with attacker-controlled data."


def severity_for_sink(sink: str) -> str:
    if sink in ("os.system", "eval", "pickle.loads", "yaml.load"):
        return "High"
    if "execute" in sink or sink == "open":
        return "Medium–High"
    return "Medium"


def render_pov_entries(records: List[Dict[str, Any]], max_per_sink: int = 5) -> str:
    """
    Take interesting dynamic records for one sink and render as a Markdown table.
    Deduplicate by payload.
    """
    lines = []
    lines.append("| Payload | Interesting behavior |")
    lines.append("|---------|----------------------|")

    seen_payloads = set()

    for rec in records:
        payload = rec.get("payload", "")
        if payload in seen_payloads:
            continue
        seen_payloads.add(payload)

        _, reason = classify_run(rec)
        res = rec.get("result", {})
        stdout = (res.get("stdout") or "").strip().replace("\n", " ")
        stderr = (res.get("stderr") or "").strip().replace("\n", " ")

        # Shorten outputs for table
        def shorten(s: str, n: int = 120) -> str:
            return s if len(s) <= n else s[:n] + "..."

        details = reason
        if stdout:
            details += f" | stdout: {shorten(stdout)}"
        if stderr:
            if details:
                details += " "
            details += f"| stderr: {shorten(stderr)}"

        lines.append(f"| `{payload}` | {details} |")

        if len(seen_payloads) >= max_per_sink:
            break

    if len(lines) == 2:
        return "_No dynamic PoV inputs recorded for this sink._\n"

    return "\n".join(lines) + "\n"


def generate_report(analysis_path: str = ANALYSIS_PATH,
                    fuzz_results_path: str = FUZZ_RESULTS_PATH,
                    report_path: str = REPORT_PATH):
    static_findings = load_json(analysis_path) or []
    fuzz_data = load_json(fuzz_results_path) or {}
    all_runs = fuzz_data.get("all_results", [])

    static_by_sink = group_static_by_sink(static_findings)
    dynamic_by_sink = group_dynamic_by_sink(all_runs)

    # Recompute which dynamic runs are interesting (not only crashes).
    interesting_by_sink: Dict[str, List[Dict[str, Any]]] = {}
    for sink, records in dynamic_by_sink.items():
        for rec in records:
            interesting, _ = classify_run(rec)
            if interesting:
                interesting_by_sink.setdefault(sink, []).append(rec)

    md_lines: List[str] = []

    md_lines.append("# SAST + Fuzzing Report for `test.py`\n")
    md_lines.append("This report combines **static analysis** (SAST) with **directed fuzzing** results.")
    md_lines.append("The scanner traced untrusted inputs from `input()` calls in `main()` to dangerous sinks, ")
    md_lines.append("then generated targeted payloads and executed the program to observe crashes and ")
    md_lines.append("security-relevant behavior.\n")

    # High-level summary
    md_lines.append("## Summary\n")
    md_lines.append(f"- Static findings: **{len(static_findings)}** potential sink usages")
    md_lines.append(f"- Dynamic runs: **{len(all_runs)}** program executions")
    md_lines.append(f"- Interesting dynamic behaviors: **{sum(len(v) for v in interesting_by_sink.values())}**\n")

    # Per-sink sections
    for sink in sorted(static_by_sink.keys()):
        md_lines.append(f"---\n")
        md_lines.append(f"## Sink: `{sink}`\n")

        md_lines.append(f"**Description:** {vuln_description_for_sink(sink)}")
        md_lines.append(f"**Severity (qualitative):** {severity_for_sink(sink)}\n")

        md_lines.append("### Static Findings\n")

        for f in static_by_sink[sink]:
            file = f.get("file", "test.py")
            func = f.get("function", "<unknown>")
            line = f.get("line", "?")
            expr = f.get("tainted_expr", "")
            conditions = f.get("conditions", [])

            md_lines.append(f"- File: `{file}`, function: `{func}`, line: `{line}`")
            if expr:
                md_lines.append(f"  - Tainted data reaching sink via: `{expr}`")
            if conditions:
                cond_str = "; ".join(conditions)
                md_lines.append(f"  - Under conditions: {cond_str}")

        md_lines.append("\n### Dynamic Proof-of-Vulnerability Inputs\n")

        dyn_records = interesting_by_sink.get(sink, [])
        md_lines.append(render_pov_entries(dyn_records))

    Path(report_path).write_text("\n".join(md_lines), encoding="utf-8")
    print(f"[✓] Report written to {report_path}")


if __name__ == "__main__":
    Path("outputs").mkdir(exist_ok=True)
    generate_report()
