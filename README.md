# AI-Guided SAST Fuzzer

An end-to-end **Static Application Security Testing (SAST) Scanner** that combines:

✅ AST-based static analysis  
✅ AI-driven / heuristic seed generation  
✅ Directed fuzzing  
✅ Automated Proof-of-Vulnerability reporting  

Built for the interview challenge: *SAST Scanner Builder*.

---

# 📌 Project Overview

This project demonstrates an AI-aided security scanner that:

1. **Statically reads vulnerable source code**
2. **Detects dangerous sinks**
3. **Generates exploit inputs** (LLM-assisted or fallback)
4. **Fuzzes execution paths**
5. **Extracts exploitation proof**
6. **Generates a human-readable vulnerability report**

Target: a deliberately vulnerable Python program (`test.py`) containing:

- Command injection
- SQL injection
- Unsafe deserialization
- Unsafe YAML loading
- XML parsing risks
- Arbitrary file read
- Dangerous `eval()`

---

# 🏗 Architecture


┌────────────────────────────────────────┐
│ test_targets/test.py                   │
└─────────────────┬──────────────────────┘
│
▼
┌──────────────────────────────────────────────┐
│ static_analyzer.py │ → outputs/analysis.json │ 
└─────────────────┬────────────────────────────┘
│
▼
┌────────────────────────────────────────┐
│ llm_seed_gen.py → outputs/seeds.json   │
└─────────────────┬──────────────────────┘
│
▼
┌────────────────────────────────────────┐
│ fuzzer.py → outputs/fuzz_results.json  │
└─────────────────┬──────────────────────┘
│
▼
┌────────────────────────────────────────┐
│ reporter.py → outputs/report.md.       │
└─────────────────┬──────────────────────┘

---

# 🔍 Static Analysis

The scanner parses code using Python's `ast` module.

### Sources Identified
User-controlled data from:
```python
input()

cat << 'EOF' > README.md
# 🛡️ AI-Guided SAST Fuzzer  
### Context-Aware Static Analysis + LLM-Assisted Directed Fuzzing

An advanced **Static Application Security Testing (SAST) + Directed Fuzzer** that finds real vulnerabilities by tracking tainted data flows, generating intelligent attack payloads, and executing exploits automatically.

Unlike traditional fuzzers that rely on random inputs, this tool works like a real attacker:
- Traces **untrusted inputs → vulnerable sinks**
- Builds **context-aware payloads**
- Executes controlled exploits
- Produces professional vulnerability reports

---

## 🚨 Dangerous Sinks Detected

| Sink | Risk |
|------|------|
| `os.system()` | Command Injection |
| `open()` | Path Traversal |
| `cursor.execute()` | SQL Injection |
| `eval()` | Code Execution |
| `pickle.loads()` | Deserialization |
| `yaml.load()` | Deserialization |
| `xml.etree.fromstring()` | XML attacks |

---

## 🔍 Taint Tracking Engine

The analyzer builds data-flow chains like:

\`\`\`
input() → variable assignment → vulnerable sink
\`\`\`

Each vulnerability contains:

- File name
- Line number
- Function name
- Sink name
- Flow conditions
- Tainted variables

---

## 🧠 Seed Generation (LLM + Heuristics)

Payload generation uses:

✅ Google Gemini (if API key present)  
✅ Built-in payloads (always available)  

### Examples

### Command Injection
\`\`\`
ls && whoami
echo test; id
; cat /etc/passwd
\`\`\`

### SQL Injection
\`\`\`
' OR '1'='1
admin' --
'; DROP TABLE users; --
\`\`\`

### Eval Injection
\`\`\`
1/0
__import__('os').system('ls')
\`\`\`

### Path Traversal
\`\`\`
../../etc/passwd
C:\Windows\system.ini
\`\`\`

---

## 💣 Directed Fuzzing

This scanner:

✅ Fuzzes only vulnerable inputs  
✅ Applies category-specific mutations  
✅ Builds valid stdin streams  
✅ Executes with subprocess.run()  
✅ Captures return codes, stdout, stderr  
✅ Logs every attempt  

Each seed produces:

- Crashes
- Errors
- Exploitation output
- Runtime exceptions

---

## 📄 Automatic Reporting

\`reporter.py\` generates:

\`\`\`
outputs/report.md
\`\`\`

### Report Includes:

✅ Vulnerability list  
✅ Severity classification  
✅ Proof-of-vulnerability payloads  
✅ Output excerpts  
✅ Execution behavior analysis  

---

## 🧪 Setup & Run

### 1. Clone Repo

\`\`\`bash
git clone https://github.com/GurmanKD/AI-Guided-SAST-Fuzzer
cd AI-Guided-SAST-Fuzzer
\`\`\`

---

### 2. Setup Environment

\`\`\`bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
\`\`\`

---

### 3. Configure Gemini (Optional)

Create a \`.env\` file:

\`\`\`
GEMINI_API_KEY=your_real_key_here
\`\`\`

---

### 4. Initialize Database

\`\`\`bash
python init_db.py
\`\`\`

Creates a SQLite DB:

| username | password |
|----------|----------|
| admin | admin123 |
| alice | alice123 |
| bob | bob123 |

---

### 5. Run Full Pipeline

\`\`\`bash
python src/main.py
\`\`\`

Or run step-by-step:

\`\`\`bash
python src/static_analyzer.py
python src/llm_seed_gen.py
python src/fuzzer.py
python src/reporter.py
\`\`\`

---

## 📊 Output Files

Generated inside:

\`\`\`
outputs/
\`\`\`

| File | Purpose |
|------|--------|
| analysis.json | Static analysis |
| seeds.json | Attack payloads |
| fuzz_results.json | Execution logs |
| report.md | Final report |

---

## 🔐 Security Guarantees

✅ API key not committed  
✅ .env ignored via .gitignore  
✅ Database generated at runtime  
✅ Output files excluded from Git  

---

## 🧠 Why This Works

This is not random fuzzing.

It is:

• Taint-aware  
• Context-aware  
• Sink-aware  
• Repeatable  
• Automated  

It simulates:

**"What would a real attacker try first?"**

---

## 🏆 Skills Demonstrated

- Static analysis
- Python AST
- Taint tracking
- LLM integration
- Fuzzing strategy
- Vulnerability research
- Exploit engineering
- Secure secrets handling
- Automated reporting

---

## ⭐ Like this project?

Give it a star ⭐ and feel free to contribute.
EOF
