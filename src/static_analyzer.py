# src/static_analyzer.py
"""
Static analyzer for Python test file.

Goal:
- Parse test_targets/test.py
- Find flows of user-controlled data (input()) into dangerous sinks:
  - os.system (command injection)
  - open        (path traversal / arbitrary read)
  - eval        (code execution)
  - pickle.loads, yaml.load, ET.fromstring
  - cursor.execute (SQL injection)
- Emit a JSON list of findings into outputs/analysis.json

This is a *simple* taint analysis:
- We treat function parameters as potentially tainted.
- We taint variables assigned from input().
- We propagate taint via simple assignments (x = y).
- We consider an expression tainted if it uses tainted names.
"""

import ast
import json
from pathlib import Path
from typing import Optional, List, Set, Dict, Any

# ----------------- Logging Helper ----------------- #
def LOG(msg):
    print(f"[STATIC_ANALYZER] {msg}")

# --- Configuration: sources & sinks tailored to your test.py --- #

# Direct function calls that are dangerous, e.g. eval(expr), open(filename)
SINK_FUNCS_SIMPLE = {
    "eval",   # evaluate_user_expression
    "open",   # read_user_file
}

# Module.attribute sinks: module.func(...)
SINK_ATTRS = {
    ("os", "system"),        # execute_system_command, backup_user_data
    ("pickle", "loads"),     # process_serialized_data
    ("yaml", "load"),        # load_configuration
    ("ET", "fromstring"),    # parse_xml_content (xml.etree.ElementTree as ET)
}

# Functions that produce user-controlled / tainted data
SOURCE_FUNCS = {
    "input",   # all the input() calls in main()
}


class PythonStaticAnalyzer(ast.NodeVisitor):
    """
    Walks the AST, tracks tainted variables, and records when tainted
    data reaches dangerous sinks.
    """

    def __init__(self, code: str, filename: str):
        self.code = code
        self.filename = filename
        self.tree = ast.parse(code)

        # Current context
        self.current_function: Optional[str] = None

        # Stack because functions can nest (inner defs, lambdas, etc.)
        self.tainted_vars_stack: List[Set[str]] = []
        self.conditions_stack: List[List[str]] = []

        # Collected findings
        self.findings: List[Dict[str, Any]] = []

        LOG(f"Initialized analyzer for {filename}")

    # ----------------- Utility helpers ----------------- #

    def _current_tainted(self) -> Set[str]:
        """Return the current function's tainted variable set."""
        return self.tainted_vars_stack[-1] if self.tainted_vars_stack else set()

    def _current_conditions(self) -> List[str]:
        """Return the list of conditions guarding the current location."""
        return self.conditions_stack[-1] if self.conditions_stack else []

    def _expr_to_str(self, node: ast.AST) -> str:
        """Convert an AST node back to a string (approx)."""
        if hasattr(ast, "unparse"):
            try:
                return ast.unparse(node)
            except Exception:
                return repr(node)
        return repr(node)

    def _expr_is_tainted(self, node: ast.AST, tainted: Set[str]) -> bool:
        """
        Determine if an expression is tainted.
        We recursively look for tainted variable names inside.
        """
        # Name: check if this variable is tainted
        if isinstance(node, ast.Name):
            return node.id in tainted

        # Binary operation: "echo " + user_input, "SELECT ..." + username
        if isinstance(node, ast.BinOp):
            return (self._expr_is_tainted(node.left, tainted) or
                    self._expr_is_tainted(node.right, tainted))

        # f-string: f"Hello {username}"
        if isinstance(node, ast.JoinedStr):
            return any(self._expr_is_tainted(value, tainted)
                       for value in node.values)

        if isinstance(node, ast.FormattedValue):
            return self._expr_is_tainted(node.value, tainted)

        # Function call: propagate into args
        if isinstance(node, ast.Call):
            return any(self._expr_is_tainted(arg, tainted)
                       for arg in node.args)

        # Subscript: arr[i], sys.argv[1]
        if isinstance(node, ast.Subscript):
            return self._expr_is_tainted(node.value, tainted)

        # Default: not obviously tainted
        return False

    # ----------------- Visitor methods ----------------- #

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """
        Entering a function:
        - Set current_function
        - Initialize tainted variables (we treat all parameters as potentially tainted)
        - Initialize conditions
        """
        prev_function = self.current_function
        self.current_function = node.name

        # Over-approximation: all params might come from user input
        tainted_params = {arg.arg for arg in node.args.args}

        self.tainted_vars_stack.append(tainted_params)
        self.conditions_stack.append([])

        LOG(f"Entering function {node.name} at line {node.lineno}")
        LOG(f"Initial tainted params: {tainted_params}")

        # Visit body
        self.generic_visit(node)

        # Pop context
        self.tainted_vars_stack.pop()
        self.conditions_stack.pop()
        self.current_function = prev_function

        LOG(f"Exiting function {node.name}")

    def visit_Assign(self, node: ast.Assign):
        """
        Handle assignments:
        - If RHS is a source, taint LHS variables.
        - If RHS is a tainted variable, taint LHS variables (simple propagation).
        """
        current_tainted = self._current_tainted()

        # Case 1: x = input(...)
        if isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name):
            if node.value.func.id in SOURCE_FUNCS:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        current_tainted.add(target.id)
                        LOG(f"Taint source: {target.id} = input() at line {node.lineno}")

        # Case 2: x = y where y is tainted
        if isinstance(node.value, ast.Name) and node.value.id in current_tainted:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    current_tainted.add(target.id)
                    LOG(f"Taint propagated: {target.id} = {node.value.id} at line {node.lineno}")

        self.generic_visit(node)

    def visit_If(self, node: ast.If):
        """
        Track conditions guarding sinks, but only inside functions.
        (We ignore the module-level `if __name__ == "__main__":`.)
        """
        if self.current_function is None:
            # Top-level if – just traverse
            self.generic_visit(node)
            return

        cond_str = self._expr_to_str(node.test)
        self._current_conditions().append(cond_str)

        LOG(f"Entering IF condition: {cond_str} at line {node.lineno}")

        # Visit body under this condition
        for stmt in node.body:
            self.visit(stmt)

        # Remove condition after body
        self._current_conditions().pop()
        LOG(f"Leaving IF condition: {cond_str}")

        # Visit else/elif without that condition (simple model)
        for stmt in node.orelse:
            self.visit(stmt)

    def visit_Call(self, node: ast.Call):
        """
        Called for every function call.
        Decide if this call is a sink; if yes, check if its args are tainted.
        """
        sink_name: Optional[str] = None
        sink_module: Optional[str] = None

        # Case 1: simple function call, e.g. eval(expr), open(filename)
        if isinstance(node.func, ast.Name):
            if node.func.id in SINK_FUNCS_SIMPLE:
                sink_name = node.func.id

        # Case 2: attribute call, e.g. os.system(cmd), pickle.loads(data)
        elif isinstance(node.func, ast.Attribute):
            attr = node.func.attr

            # Special case: any .execute(...) is treated as SQL sink
            if attr == "execute":
                sink_name = "execute"
                sink_module = None
            else:
                # module.func
                if isinstance(node.func.value, ast.Name):
                    mod = node.func.value.id
                    if (mod, attr) in SINK_ATTRS:
                        sink_name = attr
                        sink_module = mod

        # If this is a sink, analyze tainted args
        if sink_name is not None:
            LOG(f"Sink detected: {(sink_module + '.' if sink_module else '')}{sink_name} at line {node.lineno}")
            self._handle_sink_call(node, sink_name, sink_module)

        # Continue walking
        self.generic_visit(node)

    # ----------------- Sink handling ----------------- #

    def _handle_sink_call(self, node: ast.Call, sink_name: str, sink_module: Optional[str]):
        """
        Check if any argument to this sink call is tainted.
        If yes, record a finding.
        """
        tainted = self._current_tainted()
        tainted_exprs: List[str] = []

        for arg in node.args:
            if self._expr_is_tainted(arg, tainted):
                expr = self._expr_to_str(arg)
                tainted_exprs.append(expr)
                LOG(f"Tainted argument to sink {sink_name}: {expr} at line {node.lineno}")

        if not tainted_exprs:
            return  # no tainted data reaching this sink (in our simple model)

        LOG(f"Vulnerability confirmed in function {self.current_function} for sink {sink_name}")

        finding = {
            "file": self.filename,
            "function": self.current_function,
            "sink": f"{sink_module + '.' if sink_module else ''}{sink_name}",
            "sink_call_line": node.lineno,
            "tainted_exprs": tainted_exprs,
            "conditions": list(self._current_conditions()),
            # Simple assumption: all taint originates from input()
            "source": "input",
            "source_details": {
                "kind": "stdin",
                "expression": "input()",
                "line": None,
            },
        }
        self.findings.append(finding)

    # ----------------- Public API ----------------- #

    def analyze(self) -> List[Dict[str, Any]]:
        """Run the analysis and return the list of findings."""
        LOG("Starting AST traversal")
        self.visit(self.tree)
        LOG("Finished AST traversal")
        return self.findings


def analyze_file(filepath: str, output_path: str):
    """
    Convenience function:
    - read file
    - run analyzer
    - write JSON findings to output_path
    """
    LOG(f"Reading source file {filepath}")
    code = Path(filepath).read_text()

    analyzer = PythonStaticAnalyzer(code, filepath)
    findings = analyzer.analyze()

    Path(output_path).write_text(json.dumps(findings, indent=2))
    LOG(f"Results written to {output_path}")
    LOG(f"Total findings: {len(findings)}")
    return findings


if __name__ == "__main__":
    import sys

    # Default paths for quick testing
    input_file = sys.argv[1] if len(sys.argv) > 1 else "test_targets/test.py"
    output_file = sys.argv[2] if len(sys.argv) > 2 else "outputs/analysis.json"

    Path("outputs").mkdir(exist_ok=True)

    LOG("Static analysis started")
    analyze_file(input_file, output_file)
    LOG("Static analysis finished")
