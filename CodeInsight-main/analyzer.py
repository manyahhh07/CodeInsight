import ast
import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Issue:
    severity: str        # "error" | "warning" | "info"
    category: str
    message: str
    line: int | None = None
    suggestion: str | None = None
    fix_hint: str | None = None  # short code-level hint


@dataclass
class AnalysisResult:
    score: int
    language: str
    issues: list[Issue] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    naturalness_score: int = 100
    ai_likelihood_score: int = 0
    naturalness_reasons: list[str] = field(default_factory=list)
    ai_reasons: list[str] = field(default_factory=list)


# ──────────────────────────────────────────────
#  LANGUAGE-AGNOSTIC HELPERS
# ──────────────────────────────────────────────

GENERIC_NAMES = {
    "data", "info", "obj", "item", "thing", "stuff", "temp", "tmp",
    "result", "res", "val", "value", "var", "foo", "bar", "baz",
    "helper", "util", "manager", "handler", "processor", "service",
    "myfunction", "myclass", "myvar", "test1", "test2", "example",
    "doSomething", "do_something", "handleData", "handle_data",
    "processData", "process_data", "getData", "get_data",
    "doStuff", "do_stuff", "myMethod", "myFunc"
}

AI_BOILERPLATE_PATTERNS = [
    r'#\s*(step\s+\d+|todo|fixme|note|example|usage)',
    r'#\s*this (function|method|class|code)',
    r'#\s*returns?\s+.{0,30}$',
    r'#\s*initialize',
    r'#\s*main (function|entry)',
    r'\/\/\s*(step\s+\d+|todo|note|example)',
    r'\/\/\s*this (function|method|class)',
    r'\/\*\*\s*\n?\s*\*\s*@',  # overly formal JSDoc on simple funcs
]

SECRET_PATTERNS = [
    r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{3,}["\']',
    r'(?i)(api_key|apikey|secret|token)\s*=\s*["\'][^"\']{3,}["\']',
    r'(?i)(aws_access|private_key|auth_token)\s*=\s*["\'][^"\']{3,}["\']',
]


def _check_secrets(lines: list[str]) -> list[Issue]:
    issues = []
    for i, line in enumerate(lines, 1):
        for pattern in SECRET_PATTERNS:
            if re.search(pattern, line):
                issues.append(Issue(
                    "error", "security",
                    f"Possible hardcoded secret at line {i}.",
                    i,
                    "Move credentials to environment variables.",
                    "Use os.environ.get('MY_SECRET') or a .env file with python-dotenv."
                ))
    return issues


def _naturalness_and_ai(code: str, lines: list[str], language: str) -> tuple[int, int, list[str], list[str]]:
    """Returns (naturalness_score, ai_likelihood_score, naturalness_reasons, ai_reasons)."""
    nat_score = 100
    ai_score = 0
    nat_reasons = []
    ai_reasons = []

    words = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', code)
    identifiers = [w for w in words if len(w) > 1]

    # --- Generic name ratio ---
    generic_count = sum(1 for w in identifiers if w.lower() in GENERIC_NAMES)
    generic_ratio = generic_count / max(len(identifiers), 1)
    if generic_ratio > 0.15:
        nat_score -= 20
        ai_score += 25
        nat_reasons.append(f"High ratio of generic names (e.g. 'data', 'handler', 'result').")
        ai_reasons.append(f"{generic_count} generic placeholder names detected — common in AI-generated code.")

    # --- Comment quality: AI-style over-explanation ---
    boilerplate_comments = 0
    for line in lines:
        for pat in AI_BOILERPLATE_PATTERNS:
            if re.search(pat, line, re.IGNORECASE):
                boilerplate_comments += 1
    if boilerplate_comments >= 3:
        ai_score += 20
        ai_reasons.append("Comments read like auto-generated documentation (e.g. 'Step 1:', 'This function...').")
    elif boilerplate_comments == 0 and len(lines) > 20:
        nat_score -= 10
        nat_reasons.append("No inline comments in a sizeable file — harder to follow intent.")

    # --- Symmetry: suspiciously uniform line lengths ---
    code_line_lengths = [len(l) for l in lines if l.strip() and not l.strip().startswith(('#', '//', '/*', '*'))]
    if len(code_line_lengths) > 10:
        avg_len = sum(code_line_lengths) / len(code_line_lengths)
        variance = sum((l - avg_len) ** 2 for l in code_line_lengths) / len(code_line_lengths)
        if variance < 80 and avg_len > 30:
            ai_score += 15
            ai_reasons.append("Unusually uniform line lengths — a pattern common in AI-generated code.")

    # --- Perfect function symmetry ---
    func_patterns = len(re.findall(r'def |function |func |void |public ', code))
    return_patterns = len(re.findall(r'\breturn\b', code))
    if func_patterns > 2 and return_patterns == func_patterns:
        ai_score += 10
        ai_reasons.append("Every function has exactly one return — suspiciously symmetrical.")

    # --- No blank lines between logical sections ---
    consecutive_nonblank = 0
    max_consecutive = 0
    for line in lines:
        if line.strip():
            consecutive_nonblank += 1
            max_consecutive = max(max_consecutive, consecutive_nonblank)
        else:
            consecutive_nonblank = 0
    if max_consecutive > 20 and len(lines) > 30:
        nat_score -= 15
        nat_reasons.append("Long stretches of code with no blank lines — hard to visually parse.")

    # --- Naming consistency ---
    snake = len(re.findall(r'\b[a-z]+_[a-z]+\b', code))
    camel = len(re.findall(r'\b[a-z][A-Z][a-zA-Z]*\b', code))
    if snake > 3 and camel > 3:
        nat_score -= 15
        ai_score += 10
        nat_reasons.append("Mixed snake_case and camelCase naming — inconsistent style.")
        ai_reasons.append("Naming convention inconsistency can indicate pasted/merged code from different sources.")

    # --- Single-character meaningful names outside loops ---
    lone_chars = re.findall(r'\b(?<![a-zA-Z_])([a-ce-wyzA-CE-WYZ])\b(?!\w)', code)
    if len(set(lone_chars)) > 3:
        nat_score -= 10
        nat_reasons.append("Multiple single-letter variable names reduce readability.")

    # --- Positive naturalness signals ---
    descriptive = [w for w in identifiers if len(w) >= 6 and w.lower() not in GENERIC_NAMES]
    if len(descriptive) / max(len(identifiers), 1) > 0.6:
        nat_score = min(100, nat_score + 10)
        nat_reasons.insert(0, "Good use of descriptive, meaningful names.")

    return (
        max(0, min(100, nat_score)),
        max(0, min(100, ai_score)),
        nat_reasons,
        ai_reasons
    )


# ──────────────────────────────────────────────
#  PYTHON ANALYZER
# ──────────────────────────────────────────────

def _analyze_python(code: str, lines: list[str]) -> tuple[list[Issue], dict]:
    issues = []
    metrics = {}

    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return [Issue("error", "syntax", f"Syntax error at line {e.lineno}: {e.msg}", e.lineno,
                      "Fix the syntax error before analysis can continue.",
                      f"Check line {e.lineno} for mismatched brackets, missing colons, or bad indentation.")], {}

    metrics["total_lines"] = len(lines)
    metrics["blank_lines"] = sum(1 for l in lines if not l.strip())
    metrics["code_lines"] = metrics["total_lines"] - metrics["blank_lines"]

    # Cyclomatic complexity per function
    complexities = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            cc = 1
            for child in ast.walk(node):
                if isinstance(child, (ast.If, ast.While, ast.For, ast.ExceptHandler,
                                      ast.With, ast.Assert, ast.comprehension)):
                    cc += 1
                elif isinstance(child, ast.BoolOp):
                    cc += len(child.values) - 1
            complexities.append((node.name, cc, node.lineno))
            if cc > 10:
                issues.append(Issue(
                    "error", "complexity",
                    f"'{node.name}' has very high cyclomatic complexity ({cc}/10 max).",
                    node.lineno,
                    "Break into smaller, single-responsibility functions.",
                    f"# Extract branches into named helpers:\ndef check_X(): ...\ndef check_Y(): ..."
                ))
            elif cc > 5:
                issues.append(Issue(
                    "warning", "complexity",
                    f"'{node.name}' has moderate complexity ({cc}). Consider simplifying.",
                    node.lineno,
                    "Reduce nested conditionals using early returns or guard clauses.",
                    "# Use early return instead of deep nesting:\nif not valid: return\n# ... rest of logic"
                ))

    metrics["avg_complexity"] = round(sum(c for _, c, _ in complexities) / max(len(complexities), 1), 1)
    metrics["function_count"] = len(complexities)

    # Function length
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            fn_lines = (node.end_lineno or node.lineno) - node.lineno + 1
            if fn_lines > 50:
                issues.append(Issue(
                    "error", "smell",
                    f"'{node.name}' is {fn_lines} lines long (max 50 recommended).",
                    node.lineno,
                    "Extract sub-tasks into smaller helper functions.",
                    "# Split into focused functions:\ndef validate_input(x): ...\ndef process(x): ...\ndef format_output(x): ..."
                ))
            elif fn_lines > 30:
                issues.append(Issue(
                    "warning", "smell",
                    f"'{node.name}' is {fn_lines} lines. Consider splitting at 30+.",
                    node.lineno,
                    "Look for logical sections that could be extracted."
                ))

    # Too many parameters
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            n_args = len(node.args.args)
            if n_args > 5:
                issues.append(Issue(
                    "warning", "smell",
                    f"'{node.name}' has {n_args} parameters (max 5 recommended).",
                    node.lineno,
                    "Group related parameters into a dataclass or config dict.",
                    "@dataclass\nclass Config:\n    param1: str\n    param2: int\n\ndef my_func(config: Config): ..."
                ))

    # Single-letter variables outside loops
    loop_targets = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.For) and isinstance(node.target, ast.Name):
            loop_targets.add(id(node.target))
    for node in ast.walk(tree):
        if (isinstance(node, ast.Name) and id(node) not in loop_targets
                and len(node.id) == 1 and node.id.isalpha() and node.id != '_'
                and isinstance(node.ctx, ast.Store)):
            issues.append(Issue(
                "warning", "naming",
                f"Single-letter variable '{node.id}' used outside a loop.",
                getattr(node, 'lineno', None),
                "Use a name that communicates what this value represents.",
                f"# Instead of:\n{node.id} = ...\n# Use:\nuser_count = ...  # or whatever it represents"
            ))

    # Magic numbers
    magic = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            if node.value not in (0, 1, -1, 2, True, False):
                magic.append((node.value, getattr(node, 'lineno', None)))
    if len(magic) > 2:
        ex = magic[0]
        issues.append(Issue(
            "info", "style",
            f"Found {len(magic)} magic numbers (e.g. {ex[0]} at line {ex[1]}).",
            None,
            "Define named constants at the top of the file.",
            f"MAX_RETRIES = {ex[0]}  # at top of file\n# Then use MAX_RETRIES instead of {ex[0]}"
        ))

    # Docstring coverage
    funcs_classes = [n for n in ast.walk(tree)
                     if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
    public = [n for n in funcs_classes if not n.name.startswith('_')]
    documented = sum(1 for n in public if ast.get_docstring(n))
    metrics["docstring_coverage"] = round(documented / max(len(public), 1) * 100)
    if public and metrics["docstring_coverage"] < 50:
        issues.append(Issue(
            "warning", "documentation",
            f"Only {metrics['docstring_coverage']}% of public functions/classes are documented.",
            None,
            "Add docstrings to all public interfaces.",
            'def my_func(x: int) -> str:\n    """Convert integer to formatted string.\n    \n    Args:\n        x: The number to format.\n    Returns:\n        Formatted string.\n    """\n    ...'
        ))

    # Comment density
    comment_lines = sum(1 for l in lines if l.strip().startswith('#'))
    metrics["comment_ratio"] = round(comment_lines / max(len(lines), 1) * 100)
    if comment_lines == 0 and len(lines) > 10:
        issues.append(Issue(
            "info", "documentation",
            "No inline comments found in this file.",
            None,
            "Add comments to explain non-obvious logic and decisions.",
            "# Why this limit? API rate limit is 100 req/min per their docs\nMAX_REQUESTS = 100"
        ))

    # Nesting depth
    def max_depth(node, d=0):
        m = d
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.If, ast.For, ast.While, ast.With, ast.Try)):
                m = max(m, max_depth(child, d + 1))
            else:
                m = max(m, max_depth(child, d))
        return m
    metrics["max_nesting_depth"] = max_depth(tree)
    if metrics["max_nesting_depth"] > 4:
        issues.append(Issue(
            "warning", "complexity",
            f"Max nesting depth is {metrics['max_nesting_depth']} levels (max 4 recommended).",
            None,
            "Use early returns or extract nested blocks into functions.",
            "# Instead of:\nif a:\n    if b:\n        if c:\n            ...\n# Use:\nif not a: return\nif not b: return\nif not c: return\n..."
        ))

    # Duplicate code blocks
    stripped = [l.strip() for l in lines if l.strip() and not l.strip().startswith('#')]
    seen, dupes = {}, 0
    for i in range(len(stripped) - 3):
        block = "\n".join(stripped[i:i+3])
        if block in seen:
            dupes += 1
        seen[block] = i
    if dupes > 2:
        issues.append(Issue(
            "warning", "smell",
            f"Detected {dupes} potentially duplicated code blocks.",
            None,
            "Extract repeated logic into a shared helper function.",
            "# Before: copy-pasted logic\n# After:\ndef shared_logic(x):\n    # the repeated code\n    ...\n\n# Call it from both places"
        ))

    return issues, metrics


# ──────────────────────────────────────────────
#  JAVASCRIPT / TYPESCRIPT ANALYZER
# ──────────────────────────────────────────────

def _analyze_javascript(code: str, lines: list[str]) -> tuple[list[Issue], dict]:
    issues = []
    metrics = {
        "total_lines": len(lines),
        "blank_lines": sum(1 for l in lines if not l.strip()),
    }
    metrics["code_lines"] = metrics["total_lines"] - metrics["blank_lines"]

    # var usage
    var_lines = [(i+1, l) for i, l in enumerate(lines) if re.search(r'\bvar\b', l)]
    for lineno, _ in var_lines[:3]:
        issues.append(Issue(
            "warning", "style",
            f"'var' used at line {lineno}. Prefer 'const' or 'let'.",
            lineno,
            "Use 'const' for values that don't change, 'let' for variables.",
            "// Instead of: var count = 0;\nconst MAX = 10;  // never reassigned\nlet count = 0;   // reassigned later"
        ))

    # == instead of ===
    for i, line in enumerate(lines, 1):
        if re.search(r'(?<!=)==(?!=)', line) and '==' in line:
            issues.append(Issue(
                "warning", "style",
                f"Loose equality (==) at line {i}. Use strict equality (===).",
                i,
                "=== checks both value and type, avoiding unexpected coercions.",
                "// Instead of: if (x == '5')\nif (x === 5)  // strict: no type coercion"
            ))
            break

    # console.log left in
    console_lines = [i+1 for i, l in enumerate(lines) if 'console.log' in l]
    if console_lines:
        issues.append(Issue(
            "info", "style",
            f"console.log found at {len(console_lines)} line(s) — remove before production.",
            console_lines[0],
            "Remove debug logs or replace with a proper logging library.",
            "// Remove: console.log('debug:', value)\n// Or use: logger.debug('value', { value })"
        ))

    # Missing semicolons (simple heuristic)
    missing_semi = 0
    for line in lines:
        stripped = line.rstrip()
        if (stripped and not stripped.endswith((';', '{', '}', '(', ',', '//', '*'))
                and not stripped.startswith(('//', '/*', '*'))
                and len(stripped) > 5):
            missing_semi += 1
    if missing_semi > len(lines) * 0.3:
        issues.append(Issue(
            "info", "style",
            "Many lines appear to be missing semicolons.",
            None,
            "Be consistent — either always use semicolons or use a no-semi style with ESLint.",
            "// If using semicolons:\nconst x = 1;\nconst y = 2;\n\n// Or configure ESLint with 'semi: never'"
        ))

    # Callback hell (deep nesting of anonymous functions)
    nesting = 0
    max_nesting = 0
    for line in lines:
        nesting += line.count('function(') + line.count('=>')
        nesting -= line.count('}')
        nesting = max(0, nesting)
        max_nesting = max(max_nesting, nesting)
    metrics["max_nesting_depth"] = max_nesting
    if max_nesting > 4:
        issues.append(Issue(
            "warning", "complexity",
            f"Possible callback nesting (depth ~{max_nesting}). Consider async/await.",
            None,
            "Replace nested callbacks with async/await for cleaner control flow.",
            "// Instead of nested callbacks:\n// Use async/await:\nasync function fetchData() {\n  const user = await getUser();\n  const posts = await getPosts(user.id);\n  return posts;\n}"
        ))

    # Function count estimate
    func_count = len(re.findall(r'\bfunction\b|\b=>\s*{', code))
    metrics["function_count"] = func_count

    # Comment coverage
    comment_lines = sum(1 for l in lines if l.strip().startswith('//') or l.strip().startswith('/*'))
    metrics["comment_ratio"] = round(comment_lines / max(len(lines), 1) * 100)
    metrics["docstring_coverage"] = metrics["comment_ratio"]

    return issues, metrics


# ──────────────────────────────────────────────
#  JAVA ANALYZER
# ──────────────────────────────────────────────

def _analyze_java(code: str, lines: list[str]) -> tuple[list[Issue], dict]:
    issues = []
    metrics = {
        "total_lines": len(lines),
        "blank_lines": sum(1 for l in lines if not l.strip()),
    }
    metrics["code_lines"] = metrics["total_lines"] - metrics["blank_lines"]

    # System.out.println
    print_lines = [i+1 for i, l in enumerate(lines) if 'System.out.print' in l]
    if print_lines:
        issues.append(Issue(
            "info", "style",
            f"System.out.println at {len(print_lines)} location(s). Use a logger instead.",
            print_lines[0],
            "Use SLF4J or java.util.logging for production-grade logging.",
            "// Add dependency: slf4j-api\nimport org.slf4j.Logger;\nimport org.slf4j.LoggerFactory;\n\nprivate static final Logger log = LoggerFactory.getLogger(MyClass.class);\nlog.info(\"message {}\", value);"
        ))

    # Raw types (List, Map without generics)
    for i, line in enumerate(lines, 1):
        if re.search(r'\b(List|Map|Set|ArrayList|HashMap)\s+\w+\s*=', line) and '<' not in line:
            issues.append(Issue(
                "warning", "style",
                f"Raw generic type used at line {i}. Add type parameters.",
                i,
                "Raw types lose type safety. Always specify generic parameters.",
                "// Instead of: List items = new ArrayList();\nList<String> items = new ArrayList<>();"
            ))
            break

    # Public fields (should be private)
    for i, line in enumerate(lines, 1):
        if re.search(r'\bpublic\b.+\b(int|String|boolean|double|float|long)\b\s+\w+\s*;', line):
            issues.append(Issue(
                "warning", "style",
                f"Public field at line {i}. Prefer private with getters/setters.",
                i,
                "Expose state through methods, not public fields.",
                "private String name;\n\npublic String getName() { return name; }\npublic void setName(String name) { this.name = name; }"
            ))
            break

    # Missing Javadoc on public methods
    public_methods = [i+1 for i, l in enumerate(lines) if re.search(r'\bpublic\b.*\(', l)]
    javadoc = len(re.findall(r'/\*\*', code))
    metrics["docstring_coverage"] = round(javadoc / max(len(public_methods), 1) * 100)
    if public_methods and metrics["docstring_coverage"] < 50:
        issues.append(Issue(
            "warning", "documentation",
            f"Only {metrics['docstring_coverage']}% of public methods have Javadoc.",
            None,
            "Document all public API methods with Javadoc.",
            "/**\n * Calculates the total price including tax.\n * @param price Base price\n * @param taxRate Tax rate as decimal\n * @return Total price with tax\n */\npublic double calculateTotal(double price, double taxRate) { ... }"
        ))

    # Nesting depth estimate
    max_depth = 0
    depth = 0
    for line in lines:
        depth += line.count('{') - line.count('}')
        max_depth = max(max_depth, depth)
    metrics["max_nesting_depth"] = max_depth
    metrics["function_count"] = len([l for l in lines if re.search(r'\b(public|private|protected)\b.+\(', l)])
    comment_lines = sum(1 for l in lines if l.strip().startswith('//') or l.strip().startswith('*'))
    metrics["comment_ratio"] = round(comment_lines / max(len(lines), 1) * 100)

    return issues, metrics


# ──────────────────────────────────────────────
#  C++ ANALYZER
# ──────────────────────────────────────────────

def _analyze_cpp(code: str, lines: list[str]) -> tuple[list[Issue], dict]:
    issues = []
    metrics = {
        "total_lines": len(lines),
        "blank_lines": sum(1 for l in lines if not l.strip()),
    }
    metrics["code_lines"] = metrics["total_lines"] - metrics["blank_lines"]

    # using namespace std
    for i, line in enumerate(lines, 1):
        if 'using namespace std' in line:
            issues.append(Issue(
                "warning", "style",
                f"'using namespace std' at line {i} — avoid in header files.",
                i,
                "Prefer explicit std:: prefix to avoid name collisions.",
                "// Instead of: using namespace std;\n// Use:\nstd::cout << \"hello\";\nstd::string name = \"world\";"
            ))

    # Raw pointers (prefer smart pointers)
    for i, line in enumerate(lines, 1):
        if re.search(r'\b\w+\s*\*\s*\w+\s*=\s*new\b', line):
            issues.append(Issue(
                "warning", "safety",
                f"Raw pointer with 'new' at line {i}. Prefer smart pointers.",
                i,
                "Use unique_ptr or shared_ptr to avoid memory leaks.",
                "// Instead of: MyClass* obj = new MyClass();\n#include <memory>\nauto obj = std::make_unique<MyClass>();"
            ))
            break

    # printf instead of cout
    if 'printf' in code:
        issues.append(Issue(
            "info", "style",
            "printf() used. Prefer std::cout for type safety in C++.",
            None,
            "std::cout integrates better with C++ types and streams.",
            "// Instead of: printf(\"%s\", name.c_str());\nstd::cout << name << '\\n';"
        ))

    # Missing include guards or #pragma once
    if not re.search(r'#pragma once|#ifndef .+_H', code) and re.search(r'#include', code):
        if '.h' in code or 'class ' in code:
            issues.append(Issue(
                "info", "style",
                "No include guard or #pragma once detected.",
                1,
                "Add include guards to prevent double-inclusion.",
                "#pragma once\n// -- or --\n#ifndef MY_HEADER_H\n#define MY_HEADER_H\n// ... code ...\n#endif"
            ))

    metrics["max_nesting_depth"] = 0
    depth = 0
    for line in lines:
        depth += line.count('{') - line.count('}')
        metrics["max_nesting_depth"] = max(metrics["max_nesting_depth"], depth)
    metrics["function_count"] = len(re.findall(r'\b\w+\s+\w+\s*\(', code))
    comment_lines = sum(1 for l in lines if l.strip().startswith('//') or l.strip().startswith('*'))
    metrics["comment_ratio"] = round(comment_lines / max(len(lines), 1) * 100)
    metrics["docstring_coverage"] = metrics["comment_ratio"]

    return issues, metrics


# ──────────────────────────────────────────────
#  GO ANALYZER
# ──────────────────────────────────────────────

def _analyze_go(code: str, lines: list[str]) -> tuple[list[Issue], dict]:
    issues = []
    metrics = {
        "total_lines": len(lines),
        "blank_lines": sum(1 for l in lines if not l.strip()),
    }
    metrics["code_lines"] = metrics["total_lines"] - metrics["blank_lines"]

    # Ignored errors
    for i, line in enumerate(lines, 1):
        if re.search(r',\s*_\s*:?=', line) or re.search(r'_\s*=\s*\w+\(', line):
            issues.append(Issue(
                "warning", "safety",
                f"Error ignored with _ at line {i}.",
                i,
                "Handle errors explicitly — Go's error handling is part of its design.",
                "// Instead of:\nresult, _ := doSomething()\n\n// Use:\nresult, err := doSomething()\nif err != nil {\n    return fmt.Errorf(\"doSomething: %w\", err)\n}"
            ))
            break

    # panic() usage
    for i, line in enumerate(lines, 1):
        if re.search(r'\bpanic\(', line):
            issues.append(Issue(
                "warning", "safety",
                f"panic() used at line {i}. Return errors instead.",
                i,
                "Reserve panic for truly unrecoverable states. Return error values.",
                "// Instead of: panic(\"something went wrong\")\n// Return an error:\nreturn nil, fmt.Errorf(\"something went wrong: %v\", reason)"
            ))

    # Missing GoDoc comments
    exported = [i+1 for i, l in enumerate(lines) if re.search(r'^func [A-Z]', l.strip())]
    godoc = len(re.findall(r'//\s+[A-Z]\w+', code))
    metrics["docstring_coverage"] = round(godoc / max(len(exported), 1) * 100)
    if exported and metrics["docstring_coverage"] < 50:
        issues.append(Issue(
            "warning", "documentation",
            f"Only {metrics['docstring_coverage']}% of exported functions have GoDoc comments.",
            None,
            "All exported identifiers should have GoDoc comments.",
            "// CalculateTotal returns the sum of all line items including tax.\n// It returns an error if any item has a negative price.\nfunc CalculateTotal(items []Item) (float64, error) { ... }"
        ))

    metrics["max_nesting_depth"] = 0
    depth = 0
    for line in lines:
        depth += line.count('{') - line.count('}')
        metrics["max_nesting_depth"] = max(metrics["max_nesting_depth"], depth)
    metrics["function_count"] = len(re.findall(r'\bfunc\b', code))
    comment_lines = sum(1 for l in lines if l.strip().startswith('//'))
    metrics["comment_ratio"] = round(comment_lines / max(len(lines), 1) * 100)

    return issues, metrics


# ──────────────────────────────────────────────
#  GENERIC FALLBACK
# ──────────────────────────────────────────────

def _analyze_generic(code: str, lines: list[str]) -> tuple[list[Issue], dict]:
    issues = []
    metrics = {
        "total_lines": len(lines),
        "blank_lines": sum(1 for l in lines if not l.strip()),
        "function_count": 0,
        "max_nesting_depth": 0,
        "comment_ratio": 0,
        "docstring_coverage": 0,
    }
    metrics["code_lines"] = metrics["total_lines"] - metrics["blank_lines"]

    # Very long lines
    for i, line in enumerate(lines, 1):
        if len(line) > 120:
            issues.append(Issue(
                "info", "style",
                f"Line {i} is {len(line)} characters long (max 120 recommended).",
                i,
                "Break long lines for readability.",
                "# Wrap long expressions:\nresult = (\n    very_long_expression_part1\n    + very_long_expression_part2\n)"
            ))
            break

    return issues, metrics


# ──────────────────────────────────────────────
#  MAIN ENTRY POINT
# ──────────────────────────────────────────────



# ──────────────────────────────────────────────
#  C ANALYZER
# ──────────────────────────────────────────────

def _analyze_c(code: str, lines: list[str]) -> tuple[list[Issue], dict]:
    issues = []
    metrics = {
        "total_lines": len(lines),
        "blank_lines": sum(1 for l in lines if not l.strip()),
    }
    metrics["code_lines"] = metrics["total_lines"] - metrics["blank_lines"]

    # gets() — dangerous
    for i, line in enumerate(lines, 1):
        if re.search(r'\bgets\s*\(', line):
            issues.append(Issue(
                "error", "security",
                f"gets() at line {i} is unsafe — no bounds checking.",
                i,
                "Use fgets() with an explicit buffer size.",
                '// Instead of: gets(buffer);\nfgets(buffer, sizeof(buffer), stdin);'
            ))

    # malloc without NULL check
    malloc_lines = [i+1 for i, l in enumerate(lines) if re.search(r'\bmalloc\s*\(', l)]
    null_checks = len(re.findall(r'if\s*\(.*==\s*NULL|if\s*\(!', code))
    if malloc_lines and null_checks < len(malloc_lines):
        issues.append(Issue(
            "warning", "safety",
            f"malloc() used {len(malloc_lines)} time(s) — ensure every allocation is NULL-checked.",
            malloc_lines[0],
            "Always check if malloc returned NULL before using the pointer.",
            'int *ptr = malloc(sizeof(int) * n);\nif (ptr == NULL) {\n    fprintf(stderr, "Out of memory\\n");\n    exit(EXIT_FAILURE);\n}'
        ))

    # strcpy / strcat — unsafe
    for i, line in enumerate(lines, 1):
        if re.search(r'\b(strcpy|strcat)\s*\(', line):
            issues.append(Issue(
                "warning", "security",
                f"Unsafe string function at line {i}. Use strncpy/strncat.",
                i,
                "Always use the bounded versions to avoid buffer overflows.",
                '// Instead of: strcpy(dest, src);\nstrncpy(dest, src, sizeof(dest) - 1);\ndest[sizeof(dest) - 1] = \'\\0\';'
            ))
            break

    # Missing include guard
    if not re.search(r'#pragma once|#ifndef \w+_H', code):
        if re.search(r'#include', code):
            issues.append(Issue(
                "info", "style",
                "No include guard detected in this header.",
                1,
                "Add #pragma once or #ifndef guards.",
                '#pragma once\n// -- or --\n#ifndef MY_FILE_H\n#define MY_FILE_H\n// code\n#endif'
            ))

    depth, max_depth = 0, 0
    for line in lines:
        depth += line.count('{') - line.count('}')
        max_depth = max(max_depth, depth)
    metrics["max_nesting_depth"] = max_depth
    metrics["function_count"] = len(re.findall(r'\b\w+\s+\w+\s*\([^;]*\)\s*\{', code))
    comment_lines = sum(1 for l in lines if l.strip().startswith('//') or l.strip().startswith('*'))
    metrics["comment_ratio"] = round(comment_lines / max(len(lines), 1) * 100)
    metrics["docstring_coverage"] = metrics["comment_ratio"]
    return issues, metrics


# ──────────────────────────────────────────────
#  C# ANALYZER
# ──────────────────────────────────────────────

def _analyze_csharp(code: str, lines: list[str]) -> tuple[list[Issue], dict]:
    issues = []
    metrics = {
        "total_lines": len(lines),
        "blank_lines": sum(1 for l in lines if not l.strip()),
    }
    metrics["code_lines"] = metrics["total_lines"] - metrics["blank_lines"]

    # Console.WriteLine in non-test code
    cw_lines = [i+1 for i, l in enumerate(lines) if 'Console.WriteLine' in l]
    if len(cw_lines) > 2:
        issues.append(Issue(
            "info", "style",
            f"Console.WriteLine used {len(cw_lines)} times — use a logger in production.",
            cw_lines[0],
            "Replace with ILogger or Serilog for structured logging.",
            '// Add: using Microsoft.Extensions.Logging;\nprivate readonly ILogger<MyClass> _logger;\n_logger.LogInformation("Value: {Value}", myValue);'
        ))

    # var overuse (when type is not obvious)
    var_count = len(re.findall(r'\bvar\b', code))
    if var_count > 5:
        issues.append(Issue(
            "info", "style",
            f"'var' used {var_count} times. Reserve it for when the type is obvious from context.",
            None,
            "Explicit types improve readability, especially for method return values.",
            '// OK: var items = new List<string>();  // obvious\n// Better: HttpClient client = GetClient();  // not obvious'
        ))

    # Missing XML docs on public members
    public_count = len(re.findall(r'\bpublic\b', code))
    xmldoc_count = len(re.findall(r'///\s*<summary>', code))
    metrics["docstring_coverage"] = round(xmldoc_count / max(public_count, 1) * 100)
    if public_count > 2 and metrics["docstring_coverage"] < 40:
        issues.append(Issue(
            "warning", "documentation",
            f"Only {metrics['docstring_coverage']}% of public members have XML docs.",
            None,
            "Document public APIs with /// XML comments.",
            '/// <summary>\n/// Calculates the total with tax applied.\n/// </summary>\n/// <param name="price">Base price before tax.</param>\n/// <returns>Final price including tax.</returns>\npublic decimal CalculateTotal(decimal price) { ... }'
        ))

    # Exception swallowing
    for i, line in enumerate(lines, 1):
        if re.search(r'catch\s*\(\s*(Exception|Exception\s+\w+)\s*\)\s*\{?\s*$', line):
            next_lines = '\n'.join(l.strip() for l in lines[i:i+3])
            if not re.search(r'(throw|log|Log|_logger)', next_lines):
                issues.append(Issue(
                    "warning", "safety",
                    f"Possible empty/swallowed catch block near line {i}.",
                    i,
                    "Always log or rethrow exceptions — silent catches hide bugs.",
                    'catch (Exception ex)\n{\n    _logger.LogError(ex, "Operation failed");\n    throw;  // or handle meaningfully\n}'
                ))
                break

    depth, max_depth = 0, 0
    for line in lines:
        depth += line.count('{') - line.count('}')
        max_depth = max(max_depth, depth)
    metrics["max_nesting_depth"] = max_depth
    metrics["function_count"] = len(re.findall(r'\b(public|private|protected)\b.+\(', code))
    comment_lines = sum(1 for l in lines if l.strip().startswith('//') or l.strip().startswith('*'))
    metrics["comment_ratio"] = round(comment_lines / max(len(lines), 1) * 100)
    return issues, metrics


# ──────────────────────────────────────────────
#  KOTLIN ANALYZER
# ──────────────────────────────────────────────

def _analyze_kotlin(code: str, lines: list[str]) -> tuple[list[Issue], dict]:
    issues = []
    metrics = {
        "total_lines": len(lines),
        "blank_lines": sum(1 for l in lines if not l.strip()),
    }
    metrics["code_lines"] = metrics["total_lines"] - metrics["blank_lines"]

    # !! (not-null assertion) overuse
    bang_bangs = [(i+1, l) for i, l in enumerate(lines) if '!!' in l]
    if len(bang_bangs) > 2:
        issues.append(Issue(
            "warning", "safety",
            f"Non-null assertion (!!) used {len(bang_bangs)} times — risk of NullPointerException.",
            bang_bangs[0][0],
            "Use safe calls (?.) and Elvis operator (?:) instead.",
            '// Instead of: user!!.name\nval name = user?.name ?: "Unknown"\n\n// Instead of: list!!.size\nval size = list?.size ?: 0'
        ))

    # println in production
    print_lines = [i+1 for i, l in enumerate(lines) if re.search(r'\bprintln\b', l)]
    if print_lines:
        issues.append(Issue(
            "info", "style",
            f"println() at {len(print_lines)} location(s). Use a logger.",
            print_lines[0],
            "Use Timber or SLF4J for structured, level-aware logging.",
            '// Add: implementation("com.jakewharton.timber:timber:5.0.1")\nTimber.d("Value: %s", value)'
        ))

    # Mutable collections where immutable would do
    mutable_count = len(re.findall(r'\bmutableListOf\b|\bmutableMapOf\b|\bmutableSetOf\b', code))
    if mutable_count > 3:
        issues.append(Issue(
            "info", "style",
            f"Mutable collections used {mutable_count} times. Prefer immutable where possible.",
            None,
            "Prefer listOf/mapOf unless mutation is needed — safer and more idiomatic.",
            '// Prefer:\nval items = listOf("a", "b", "c")\n// Only use mutableListOf when you need to add/remove'
        ))

    depth, max_depth = 0, 0
    for line in lines:
        depth += line.count('{') - line.count('}')
        max_depth = max(max_depth, depth)
    metrics["max_nesting_depth"] = max_depth
    metrics["function_count"] = len(re.findall(r'\bfun\b', code))
    comment_lines = sum(1 for l in lines if l.strip().startswith('//') or l.strip().startswith('*'))
    metrics["comment_ratio"] = round(comment_lines / max(len(lines), 1) * 100)
    metrics["docstring_coverage"] = round(len(re.findall(r'/\*\*', code)) / max(metrics["function_count"], 1) * 100)
    return issues, metrics


# ──────────────────────────────────────────────
#  RUBY ANALYZER
# ──────────────────────────────────────────────

def _analyze_ruby(code: str, lines: list[str]) -> tuple[list[Issue], dict]:
    issues = []
    metrics = {
        "total_lines": len(lines),
        "blank_lines": sum(1 for l in lines if not l.strip()),
    }
    metrics["code_lines"] = metrics["total_lines"] - metrics["blank_lines"]

    # puts in production
    puts_lines = [i+1 for i, l in enumerate(lines) if re.search(r'\bputs\b', l)]
    if puts_lines:
        issues.append(Issue(
            "info", "style",
            f"puts at {len(puts_lines)} location(s) — use Rails.logger in production.",
            puts_lines[0],
            "Use Rails.logger or the Logger class for proper logging.",
            "# Instead of: puts \"User: #{user.name}\"\nRails.logger.info \"User: #{user.name}\""
        ))

    # eval usage
    for i, line in enumerate(lines, 1):
        if re.search(r'\beval\b', line):
            issues.append(Issue(
                "error", "security",
                f"eval() at line {i} — serious security risk.",
                i,
                "Never eval user input. Find a safer alternative.",
                "# Avoid eval entirely.\n# Use send() for dynamic method calls:\nobj.send(method_name, *args)"
            ))

    # Long methods (end keyword based)
    method_starts = [i for i, l in enumerate(lines) if re.match(r'\s*def ', l)]
    for start in method_starts:
        end_candidates = [i for i in range(start+1, len(lines)) if re.match(r'\s*end\s*$', lines[i])]
        if end_candidates:
            length = end_candidates[0] - start
            name_match = re.search(r'def\s+(\w+)', lines[start])
            name = name_match.group(1) if name_match else '?'
            if length > 30:
                issues.append(Issue(
                    "warning", "smell",
                    f"Method '{name}' is {length} lines long.",
                    start + 1,
                    "Ruby methods should ideally be under 10 lines.",
                    "# Extract logic into private methods:\ndef process_order(order)\n  validate!(order)\n  calculate_totals(order)\n  persist(order)\nend"
                ))

    metrics["function_count"] = len(method_starts)
    comment_lines = sum(1 for l in lines if l.strip().startswith('#'))
    metrics["comment_ratio"] = round(comment_lines / max(len(lines), 1) * 100)
    metrics["max_nesting_depth"] = 0
    metrics["docstring_coverage"] = 0
    return issues, metrics


# ──────────────────────────────────────────────
#  HTML/CSS ANALYZER
# ──────────────────────────────────────────────

def _analyze_html(code: str, lines: list[str]) -> tuple[list[Issue], dict]:
    issues = []
    metrics = {
        "total_lines": len(lines),
        "blank_lines": sum(1 for l in lines if not l.strip()),
    }
    metrics["code_lines"] = metrics["total_lines"] - metrics["blank_lines"]

    # Missing alt on images
    img_tags = re.findall(r'<img[^>]*>', code, re.IGNORECASE)
    for img in img_tags:
        if 'alt=' not in img.lower():
            issues.append(Issue(
                "warning", "accessibility",
                "img tag missing alt attribute — breaks screen readers.",
                None,
                "Always include meaningful alt text on images.",
                '<!-- Instead of: <img src="cat.jpg"> -->\n<img src="cat.jpg" alt="A tabby cat sitting on a windowsill">'
            ))
            break

    # Inline styles
    inline_style_count = len(re.findall(r'\bstyle\s*=\s*["\']', code, re.IGNORECASE))
    if inline_style_count > 3:
        issues.append(Issue(
            "info", "style",
            f"{inline_style_count} inline style attributes found — move to CSS classes.",
            None,
            "Inline styles make maintenance harder and override specificity.",
            '<!-- Instead of: <div style="color:red;font-size:14px"> -->\n<!-- Add to CSS: -->\n.error-text { color: red; font-size: 14px; }\n<!-- HTML: -->\n<div class="error-text">'
        ))

    # Missing doctype
    if not re.search(r'<!DOCTYPE\s+html', code, re.IGNORECASE):
        issues.append(Issue(
            "warning", "style",
            "Missing <!DOCTYPE html> declaration.",
            1,
            "Always declare the doctype — it sets the browser rendering mode.",
            '<!DOCTYPE html>\n<html lang="en">\n<head>...</head>\n<body>...</body>\n</html>'
        ))

    # Missing lang on html tag
    if re.search(r'<html', code, re.IGNORECASE) and not re.search(r'<html[^>]+lang=', code, re.IGNORECASE):
        issues.append(Issue(
            "warning", "accessibility",
            "<html> tag missing lang attribute.",
            None,
            "The lang attribute helps screen readers use the correct pronunciation.",
            '<html lang="en">'
        ))

    # Deprecated tags
    deprecated = ['<center', '<font ', '<marquee', '<blink', '<frame']
    for tag in deprecated:
        if tag.lower() in code.lower():
            issues.append(Issue(
                "warning", "style",
                f"Deprecated HTML tag '{tag.strip('<')}' used.",
                None,
                "Replace with modern CSS equivalents.",
                '<!-- Instead of: <center>text</center> -->\n<div style="text-align: center">text</div>\n<!-- Or better, use a CSS class -->'
            ))

    # !important overuse in CSS
    important_count = len(re.findall(r'!important', code))
    if important_count > 3:
        issues.append(Issue(
            "warning", "style",
            f"!important used {important_count} times — signals specificity problems.",
            None,
            "Fix CSS specificity properly instead of using !important.",
            '/* Instead of:\n.btn { color: red !important; }\n\nFix specificity:\n.sidebar .btn { color: red; }  /* more specific */'
        ))

    metrics["function_count"] = 0
    metrics["max_nesting_depth"] = 0
    metrics["comment_ratio"] = round(len(re.findall(r'<!--', code)) / max(len(lines), 1) * 100)
    metrics["docstring_coverage"] = 0
    return issues, metrics


# ──────────────────────────────────────────────
#  R ANALYZER
# ──────────────────────────────────────────────

def _analyze_r(code: str, lines: list[str]) -> tuple[list[Issue], dict]:
    issues = []
    metrics = {
        "total_lines": len(lines),
        "blank_lines": sum(1 for l in lines if not l.strip()),
    }
    metrics["code_lines"] = metrics["total_lines"] - metrics["blank_lines"]

    # = instead of <- for assignment
    assign_eq = len(re.findall(r'(?<![=!<>])\s=\s(?!=)', code))
    assign_arrow = len(re.findall(r'<-', code))
    if assign_eq > assign_arrow and assign_eq > 2:
        issues.append(Issue(
            "info", "style",
            f"Using = for assignment {assign_eq} times. R convention prefers <-.",
            None,
            "Use <- for assignment; reserve = for function arguments.",
            "# Instead of: x = 10\nx <- 10\n\n# = is fine inside function calls:\nmean(x = c(1, 2, 3))"
        ))

    # T/F instead of TRUE/FALSE
    if re.search(r'\bT\b|\bF\b', code):
        issues.append(Issue(
            "warning", "style",
            "Using T or F as shorthand for TRUE/FALSE — dangerous if T or F is redefined.",
            None,
            "Always write TRUE and FALSE explicitly.",
            "# Risky: flag <- T\n# Safe:  flag <- TRUE"
        ))

    # setwd() — bad practice
    if 'setwd(' in code:
        issues.append(Issue(
            "warning", "style",
            "setwd() makes code non-portable across machines.",
            None,
            "Use here::here() or relative paths instead.",
            '# Instead of: setwd("/Users/me/project")\nlibrary(here)\ndata <- read.csv(here("data", "file.csv"))'
        ))

    # Growing vector in loop (performance)
    if re.search(r'for\s*\(', code) and re.search(r'c\(', code):
        issues.append(Issue(
            "info", "performance",
            "Possible vector growing inside a loop — very slow in R.",
            None,
            "Pre-allocate with vector() or use vectorized functions / lapply.",
            "# Instead of:\nresult <- c()\nfor (i in 1:n) result <- c(result, f(i))\n\n# Use:\nresult <- vector('numeric', n)\nfor (i in 1:n) result[i] <- f(i)\n# Or even better:\nresult <- sapply(1:n, f)"
        ))

    metrics["function_count"] = len(re.findall(r'\bfunction\s*\(', code))
    comment_lines = sum(1 for l in lines if l.strip().startswith('#'))
    metrics["comment_ratio"] = round(comment_lines / max(len(lines), 1) * 100)
    metrics["max_nesting_depth"] = 0
    metrics["docstring_coverage"] = 0
    return issues, metrics


# ──────────────────────────────────────────────
#  SQL ANALYZER
# ──────────────────────────────────────────────

def _analyze_sql(code: str, lines: list[str]) -> tuple[list[Issue], dict]:
    issues = []
    metrics = {
        "total_lines": len(lines),
        "blank_lines": sum(1 for l in lines if not l.strip()),
    }
    metrics["code_lines"] = metrics["total_lines"] - metrics["blank_lines"]

    upper_code = code.upper()

    # SELECT *
    if re.search(r'SELECT\s+\*', upper_code):
        issues.append(Issue(
            "warning", "performance",
            "SELECT * fetches all columns — specify only what you need.",
            None,
            "Explicitly list columns for better performance and clarity.",
            "-- Instead of:\nSELECT * FROM orders;\n\n-- Use:\nSELECT id, customer_id, total, created_at\nFROM orders;"
        ))

    # No WHERE on UPDATE/DELETE
    if re.search(r'\bUPDATE\b', upper_code) and not re.search(r'\bWHERE\b', upper_code):
        issues.append(Issue(
            "error", "safety",
            "UPDATE without a WHERE clause — will modify every row!",
            None,
            "Always add a WHERE clause to UPDATE statements.",
            "-- Dangerous:\nUPDATE users SET active = 0;\n\n-- Safe:\nUPDATE users SET active = 0 WHERE last_login < '2023-01-01';"
        ))

    if re.search(r'\bDELETE\b', upper_code) and not re.search(r'\bWHERE\b', upper_code):
        issues.append(Issue(
            "error", "safety",
            "DELETE without a WHERE clause — will delete every row!",
            None,
            "Always add a WHERE clause to DELETE statements.",
            "-- Dangerous:\nDELETE FROM sessions;\n\n-- Safe:\nDELETE FROM sessions WHERE expires_at < NOW();"
        ))

    # N+1 hint (subquery in SELECT)
    if re.search(r'SELECT.+SELECT', upper_code, re.DOTALL):
        issues.append(Issue(
            "warning", "performance",
            "Subquery inside SELECT detected — possible N+1 performance issue.",
            None,
            "Use a JOIN instead of a correlated subquery.",
            "-- Instead of:\nSELECT name, (SELECT COUNT(*) FROM orders WHERE user_id = u.id)\nFROM users u;\n\n-- Use:\nSELECT u.name, COUNT(o.id)\nFROM users u\nLEFT JOIN orders o ON o.user_id = u.id\nGROUP BY u.id, u.name;"
        ))

    # Missing index hint on large-table patterns
    if re.search(r'\bLIKE\s+[\'"]%', upper_code):
        issues.append(Issue(
            "info", "performance",
            "Leading wildcard LIKE '%...' cannot use an index — full table scan.",
            None,
            "Avoid leading wildcards. Use full-text search for pattern matching.",
            "-- Cannot use index:\nWHERE name LIKE '%smith'\n\n-- Can use index:\nWHERE name LIKE 'smith%'\n\n-- For full-text: use MATCH AGAINST or pg_trgm"
        ))

    metrics["function_count"] = len(re.findall(r'\b(FUNCTION|PROCEDURE|TRIGGER)\b', upper_code))
    metrics["max_nesting_depth"] = code.upper().count('SELECT')
    comment_lines = sum(1 for l in lines if l.strip().startswith('--') or l.strip().startswith('/*'))
    metrics["comment_ratio"] = round(comment_lines / max(len(lines), 1) * 100)
    metrics["docstring_coverage"] = 0
    return issues, metrics


# ──────────────────────────────────────────────
#  SCALA ANALYZER
# ──────────────────────────────────────────────

def _analyze_scala(code: str, lines: list[str]) -> tuple[list[Issue], dict]:
    issues = []
    metrics = {
        "total_lines": len(lines),
        "blank_lines": sum(1 for l in lines if not l.strip()),
    }
    metrics["code_lines"] = metrics["total_lines"] - metrics["blank_lines"]

    # null usage — un-Scala-like
    null_count = len(re.findall(r'\bnull\b', code))
    if null_count > 1:
        issues.append(Issue(
            "warning", "style",
            f"null used {null_count} times — use Option instead.",
            None,
            "Scala's Option[T] is safer and more idiomatic than null.",
            '// Instead of: def findUser(id: Int): User = null\ndef findUser(id: Int): Option[User] = {\n  users.find(_.id == id)  // returns Some(user) or None\n}'
        ))

    # var instead of val
    var_count = len(re.findall(r'\bvar\b', code))
    if var_count > 2:
        issues.append(Issue(
            "warning", "style",
            f"var used {var_count} times. Prefer immutable val.",
            None,
            "Immutability is a core Scala principle — use val by default.",
            '// Instead of: var total = 0\nval total = items.map(_.price).sum'
        ))

    # Return keyword (un-idiomatic)
    return_count = len(re.findall(r'\breturn\b', code))
    if return_count > 1:
        issues.append(Issue(
            "info", "style",
            f"Explicit return used {return_count} times — un-idiomatic Scala.",
            None,
            "Scala functions return the last expression. Avoid explicit return.",
            '// Instead of:\ndef add(a: Int, b: Int): Int = {\n  return a + b\n}\n\n// Use:\ndef add(a: Int, b: Int): Int = a + b'
        ))

    metrics["function_count"] = len(re.findall(r'\bdef\b', code))
    depth, max_depth = 0, 0
    for line in lines:
        depth += line.count('{') - line.count('}')
        max_depth = max(max_depth, depth)
    metrics["max_nesting_depth"] = max_depth
    comment_lines = sum(1 for l in lines if l.strip().startswith('//') or l.strip().startswith('*'))
    metrics["comment_ratio"] = round(comment_lines / max(len(lines), 1) * 100)
    metrics["docstring_coverage"] = round(len(re.findall(r'/\*\*', code)) / max(metrics["function_count"], 1) * 100)
    return issues, metrics


# ──────────────────────────────────────────────
#  DART ANALYZER
# ──────────────────────────────────────────────

def _analyze_dart(code: str, lines: list[str]) -> tuple[list[Issue], dict]:
    issues = []
    metrics = {
        "total_lines": len(lines),
        "blank_lines": sum(1 for l in lines if not l.strip()),
    }
    metrics["code_lines"] = metrics["total_lines"] - metrics["blank_lines"]

    # dynamic type usage
    dynamic_count = len(re.findall(r'\bdynamic\b', code))
    if dynamic_count > 2:
        issues.append(Issue(
            "warning", "style",
            f"'dynamic' type used {dynamic_count} times — defeats Dart's type system.",
            None,
            "Use specific types or generics instead of dynamic.",
            '// Instead of: dynamic value = getData();\nString value = getData();  // or Map<String, dynamic> for JSON'
        ))

    # print() in production
    print_lines = [i+1 for i, l in enumerate(lines) if re.search(r'\bprint\s*\(', l)]
    if print_lines:
        issues.append(Issue(
            "info", "style",
            f"print() at {len(print_lines)} location(s). Use a logger package.",
            print_lines[0],
            "Use package:logger or debugPrint for Flutter apps.",
            "// Add to pubspec: logger: ^2.0.0\nimport 'package:logger/logger.dart';\nfinal log = Logger();\nlog.d('Debug message');"
        ))

    # Nullable without null safety
    late_count = len(re.findall(r'\blate\b', code))
    if late_count > 3:
        issues.append(Issue(
            "info", "style",
            f"'late' keyword used {late_count} times — ensure late init is truly needed.",
            None,
            "Overuse of late can cause LateInitializationError at runtime.",
            '// Only use late when you can guarantee init before access:\nlate final String name;  // OK if set in constructor\n\n// Prefer nullable + null check:\nString? name;'
        ))

    metrics["function_count"] = len(re.findall(r'\b(void|Future|Stream|Widget)\s+\w+\s*\(', code))
    depth, max_depth = 0, 0
    for line in lines:
        depth += line.count('{') - line.count('}')
        max_depth = max(max_depth, depth)
    metrics["max_nesting_depth"] = max_depth
    comment_lines = sum(1 for l in lines if l.strip().startswith('//') or l.strip().startswith('*'))
    metrics["comment_ratio"] = round(comment_lines / max(len(lines), 1) * 100)
    metrics["docstring_coverage"] = round(len(re.findall(r'///\s*\w', code)) / max(metrics["function_count"], 1) * 100)
    return issues, metrics


# ──────────────────────────────────────────────
#  PHP ANALYZER
# ──────────────────────────────────────────────

def _analyze_php(code: str, lines: list[str]) -> tuple[list[Issue], dict]:
    issues = []
    metrics = {
        "total_lines": len(lines),
        "blank_lines": sum(1 for l in lines if not l.strip()),
    }
    metrics["code_lines"] = metrics["total_lines"] - metrics["blank_lines"]

    # Direct $_GET/$_POST in queries (SQL injection risk)
    for i, line in enumerate(lines, 1):
        if re.search(r'\$_(GET|POST|REQUEST)', line) and re.search(r'(query|mysql_|mysqli_|execute)', line, re.IGNORECASE):
            issues.append(Issue(
                "error", "security",
                f"Possible SQL injection at line {i} — user input in query.",
                i,
                "Always use prepared statements with bound parameters.",
                '$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");\n$stmt->execute([$_GET["id"]]);'
            ))

    # echo with user input
    for i, line in enumerate(lines, 1):
        if re.search(r'\becho\b.+\$_(GET|POST|REQUEST)', line):
            issues.append(Issue(
                "error", "security",
                f"XSS risk at line {i} — echoing user input without escaping.",
                i,
                "Always escape output with htmlspecialchars().",
                '// Instead of: echo $_GET["name"];\necho htmlspecialchars($_GET["name"], ENT_QUOTES, "UTF-8");'
            ))
            break

    # mysql_ (deprecated)
    if re.search(r'\bmysql_\w+\s*\(', code):
        issues.append(Issue(
            "error", "style",
            "mysql_* functions are removed in PHP 7+.",
            None,
            "Use PDO or MySQLi with prepared statements.",
            '// Use PDO:\n$pdo = new PDO("mysql:host=localhost;dbname=mydb", $user, $pass);\n$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");\n$stmt->execute([$id]);'
        ))

    # Missing type declarations
    typed_funcs = len(re.findall(r'function\s+\w+\s*\([^)]*:\s*\w', code))
    total_funcs = len(re.findall(r'function\s+\w+\s*\(', code))
    metrics["docstring_coverage"] = round(typed_funcs / max(total_funcs, 1) * 100)
    if total_funcs > 2 and metrics["docstring_coverage"] < 50:
        issues.append(Issue(
            "warning", "style",
            f"Only {metrics['docstring_coverage']}% of functions have type declarations.",
            None,
            "Use PHP 7+ type hints for parameters and return types.",
            'function calculateTotal(float $price, int $qty): float {\n    return $price * $qty;\n}'
        ))

    metrics["function_count"] = total_funcs
    depth, max_depth = 0, 0
    for line in lines:
        depth += line.count('{') - line.count('}')
        max_depth = max(max_depth, depth)
    metrics["max_nesting_depth"] = max_depth
    comment_lines = sum(1 for l in lines if l.strip().startswith('//') or l.strip().startswith('*') or l.strip().startswith('#'))
    metrics["comment_ratio"] = round(comment_lines / max(len(lines), 1) * 100)
    return issues, metrics


# ──────────────────────────────────────────────
#  RUST ANALYZER
# ──────────────────────────────────────────────

def _analyze_rust(code: str, lines: list[str]) -> tuple[list[Issue], dict]:
    issues = []
    metrics = {
        "total_lines": len(lines),
        "blank_lines": sum(1 for l in lines if not l.strip()),
    }
    metrics["code_lines"] = metrics["total_lines"] - metrics["blank_lines"]

    # unwrap() — panic risk
    unwrap_lines = [(i+1) for i, l in enumerate(lines) if '.unwrap()' in l]
    if len(unwrap_lines) > 2:
        issues.append(Issue(
            "warning", "safety",
            f".unwrap() used {len(unwrap_lines)} times — will panic on None/Err.",
            unwrap_lines[0],
            "Use ? operator or match/if let for proper error handling.",
            '// Instead of: let val = some_option.unwrap();\n\n// Use ? in functions returning Result/Option:\nlet val = some_option.ok_or(MyError::NotFound)?;\n\n// Or handle explicitly:\nif let Some(val) = some_option {\n    // use val\n}'
        ))

    # clone() overuse (might indicate ownership misunderstanding)
    clone_count = len(re.findall(r'\.clone\(\)', code))
    if clone_count > 4:
        issues.append(Issue(
            "info", "performance",
            f".clone() called {clone_count} times — verify these are intentional.",
            None,
            "Excessive cloning may indicate a borrow/lifetime design issue.",
            '// Consider borrowing instead of cloning:\nfn process(data: &Vec<u8>) { ... }  // borrow\nfn process(data: Vec<u8>) { ... }   // take ownership\n// Only clone when you truly need two independent copies'
        ))

    # Missing doc comments on pub functions
    pub_fns = len(re.findall(r'\bpub\s+(fn|struct|enum)\b', code))
    doc_comments = len(re.findall(r'///\s*\w', code))
    metrics["docstring_coverage"] = round(doc_comments / max(pub_fns, 1) * 100)
    if pub_fns > 1 and metrics["docstring_coverage"] < 50:
        issues.append(Issue(
            "warning", "documentation",
            f"Only {metrics['docstring_coverage']}% of public items have doc comments.",
            None,
            "Document all public API items — cargo doc generates from /// comments.",
            '/// Calculates the checksum of the given bytes.\n///\n/// # Examples\n/// ```\n/// let sum = checksum(&[1, 2, 3]);\n/// assert_eq!(sum, 6);\n/// ```\npub fn checksum(data: &[u8]) -> u32 { ... }'
        ))

    # panic!() macro
    panic_count = len(re.findall(r'\bpanic!\b', code))
    if panic_count > 0:
        issues.append(Issue(
            "warning", "safety",
            f"panic!() macro used {panic_count} time(s) — crashes the thread.",
            None,
            "Return a Result<T, E> instead of panicking in library code.",
            '// Library code should never panic:\n// Instead of: panic!("invalid input")\n// Use:\nreturn Err(MyError::InvalidInput(msg))'
        ))

    metrics["function_count"] = len(re.findall(r'\bfn\b', code))
    depth, max_depth = 0, 0
    for line in lines:
        depth += line.count('{') - line.count('}')
        max_depth = max(max_depth, depth)
    metrics["max_nesting_depth"] = max_depth
    comment_lines = sum(1 for l in lines if l.strip().startswith('//'))
    metrics["comment_ratio"] = round(comment_lines / max(len(lines), 1) * 100)
    return issues, metrics


# ──────────────────────────────────────────────
#  SWIFT ANALYZER
# ──────────────────────────────────────────────

def _analyze_swift(code: str, lines: list[str]) -> tuple[list[Issue], dict]:
    issues = []
    metrics = {
        "total_lines": len(lines),
        "blank_lines": sum(1 for l in lines if not l.strip()),
    }
    metrics["code_lines"] = metrics["total_lines"] - metrics["blank_lines"]

    # Force unwrap !
    force_unwraps = [(i+1) for i, l in enumerate(lines) if re.search(r'\w+!(?!\s*=)', l) and '// ' not in l.split('!')[0][-3:]]
    if len(force_unwraps) > 2:
        issues.append(Issue(
            "warning", "safety",
            f"Force unwrap (!) used {len(force_unwraps)} times — crashes on nil.",
            force_unwraps[0],
            "Use optional binding (if let / guard let) or provide a default.",
            '// Instead of: let name = user!.name\n\n// Safe:\nif let user = user {\n    let name = user.name\n}\n\n// Or with guard:\nguard let user = user else { return }\nlet name = user.name'
        ))

    # print() in production
    print_lines = [i+1 for i, l in enumerate(lines) if re.search(r'\bprint\s*\(', l)]
    if print_lines:
        issues.append(Issue(
            "info", "style",
            f"print() at {len(print_lines)} location(s). Use OSLog in production.",
            print_lines[0],
            "OSLog is faster and integrates with Instruments and Console.app.",
            'import OSLog\nlet logger = Logger(subsystem: "com.myapp", category: "network")\nlogger.info("Request started: \\(url)")'
        ))

    # Strong reference cycles (delegate without weak)
    if 'delegate' in code.lower() and 'weak var' not in code:
        issues.append(Issue(
            "warning", "safety",
            "Delegate property without 'weak var' — possible retain cycle.",
            None,
            "Delegates should almost always be declared weak.",
            '// Instead of: var delegate: MyDelegate?\nweak var delegate: MyDelegate?'
        ))

    # Missing access control
    class_count = len(re.findall(r'\bclass\b|\bstruct\b', code))
    access_keywords = len(re.findall(r'\b(public|private|internal|fileprivate|open)\b', code))
    if class_count > 1 and access_keywords < class_count:
        issues.append(Issue(
            "info", "style",
            "Some types/members lack explicit access control modifiers.",
            None,
            "Be explicit about access control — it documents intent.",
            'public class NetworkManager {\n    private let session: URLSession\n    internal var timeout: TimeInterval = 30\n}'
        ))

    metrics["function_count"] = len(re.findall(r'\bfunc\b', code))
    depth, max_depth = 0, 0
    for line in lines:
        depth += line.count('{') - line.count('}')
        max_depth = max(max_depth, depth)
    metrics["max_nesting_depth"] = max_depth
    comment_lines = sum(1 for l in lines if l.strip().startswith('//') or l.strip().startswith('*'))
    metrics["comment_ratio"] = round(comment_lines / max(len(lines), 1) * 100)
    metrics["docstring_coverage"] = round(len(re.findall(r'///\s*\w', code)) / max(metrics["function_count"], 1) * 100)
    return issues, metrics


LANGUAGE_ANALYZERS = {
    "python":     _analyze_python,
    "javascript": _analyze_javascript,
    "typescript": _analyze_javascript,
    "java":       _analyze_java,
    "cpp":        _analyze_cpp,
    "c":          _analyze_c,
    "csharp":     _analyze_csharp,
    "kotlin":     _analyze_kotlin,
    "ruby":       _analyze_ruby,
    "html":       _analyze_html,
    "html/css":   _analyze_html,
    "css":        _analyze_html,
    "r":          _analyze_r,
    "sql":        _analyze_sql,
    "scala":      _analyze_scala,
    "dart":       _analyze_dart,
    "php":        _analyze_php,
    "rust":       _analyze_rust,
    "swift":      _analyze_swift,
    "go":         _analyze_go,
}


def analyze_code(code: str, language: str = "python") -> AnalysisResult:
    lines = code.splitlines()
    lang = language.lower()

    analyzer = LANGUAGE_ANALYZERS.get(lang, _analyze_generic)
    lang_issues, metrics = analyzer(code, lines)

    secret_issues = _check_secrets(lines)
    all_issues = lang_issues + secret_issues

    nat_score, ai_score, nat_reasons, ai_reasons = _naturalness_and_ai(code, lines, lang)

    deductions = {"error": 15, "warning": 5, "info": 1}
    total_ded = sum(deductions.get(i.severity, 0) for i in all_issues)
    score = max(0, 100 - total_ded)

    return AnalysisResult(
        score=score,
        language=language,
        issues=all_issues,
        metrics=metrics,
        naturalness_score=nat_score,
        ai_likelihood_score=ai_score,
        naturalness_reasons=nat_reasons,
        ai_reasons=ai_reasons,
    )
