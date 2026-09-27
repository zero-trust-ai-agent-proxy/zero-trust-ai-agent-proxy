from __future__ import annotations

import ast
import re
from pathlib import Path


def _string_value(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _string_value(node.left)
        right = _string_value(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def _docstring_node_ids(tree: ast.AST) -> set[int]:
    docstring_nodes: set[int] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
            and node.body
            and isinstance(node.body[0], ast.Expr)
        ):
            first = node.body[0].value
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                docstring_nodes.add(id(first))
    return docstring_nodes


def _string_literals(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    docstring_nodes = _docstring_node_ids(tree)
    values: list[str] = []
    for node in ast.walk(tree):
        if id(node) in docstring_nodes:
            continue
        value = _string_value(node)
        if value is not None:
            values.append(value)
    return values


def _regex_alternation_count(pattern: str) -> int:
    in_class = False
    escaped = False
    count = 0
    for ch in pattern:
        if escaped:
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == "[":
            in_class = True
        elif ch == "]":
            in_class = False
        elif ch == "|" and not in_class:
            count += 1
    return count + 1 if count else 0


def _compiled_regexes(path: Path) -> list[tuple[str, str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    patterns: list[tuple[str, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "compile"
            and isinstance(func.value, ast.Name)
            and func.value.id == "re"
            and node.args
        ):
            pattern = _string_value(node.args[0])
            parent = parents.get(node)
            name = ""
            if isinstance(parent, ast.Assign) and len(parent.targets) == 1:
                target = parent.targets[0]
                if isinstance(target, ast.Name):
                    name = target.id
            if pattern is not None:
                patterns.append((name, pattern))
    return patterns


def test_src_string_literals_do_not_copy_trace_identifiers_or_payloads() -> None:
    src = Path(__file__).resolve().parents[1] / "src"
    offenders: list[str] = []
    for path in src.rglob("*.py"):
        for literal in _string_literals(path):
            if re.search(r"\b(?:t|r)-[0-9a-f]{4,}\b|\bD-\d{4,}\b", literal):
                offenders.append(f"{path.relative_to(src)}:{literal[:60]}")
    assert offenders == []


def test_src_has_no_large_content_keyword_regexes() -> None:
    allowed_generic_patterns = {"_CHAT_CONTROL_RE", "_DENY_COMMAND_RE"}
    src = Path(__file__).resolve().parents[1] / "src"
    offenders: list[str] = []
    for path in src.rglob("*.py"):
        for name, pattern in _compiled_regexes(path):
            if name in allowed_generic_patterns:
                continue
            if _regex_alternation_count(pattern) > 10:
                offenders.append(f"{path.relative_to(src)}:{name}")
    assert offenders == []
