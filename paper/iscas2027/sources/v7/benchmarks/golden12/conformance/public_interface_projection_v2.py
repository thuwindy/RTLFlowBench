"""Bounded public-width projection for native parsers, not a design generator.

Only explicit public parameters/aliases/ports are accepted. The full public
contract remains authoritative; a default-width declaration is parser metadata,
never a replacement for the parameterized design specification.
"""

from __future__ import annotations

import ast
import re
from typing import Any

IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
MAX_INTEGER = 2**63 - 1


def identifier(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not IDENTIFIER.fullmatch(value)
        or len(value) > 128
    ):
        raise ValueError("invalid explicit public identifier")
    return value


def resolve_width(
    expression: str, defaults: dict[str, int], aliases: dict[str, str]
) -> int:
    if (
        not isinstance(defaults, dict)
        or not isinstance(aliases, dict)
        or len(defaults) + len(aliases) > 256
    ):
        raise ValueError("public expression environment exceeds limit")
    if set(defaults) & set(aliases):
        raise ValueError("conflicting public parameter and alias names")
    for name, value in defaults.items():
        identifier(name)
        if type(value) is not int or abs(value) > MAX_INTEGER:
            raise ValueError("invalid public integer default")
    for name, value in aliases.items():
        identifier(name)
        if not isinstance(value, str):
            raise ValueError("public alias expression must be text")
    cache = dict(defaults)
    active = set()
    operations = 0

    def integer(value):
        if type(value) is not int or abs(value) > MAX_INTEGER:
            raise ValueError("public integer expression exceeds bounds")
        return value

    def parse(value):
        if not isinstance(value, str) or not value or len(value) > 4096:
            raise ValueError("public expression byte/length limit")
        # Retain the already-supported single conditional form. Nested or
        # ambiguous Verilog conditionals stay unsupported, never eval()'d.
        match = re.fullmatch(r"\s*\(([^?]+)\)\s*\?\s*([^:]+)\s*:\s*(.+)", value)
        if match:
            condition, positive, negative = match.groups()
            value = f"({positive} if {condition} else {negative})"
        value = value.replace("$clog2", "clog2")
        try:
            tree = ast.parse(value.strip(), mode="eval")
        except (SyntaxError, RecursionError) as exc:
            raise ValueError("unsupported public expression syntax") from exc
        if sum(1 for _ in ast.walk(tree)) > 256:
            raise ValueError("public expression node limit")
        return evaluate(tree, 0)

    def evaluate(node, depth):
        nonlocal operations
        operations += 1
        if operations > 2048 or depth > 64:
            raise ValueError("public expression complexity limit")

        def child(value):
            return evaluate(value, depth + 1)

        if isinstance(node, ast.Expression):
            return child(node.body)
        if isinstance(node, ast.Constant):
            return integer(node.value)
        if isinstance(node, ast.Name):
            if node.id in cache:
                return cache[node.id]
            if node.id not in aliases:
                raise ValueError("undeclared public width symbol")
            if node.id in active or len(active) > 32:
                raise ValueError("cyclic or excessive public alias expansion")
            active.add(node.id)
            try:
                cache[node.id] = integer(parse(aliases[node.id]))
            finally:
                active.remove(node.id)
            return cache[node.id]
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
            value = integer(child(node.operand))
            return integer(value if isinstance(node.op, ast.UAdd) else -value)
        if isinstance(node, ast.BinOp) and isinstance(
            node.op, (ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv)
        ):
            left, right = integer(child(node.left)), integer(child(node.right))
            if isinstance(node.op, ast.Add):
                return integer(left + right)
            if isinstance(node.op, ast.Sub):
                return integer(left - right)
            if isinstance(node.op, ast.Mult):
                return integer(left * right)
            if right == 0:
                raise ValueError("public width division by zero")
            if isinstance(node.op, ast.Div) and left % right:
                raise ValueError("nonintegral public width division is not inferred")
            return integer(left // right)
        if (
            isinstance(node, ast.Compare)
            and len(node.ops) == len(node.comparators) == 1
        ):
            left, right = integer(child(node.left)), integer(child(node.comparators[0]))
            operation = node.ops[0]
            if isinstance(operation, ast.Lt):
                return left < right
            if isinstance(operation, ast.LtE):
                return left <= right
            if isinstance(operation, ast.Gt):
                return left > right
            if isinstance(operation, ast.GtE):
                return left >= right
            if isinstance(operation, ast.Eq):
                return left == right
            if isinstance(operation, ast.NotEq):
                return left != right
        if isinstance(node, ast.IfExp):
            condition = child(node.test)
            if type(condition) is not bool:
                raise ValueError("public conditional needs a comparison")
            return child(node.body if condition else node.orelse)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "clog2"
            and len(node.args) == 1
            and not node.keywords
        ):
            value = integer(child(node.args[0]))
            if value < 1:
                raise ValueError("public clog2 needs a positive integer")
            return (value - 1).bit_length()
        raise ValueError("expression outside the supported public subset")

    result = parse(expression)
    if type(result) is not int or not 1 <= result <= 1_048_576:
        raise ValueError("public width does not resolve to a bounded positive integer")
    return result


def project_interface(interface: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    if not isinstance(interface, dict):
        raise ValueError("missing explicit public interface")
    top = identifier(interface.get("top_module"))
    parameters, ports = interface.get("parameters", []), interface.get("ports")
    if (
        not isinstance(parameters, list)
        or len(parameters) > 256
        or not isinstance(ports, list)
        or not 1 <= len(ports) <= 1024
    ):
        raise ValueError("missing or oversized public parameters/ports")
    defaults = {}
    for item in parameters:
        if not isinstance(item, dict):
            raise ValueError("invalid parameter object")
        name = identifier(item.get("name"))
        value, kind = item.get("default"), item.get("type", "integer")
        if name in defaults or type(value) is not int or not 0 <= value <= MAX_INTEGER:
            raise ValueError("invalid or duplicate integer parameter")
        if kind not in {"int unsigned", "integer", "positive_integer"} or (
            kind == "positive_integer" and value < 1
        ):
            raise ValueError("unsupported public parameter type/default")
        defaults[name] = value
    aliases = interface.get("derived_widths", {})
    if aliases is None:
        aliases = {}
    rendered, widths = [], {}
    for port in ports:
        if not isinstance(port, dict):
            raise ValueError("invalid public port object")
        name = identifier(port.get("name"))
        direction = port.get("direction")
        if name in widths or direction not in {"input", "output", "inout"}:
            raise ValueError("duplicate port or unsupported direction")
        width = resolve_width(port.get("width"), defaults, aliases)
        widths[name] = width
        rendered.append(f"  {direction} [{width - 1}:0] {name}")
    return f"module {top}(\n" + ",\n".join(rendered) + "\n);", {
        "version": "hdlagent-explicit-public-interface-v4",
        "parameter_defaults": defaults,
        "resolved_port_widths": widths,
        "authoritative_parameter_contract": "unchanged_complete_public_context",
        "native_design_name": top,
        "native_design_name_source": "public_interface_spec.top_module",
        "purpose": "upstream_parser_compatibility_only",
        "division_policy": "exact_integer_only_otherwise_reject",
        "native_workflow_verified": False,
    }
