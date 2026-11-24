from flask import Flask, render_template, request
import ast
import operator
import os
import re
import subprocess

app = Flask(__name__)
app.config["SECRET_KEY"] = "your-secret-key-here"

# A hostname: dot-separated labels of letters, digits and hyphens.
# A label can never start with "-", so the value cannot be read as an option by dig/nslookup.
DOMAIN_RE = re.compile(
    r"(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*"
)

_BINARY_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
}
_UNARY_OPS = {ast.UAdd: operator.pos, ast.USub: operator.neg}


def _eval_node(node):
    """Evaluate one node of an arithmetic expression; anything else is rejected."""
    if isinstance(node, ast.Constant):
        if isinstance(node.value, bool) or not isinstance(node.value, (int, float)):
            raise ValueError("Only numbers are allowed")
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _BINARY_OPS:
        left = _eval_node(node.left)
        right = _eval_node(node.right)
        if isinstance(node.op, ast.Pow) and abs(right) > 100:
            raise ValueError("Exponent is too large")
        return _BINARY_OPS[type(node.op)](left, right)
    if isinstance(node, ast.UnaryOp) and type(node.op) in _UNARY_OPS:
        return _UNARY_OPS[type(node.op)](_eval_node(node.operand))
    raise ValueError("Only arithmetic expressions are allowed")


def safe_calculate(expression):
    """Calculator replacement for eval(): numbers and + - * / // % ** only."""
    if len(expression) > 200:
        raise ValueError("Expression is too long")
    tree = ast.parse(expression.strip(), mode="eval")
    return _eval_node(tree.body)


@app.route("/")
def index():
    """Main page with command injection lab description"""
    return render_template("index.html")


@app.route("/lab1", methods=["GET", "POST"])
def lab1():
    """Lab 1: Name Server Lookup (patched: no shell, validated input)"""
    if request.method == "POST":
        domain = request.form.get("domain", "").strip()
        os_type = request.form.get("os", "")

        if not DOMAIN_RE.fullmatch(domain):
            return render_template("lab1.html", output="Invalid domain name")

        tool = "nslookup" if os_type == "win" else "dig"

        try:
            # Fixed: the command is an argument list executed without a shell,
            # so shell metacharacters (; | && $() ...) in user input are never interpreted.
            result = subprocess.run(
                [tool, domain],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            output = result.stdout + result.stderr
        except Exception as e:
            output = str(e)

        return render_template("lab1.html", output=output)

    return render_template("lab1.html")


@app.route("/lab2", methods=["GET", "POST"])
def lab2():
    """Lab 2: Calculator (patched: eval() replaced with a restricted evaluator)"""
    if request.method == "POST":
        try:
            # Fixed: user input is parsed into an AST and only arithmetic nodes are evaluated,
            # so names, calls, attributes and imports are rejected instead of executed.
            expression = request.form.get("val", "")
            output = safe_calculate(expression)
            return render_template("lab2.html", output=str(output))
        except Exception as e:
            return render_template("lab2.html", output=str(e))
    return render_template("lab2.html")

@app.route("/health")
def health_check():
    return "OK", 200

if __name__ == '__main__':
    # Fixed: the Werkzeug debugger (remote code execution console) is off unless explicitly enabled
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host='0.0.0.0', port=5013, debug=debug)
