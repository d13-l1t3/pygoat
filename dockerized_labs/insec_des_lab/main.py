from flask import Flask, render_template, request
import base64
import hashlib
import hmac
import json
import os
from dataclasses import asdict, dataclass

app = Flask(__name__)

# Key used to sign tokens. Random per process unless provided through the environment,
# so a client can never compute a valid signature for a modified token.
TOKEN_KEY = os.environ.get("TOKEN_SIGNING_KEY", "").encode() or os.urandom(32)


@dataclass
class User:
    username: str
    is_admin: bool = False


def _sign(payload: bytes) -> str:
    return hmac.new(TOKEN_KEY, payload, hashlib.sha256).hexdigest()


def dump_token(user: User) -> str:
    """Serialize a user as JSON (data only, no code) and sign it."""
    payload = base64.urlsafe_b64encode(json.dumps(asdict(user)).encode())
    return f"{payload.decode()}.{_sign(payload)}"


def load_token(token: str) -> User:
    """Verify the signature first, then parse JSON and validate every field."""
    payload, _, signature = token.strip().rpartition(".")
    if not payload or not hmac.compare_digest(
        signature.encode(), _sign(payload.encode()).encode()
    ):
        raise ValueError("Invalid token signature")

    data = json.loads(base64.urlsafe_b64decode(payload))
    if (
        not isinstance(data, dict)
        or not isinstance(data.get("username"), str)
        or not isinstance(data.get("is_admin"), bool)
    ):
        raise ValueError("Invalid token content")
    return User(username=data["username"], is_admin=data["is_admin"])


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/serialize", methods=["POST"])
def serialize_data():
    username = request.form.get("username", "guest")
    # Create regular user with admin=False
    user = User(username=username, is_admin=False)
    # Fixed: JSON + HMAC signature instead of pickle
    serialized = dump_token(user)
    return render_template("result.html", serialized=serialized)


@app.route("/deserialize", methods=["POST"])
def deserialize_data():
    try:
        serialized_data = request.form.get("serialized_data", "")
        # Fixed: pickle.loads() executed attacker-controlled bytecode and trusted
        # the is_admin flag. JSON cannot execute code, and the signature makes
        # the token tamper-proof.
        user = load_token(serialized_data)

        if user.is_admin:
            message = f"Welcome Admin {user.username}! Here's the secret admin content: ADMIN_KEY_123"
        else:
            message = (
                f"Welcome {user.username}. Only admins can see the secret content."
            )

        return render_template("result.html", message=message)
    except Exception as e:
        return render_template("result.html", message=f"Error: {str(e)}")

@app.route("/health")
def health_check():
    return "OK", 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
