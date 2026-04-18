import os, sys
# Add current directory to path for module imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, request, jsonify, session
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_socketio import SocketIO, emit
from flask_session import Session
import hashlib, json, time, uuid
from dotenv import load_dotenv

load_dotenv()

from blockchain.node import BlockchainNetwork
from auth.otp import verify_otp, generate_otp_secret, generate_qr_code, get_otp_secret
from auth.webauthn_auth import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
)
from auth.crypto_utils import verify_signature
from auth.challenge import create_challenge, get_challenge
from ai.anomaly_detector import detector
from database.mongo_client import get_cloud_db, sync_nodes
from security.geoip import get_ip_location
from security.logger import log_event
import pymongo

# ─── App setup ────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", os.urandom(32))

# Flask-Session backed by MongoDB (survives Heroku dyno restarts / multi-dynos)
_mongo_client = pymongo.MongoClient(os.getenv("MONGO_URI"))
app.config["SESSION_TYPE"] = "mongodb"
app.config["SESSION_MONGODB"] = _mongo_client
app.config["SESSION_MONGODB_DB"] = "blockchain_auth"
app.config["SESSION_MONGODB_COLLECT"] = "flask_sessions"
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_USE_SIGNER"] = True
Session(app)

# CORS — set FRONTEND_URL in Heroku Config Vars
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")
CORS(
    app,
    supports_credentials=True,
    origins=[FRONTEND_URL, "http://localhost:3000", "http://127.0.0.1:3000"],
)

socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["500 per day", "100 per hour"],
    storage_uri="memory://",
)

network = BlockchainNetwork()
db = get_cloud_db()


# ─── Helper ───────────────────────────────────────────
def _ip(req=None) -> str:
    """Get real IP even behind reverse proxy."""
    r = req or request
    return (
        r.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or r.remote_addr
        or "0.0.0.0"
    )


def log_and_emit(event_type, username, ip, details, severity="INFO", success=True):
    try:
        geo = get_ip_location(ip)
    except Exception:
        geo = {"lat": 0, "lon": 0, "country": "??", "city": "?"}

    is_anomaly, score, reason = detector.is_anomaly(ip, username)

    event = {
        "id": str(uuid.uuid4()),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event_type": event_type,
        "username": username,
        "source_ip": ip,
        "country": geo.get("country", "??"),
        "city": geo.get("city", "?"),
        "lat": geo.get("lat", 0),
        "lon": geo.get("lon", 0),
        "severity": severity,
        "details": details,
        "success": success,
        "is_anomaly": is_anomaly,
        "anomaly_score": round(score, 3),
        "anomaly_reason": reason,
        "threat_level": detector.get_threat_level(ip),
    }

    log_event(event_type, username, ip, details, severity, success, extra={
        "country": event["country"],
        "lat": event["lat"],
        "lon": event["lon"],
        "is_anomaly": is_anomaly,
        "anomaly_score": event["anomaly_score"],
    })
    socketio.emit("security_event", event, namespace="/live")
    return event


# ─── Health check ─────────────────────────────────────
@app.route("/health")
def health():
    return jsonify({"status": "ok", "ts": time.time()})


# ─── Register ─────────────────────────────────────────
@app.route("/api/register", methods=["POST"])
@limiter.limit("5 per hour")
def register():
    data = request.get_json(force=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    public_key = data.get("public_key", "")

    if not all([username, password, public_key]):
        return jsonify({"error": "Champs manquants"}), 400

    if len(username) < 3 or len(username) > 32:
        return jsonify({"error": "Username: 3-32 caractères"}), 400

    hashed_pw = hashlib.sha256(password.encode()).hexdigest()

    if db.users.find_one({"username": username}):
        return jsonify({"error": "Utilisateur existant"}), 409

    otp_secret = generate_otp_secret()
    qr_b64, otp_uri = generate_qr_code(username, otp_secret)

    db.users.insert_one(
        {
            "username": username,
            "password": hashed_pw,
            "public_key": public_key,
            "otp_secret": otp_secret,
            "otp_enabled": True,
            "webauthn_enabled": False,
            "created_at": time.time(),
        }
    )
    sync_nodes(username, hashed_pw, public_key)

    ip = _ip()
    log_and_emit("USER_REGISTERED", username, ip, "New user registered")

    return jsonify(
        {
            "success": True,
            "qr_code": qr_b64,
            "otp_secret": otp_secret,
            "message": "Compte créé. Scannez le QR code avec Google Authenticator.",
        }
    )


# ─── Login Phase 1 : Credentials + OTP + Blockchain Consensus ─
@app.route("/api/login/step1", methods=["POST"])
@limiter.limit("15 per minute")
def login_step1():
    data = request.get_json(force=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    otp_token = data.get("otp_token", "")
    ip = _ip()

    if not all([username, password, otp_token]):
        log_and_emit("AUTH_FAILURE", username, ip, "Missing fields", "WARNING", False)
        return jsonify({"error": "Champs manquants"}), 400

    # AI anomaly detection
    is_anomaly, score, reason = detector.is_anomaly(ip, username)
    if is_anomaly and score > 0.8:
        log_and_emit("AI_BLOCK", username, ip, reason, "CRITICAL", False)
        return (
            jsonify({"error": f"Accès bloqué par l'IA: {reason}", "threat_level": "CRITIQUE"}),
            429,
        )

    hashed_pw = hashlib.sha256(password.encode()).hexdigest()

    otp_secret = get_otp_secret(username)
    if not otp_secret:
        log_and_emit("AUTH_FAILURE", username, ip, "User not found", "WARNING", False)
        return jsonify({"error": "Utilisateur introuvable"}), 404

    if not verify_otp(otp_secret, otp_token):
        log_and_emit("OTP_FAILURE", username, ip, "Invalid OTP", "WARNING", False)
        return jsonify({"error": "Code OTP invalide"}), 401

    # Blockchain Phase 1 — PoS weighted consensus (≥70%)
    success, percentage, node_results = network.phase1_verify(username, hashed_pw)
    if not success:
        log_and_emit(
            "BLOCKCHAIN_PHASE1_FAIL", username, ip,
            f"{percentage:.1f}% consensus", "WARNING", False,
        )
        return (
            jsonify(
                {
                    "success": False,
                    "error": f"Consensus insuffisant: {percentage:.1f}% (requis: 70%)",
                    "node_results": node_results,
                }
            ),
            401,
        )

    log_and_emit("BLOCKCHAIN_PHASE1_OK", username, ip, f"{percentage:.1f}% nodes", "INFO", True)

    user = db.users.find_one({"username": username})
    challenges_raw = network.phase2_challenge(user.get("public_key", ""))

    # Store challenges in MongoDB (stateless, Heroku safe)
    challenge_plain_map = {str(nid): info["challenge_plain"] for nid, info in challenges_raw.items()}
    challenge_id = create_challenge(username, challenge_plain_map)

    return jsonify(
        {
            "success": True,
            "challenge_id": challenge_id,
            "username": username,
            "phase1_percentage": round(percentage, 1),
            "node_results": node_results,
            "challenges": {
                str(nid): {
                    "node_id": nid,
                    "encrypted_challenge": info["challenge_encrypted"],
                }
                for nid, info in challenges_raw.items()
            },
        }
    )


# ─── Login Phase 2 : Challenge-Response RSA ───────────
@app.route("/api/login/step2", methods=["POST"])
@limiter.limit("15 per minute")
def login_step2():
    data = request.get_json(force=True) or {}
    signatures = data.get("signatures", {})
    username = data.get("username", "").strip()
    challenge_id = data.get("challenge_id", "")
    ip = _ip()

    if not username or not challenge_id:
        return jsonify({"error": "Données manquantes"}), 400

    original_challenges = get_challenge(username, challenge_id)
    if original_challenges is None:
        return jsonify({"error": "Challenge expiré ou invalide"}), 401

    user = db.users.find_one({"username": username})
    if not user:
        return jsonify({"error": "Utilisateur introuvable"}), 404

    user_public_key = user.get("public_key")
    all_valid, results = network.phase2_verify_all(signatures, original_challenges, user_public_key)

    if not all_valid:
        log_and_emit("BLOCKCHAIN_PHASE2_FAIL", username, ip, "Challenge failed", "CRITICAL", False)
        return jsonify({"success": False, "error": "Challenge cryptographique échoué", "results": results}), 401

    network.log_auth_event(username, ip, True, "Full blockchain auth OK")
    log_and_emit("AUTH_SUCCESS", username, ip, "2-phase blockchain auth", "INFO", True)

    import jwt
    token = jwt.encode(
        {"username": username, "exp": int(time.time()) + 3600, "iat": int(time.time())},
        app.secret_key,
        algorithm="HS256",
    )

    return jsonify(
        {
            "success": True,
            "token": token,
            "message": "Authentification blockchain réussie!",
            "challenge_results": results,
        }
    )


# ─── WebAuthn ─────────────────────────────────────────
@app.route("/api/webauthn/register/options", methods=["POST"])
def webauthn_reg_options():
    data = request.get_json(force=True) or {}
    username = data.get("username", "")
    user_id = str(uuid.uuid4())
    options = generate_registration_options(username, user_id)
    import webauthn as _wa
    options_json = _wa.options_to_json(options)
    session["webauthn_reg_challenge"] = json.loads(options_json)["challenge"]
    session["webauthn_username"] = username
    return options_json


@app.route("/api/webauthn/register/verify", methods=["POST"])
def webauthn_reg_verify():
    data = request.get_json(force=True) or {}
    username = data.get("username", session.get("webauthn_username", ""))
    credential = data.get("credential")
    challenge = session.get("webauthn_reg_challenge")
    try:
        verify_registration_response(username, credential, challenge)
        return jsonify({"success": True, "message": "Biométrie enregistrée!"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


# ─── Stats & Live API ─────────────────────────────────
@app.route("/api/stats", methods=["GET"])
def get_stats():
    return jsonify(network.get_stats())


@app.route("/api/events", methods=["GET"])
def get_events():
    limit = min(int(request.args.get("limit", 50)), 200)
    return jsonify(network.auth_events[-limit:])


@app.route("/api/blockchain/chain", methods=["GET"])
def get_chain():
    chain = [b.to_dict() for b in network.nodes[0].blockchain.chain]
    return jsonify(
        {
            "chain": chain,
            "length": len(chain),
            "valid": network.nodes[0].blockchain.is_valid(),
            "tampered_blocks": network.nodes[0].blockchain.tamper_detect(),
        }
    )


# ─── WebSocket /live ──────────────────────────────────
@socketio.on("connect", namespace="/live")
def handle_connect():
    emit("connected", {"status": "SOC Live connecté"})


@socketio.on("ping", namespace="/live")
def handle_ping():
    emit("pong", {"ts": time.time()})


# ─── Entry point ──────────────────────────────────────
if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    socketio.run(app, host="0.0.0.0", port=port, debug=False)