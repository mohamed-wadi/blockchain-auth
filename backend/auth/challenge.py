"""
challenge.py — stateless challenge store backed by MongoDB.
Challenges are stored with a short TTL (5 min) to be session-independent,
which is critical for Heroku where the session cookie may not be reliable
across multiple dynos.
"""
import uuid
import time
from database.mongo_client import get_cloud_db

TTL_SECONDS = 300  # 5 minutes


def create_challenge(username: str, challenges: dict) -> str:
    """
    Persist phase-2 challenges for a given username.
    Returns a challenge_id that the client sends back in step2.
    """
    db = get_cloud_db()
    challenge_id = str(uuid.uuid4())
    db.challenges.replace_one(
        {"username": username},
        {
            "challenge_id": challenge_id,
            "username": username,
            "challenges": {str(k): v for k, v in challenges.items()},
            "created_at": time.time(),
        },
        upsert=True,
    )
    # Create TTL index on first use (idempotent)
    try:
        db.challenges.create_index("created_at", expireAfterSeconds=TTL_SECONDS)
    except Exception:
        pass
    return challenge_id


def get_challenge(username: str, challenge_id: str) -> dict | None:
    """
    Retrieve and delete the stored challenges for username.
    Returns None if not found or expired.
    """
    db = get_cloud_db()
    doc = db.challenges.find_one_and_delete(
        {"username": username, "challenge_id": challenge_id}
    )
    if not doc:
        return None
    if time.time() - doc["created_at"] > TTL_SECONDS:
        return None
    return doc["challenges"]
