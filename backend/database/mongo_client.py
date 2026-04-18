from pymongo import MongoClient
import os

_cloud_client = None
_local_clients = {}

def get_cloud_db():
    global _cloud_client
    if not _cloud_client:
        uri = os.getenv("MONGO_URI")
        _cloud_client = MongoClient(uri)
    return _cloud_client["blockchain_auth"]

def get_local_db(node_id):
    """Chaque node a sa propre collection locale (simule DB locale)"""
    if node_id not in _local_clients:
        uri = os.getenv("MONGO_URI")
        client = MongoClient(uri)
        _local_clients[node_id] = client["blockchain_auth_local"][f"node_{node_id}"]
    return _local_clients[node_id]

def sync_nodes(username, hashed_password, public_key):
    """Synchronise l'utilisateur dans tous les nodes (simulation réseau)"""
    db = get_cloud_db()
    user_doc = {
        "username": username,
        "password": hashed_password,
        "public_key": public_key
    }
    for node_id in range(1, 6):
        local = get_local_db(node_id)
        local.update_one(
            {"username": username},
            {"$set": user_doc},
            upsert=True
        )