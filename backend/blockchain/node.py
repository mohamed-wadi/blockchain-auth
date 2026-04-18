import hashlib, json, random, time, uuid
from blockchain.block import Blockchain
from auth.crypto_utils import generate_keypair, encrypt_challenge, verify_signature
from database.mongo_client import get_local_db

class Node:
    def __init__(self, node_id, host, port, stake=None):
        self.node_id = node_id
        self.host = host
        self.port = port
        self.stake = stake or random.randint(10, 100)
        self.blockchain = Blockchain()
        self.peers = []
        self.public_key, self.private_key = generate_keypair()
        self.db = get_local_db(node_id)
        self.status = "active"
        self.verified_count = 0

    def verify_credentials(self, username, hashed_password):
        try:
            user = self.db.find_one({"username": username})
            if user and user.get("password") == hashed_password:
                self.verified_count += 1
                return True
            return False
        except Exception:
            return False

    def generate_challenge(self):
        return str(uuid.uuid4())

    def to_dict(self):
        return {
            "node_id": self.node_id,
            "host": self.host,
            "port": self.port,
            "stake": self.stake,
            "public_key": self.public_key,
            "status": self.status,
            "verified_count": self.verified_count,
            "chain_length": len(self.blockchain.chain)
        }


class BlockchainNetwork:
    def __init__(self):
        self.nodes = []
        self.auth_events = []
        self._init_nodes()

    def _init_nodes(self):
        stakes = [85, 77, 62, 55, 41]
        for i in range(1, 6):
            node = Node(
                node_id=i,
                host="localhost",
                port=6000 + i,
                stake=stakes[i-1]
            )
            self.nodes.append(node)
        for node in self.nodes:
            node.peers = [n.to_dict() for n in self.nodes if n.node_id != node.node_id]

    def select_leader(self):
        return max(self.nodes, key=lambda n: n.stake)

    def phase1_verify(self, username, hashed_password):
        confirmations = []
        node_results = []
        for node in self.nodes:
            result = node.verify_credentials(username, hashed_password)
            confirmations.append(result)
            node_results.append({
                "node_id": node.node_id,
                "confirmed": result,
                "stake": node.stake
            })
        true_count = sum(confirmations)
        percentage = (true_count / len(self.nodes)) * 100
        return percentage >= 70, percentage, node_results

    def phase2_challenge(self, user_public_key_pem):
        challenges = {}
        for node in self.nodes:
            challenge_str = node.generate_challenge()
            encrypted = encrypt_challenge(challenge_str, user_public_key_pem)
            challenges[node.node_id] = {
                "node_id": node.node_id,
                "challenge_plain": challenge_str,
                "challenge_encrypted": encrypted
            }
        return challenges

    def phase2_verify_all(self, signatures, original_challenges, user_public_key):
        results = {}
        all_valid = True
        for node in self.nodes:
            nid = str(node.node_id)
            sig = signatures.get(nid)
            original = original_challenges.get(nid)
            if not sig or not original:
                results[nid] = False
                all_valid = False
                continue
            valid = verify_signature(original, sig, user_public_key)
            results[nid] = valid
            if not valid:
                all_valid = False
        return all_valid, results

    def log_auth_event(self, username, ip, success, details, country=None):
        event = {
            "id": str(uuid.uuid4()),
            "timestamp": time.time(),
            "event_type": "AUTH_SUCCESS" if success else "AUTH_FAILURE",
            "username": username,
            "source_ip": ip,
            "country": country or "Unknown",
            "details": details,
            "success": success
        }
        self.auth_events.append(event)
        if len(self.auth_events) > 200:
            self.auth_events = self.auth_events[-200:]
        if success:
            self.nodes[0].blockchain.add_block({
                "type": "AUTH_SUCCESS",
                "username": username,
                "ip": ip,
                "timestamp": event["timestamp"]
            })
        return event

    def get_stats(self):
        total = len(self.auth_events)
        success = sum(1 for e in self.auth_events if e.get("success"))
        attacks = sum(1 for e in self.auth_events if not e.get("success"))
        return {
            "total_auth": total,
            "success": success,
            "failures": attacks,
            "nodes": [n.to_dict() for n in self.nodes],
            "leader": self.select_leader().to_dict(),
            "chain_length": len(self.nodes[0].blockchain.chain),
            "chain_valid": self.nodes[0].blockchain.is_valid()
        }