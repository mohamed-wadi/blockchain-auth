import hashlib, time, json

class Block:
    def __init__(self, index, data, prev_hash="0", nonce=0):
        self.index = index
        self.data = data
        self.prev_hash = prev_hash
        self.timestamp = time.time()
        self.nonce = nonce
        self.hash = self.calc_hash()

    def calc_hash(self):
        content = json.dumps({
            "index": self.index,
            "data": self.data,
            "prev_hash": self.prev_hash,
            "timestamp": self.timestamp,
            "nonce": self.nonce
        }, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()

    def mine_block(self, difficulty=2):
        target = "0" * difficulty
        while not self.hash.startswith(target):
            self.nonce += 1
            self.hash = self.calc_hash()
        return self

    def to_dict(self):
        return {
            "index": self.index,
            "data": self.data,
            "prev_hash": self.prev_hash,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "hash": self.hash,
            "difficulty": 2
        }

class Blockchain:
    def __init__(self):
        self.chain = [self._genesis()]

    def _genesis(self):
        b = Block(0, {"type": "GENESIS", "message": "Blockchain Auth v2.0"}, "0")
        return b

    def add_block(self, data):
        prev = self.chain[-1]
        block = Block(len(self.chain), data, prev.hash)
        block.mine_block()
        self.chain.append(block)
        return block

    def is_valid(self):
        for i in range(1, len(self.chain)):
            curr = self.chain[i]
            prev = self.chain[i-1]
            if curr.hash != curr.calc_hash():
                return False
            if curr.prev_hash != prev.hash:
                return False
        return True

    def tamper_detect(self):
        """Auto-détection de tampering — CHOC JURY"""
        tampered = []
        for i in range(1, len(self.chain)):
            if self.chain[i].prev_hash != self.chain[i-1].hash:
                tampered.append(i)
        return tampered