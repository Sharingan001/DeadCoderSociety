import hashlib
import json
import time
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# CP-003 Block
# Hash formula: SHA256(previous_hash + timestamp + actor + action)
# ---------------------------------------------------------------------------

class Block:
    def __init__(self, index, previous_hash, timestamp, actor, action, data=None, nonce=0):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp          # ISO-8601 string
        self.actor = actor                  # username@host or IP
        self.action = action                # event type string
        self.data = data or {}             # extra payload (optional)
        self.nonce = nonce
        self.hash = self.calculate_hash()

    # CP-003: SHA256(previous_hash + timestamp + actor + action)
    def calculate_hash(self):
        raw = self.previous_hash + self.timestamp + self.actor + self.action + str(self.nonce)
        return hashlib.sha256(raw.encode('utf-8')).hexdigest()

    def to_dict(self):
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "actor": self.actor,
            "action": self.action,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "current_hash": self.hash,
            "nonce": self.nonce,
        }


# ---------------------------------------------------------------------------
# Blockchain — CP-003 compliant, with Polygon anchor support
# ---------------------------------------------------------------------------

class Blockchain:
    def __init__(self, difficulty=2, anchor_interval=100):
        self.chain = []
        self.difficulty = difficulty
        self.anchor_interval = anchor_interval   # every N blocks → Polygon anchor
        self.anchors = []                        # list of {block_index, merkle_root, tx_hash}
        self._polygon_client = None              # set externally if web3 is available
        self.create_genesis_block()

    # ------------------------------------------------------------------
    # Genesis
    # ------------------------------------------------------------------
    def create_genesis_block(self):
        ts = datetime.now(timezone.utc).isoformat()
        genesis = Block(
            index=0,
            previous_hash="0",
            timestamp=ts,
            actor="system",
            action="genesis",
            data={"note": "LogSentinel Pro — Genesis Block"},
        )
        self._mine(genesis)
        self.chain.append(genesis)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _now_iso(self):
        return datetime.now(timezone.utc).isoformat()

    def _mine(self, block):
        target = "0" * self.difficulty
        while not block.hash.startswith(target):
            block.nonce += 1
            block.hash = block.calculate_hash()

    def get_latest_block(self):
        return self.chain[-1]

    # ------------------------------------------------------------------
    # Add any event (CP-003 — chains everything, not just alerts)
    # ------------------------------------------------------------------
    def add_event(self, actor: str, action: str, data: dict = None):
        """Add any event to the hash chain.

        Args:
            actor:  username@host or source IP
            action: event type, e.g. 'login_attempt', 'file_access', 'soar_block_ip'
            data:   optional extra payload dict
        """
        latest = self.get_latest_block()
        new_block = Block(
            index=latest.index + 1,
            previous_hash=latest.hash,
            timestamp=self._now_iso(),
            actor=actor,
            action=action,
            data=data or {},
        )
        self._mine(new_block)
        self.chain.append(new_block)

        # Check if we should anchor to Polygon
        if len(self.chain) % self.anchor_interval == 0:
            self._anchor_to_polygon()

        return new_block

    # ------------------------------------------------------------------
    # Chain validity (CP-003)
    # ------------------------------------------------------------------
    def is_chain_valid(self):
        """Recompute every hash and verify PoW + linkage."""
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            if current.hash != current.calculate_hash():
                return False
            if current.previous_hash != previous.hash:
                return False
            if not current.hash.startswith("0" * self.difficulty):
                return False
        return True

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------
    def export_ledger(self, filepath):
        with open(filepath, 'w') as f:
            json.dump([b.to_dict() for b in self.chain], f, indent=4)

    # ------------------------------------------------------------------
    # Polygon Root Anchor (Merkle root of last N block hashes → testnet)
    # ------------------------------------------------------------------
    def _compute_merkle_root(self, hashes):
        """Binary Merkle tree — returns root hash."""
        if not hashes:
            return ""
        layer = list(hashes)
        while len(layer) > 1:
            if len(layer) % 2 != 0:
                layer.append(layer[-1])   # duplicate last if odd
            next_layer = []
            for i in range(0, len(layer), 2):
                combined = layer[i] + layer[i + 1]
                next_layer.append(hashlib.sha256(combined.encode()).hexdigest())
            layer = next_layer
        return layer[0]

    def _anchor_to_polygon(self):
        """Compute Merkle root of last `anchor_interval` blocks and
        submit to Polygon Mumbai testnet.  Stores tx_hash as proof."""
        n = self.anchor_interval
        recent_hashes = [b.hash for b in self.chain[-n:]]
        merkle_root = self._compute_merkle_root(recent_hashes)
        anchor_block_index = self.chain[-1].index

        tx_hash = None
        if self._polygon_client is not None:
            try:
                tx_hash = self._polygon_client.submit_root(merkle_root)
            except Exception as e:
                tx_hash = f"error:{e}"
        else:
            # Offline simulation — store locally for now
            tx_hash = "polygon_offline_" + merkle_root[:16]

        record = {
            "block_index": anchor_block_index,
            "merkle_root": merkle_root,
            "tx_hash": tx_hash,
            "anchored_at": self._now_iso(),
        }
        self.anchors.append(record)
        print(f"[Polygon Anchor] block={anchor_block_index} merkle={merkle_root[:16]}... tx={tx_hash}")
        return record

    def get_anchors(self):
        return list(self.anchors)

    # ------------------------------------------------------------------
    # Chain Integrity Verifier — full audit with Polygon cross-reference
    # ------------------------------------------------------------------
    def verify_chain(self):
        """Recompute all hashes from genesis, verify PoW nonces,
        and cross-reference with stored Polygon anchors.

        Returns:
            dict with keys:
                valid (bool), tampered_blocks (list[int]),
                pow_failures (list[int]), anchor_results (list[dict])
        """
        tampered = []
        pow_failures = []

        for i in range(1, len(self.chain)):
            block = self.chain[i]

            # 1. Recompute and compare
            recomputed = block.calculate_hash()
            if recomputed != block.hash:
                tampered.append(block.index)

            # 2. Verify PoW
            if not block.hash.startswith("0" * self.difficulty):
                pow_failures.append(block.index)

            # 3. Verify linkage
            if block.previous_hash != self.chain[i - 1].hash:
                if block.index not in tampered:
                    tampered.append(block.index)

        # 4. Cross-reference Polygon anchors
        anchor_results = []
        for anchor in self.anchors:
            idx = anchor["block_index"]
            n = self.anchor_interval
            start = max(0, idx - n + 1)
            window = [b.hash for b in self.chain[start: idx + 1]]
            recomputed_root = self._compute_merkle_root(window)
            match = recomputed_root == anchor["merkle_root"]
            anchor_results.append({
                "block_index": idx,
                "merkle_match": match,
                "stored_root": anchor["merkle_root"],
                "recomputed_root": recomputed_root,
                "tx_hash": anchor["tx_hash"],
            })

        overall_valid = (not tampered) and (not pow_failures) and all(
            a["merkle_match"] for a in anchor_results
        )

        return {
            "valid": overall_valid,
            "tampered_blocks": tampered,
            "pow_failures": pow_failures,
            "anchor_results": anchor_results,
        }
