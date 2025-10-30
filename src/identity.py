#!/usr/bin/env python3
"""
Identity Management for Bee-Hive Network
Handles cryptographic identities, key generation, and credential storage.
"""
import json
import hashlib
import time
from pathlib import Path
from typing import Dict, Tuple
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


class IdentityManager:
    """Manages node identities with encrypted credentials.

    Per-node identity management: Each node maintains its own view of the network.
    - If alias provided: Operates on ~/.bee-hive/{alias}/identities.json (node-level)
    - If alias is None: Used for machine-level operations (listing all local nodes)
    """

    def __init__(self, alias: str = None):
        self.base_dir = Path("~/.bee-hive").expanduser()
        self.base_dir.mkdir(exist_ok=True)
        self.alias = alias

        if alias:
            # Per-node mode: Work with specific node's identities file
            self.node_dir = self.base_dir / alias
            self.identities_file = self.node_dir / "identities.json"
        else:
            # Machine mode: For CLI operations like listing nodes
            self.node_dir = None
            self.identities_file = None

    def validate_alias(self, alias: str) -> bool:
        """Validate alias format (alphanumeric + underscores/hyphens)."""
        if not alias or not alias.replace('_', '').replace('-', '').isalnum():
            return False
        return True

    def validate_email(self, email: str) -> bool:
        """Basic email validation."""
        return '@' in email and '.' in email.split('@')[1]

    @staticmethod
    def node_exists(alias: str) -> bool:
        """Check if a node exists on this machine (machine-level operation)."""
        node_dir = Path.home() / ".bee-hive" / alias
        return node_dir.exists() and (node_dir / "identities.json").exists()

    def get_local_identity(self) -> Dict:
        """Get the local identity for this node (node-level operation).

        Returns the single 'local' type identity from this node's identities.json.
        """
        if not self.alias:
            raise ValueError("Cannot get local identity in machine mode")

        identities = self._load_identities()
        for identity in identities.values():
            if identity.get("type") == "local":
                return identity
        raise ValueError(f"No local identity found for {self.alias}")

    def get_identity(self, alias: str) -> Dict:
        """Get any identity (local or peer) by alias."""
        identities = self._load_identities()
        if alias not in identities:
            raise ValueError(f"Identity '{alias}' not found")
        return identities[alias]

    def create_identity(self, alias: str, email: str, password: str, node_type: str) -> Dict:
        """Create new local identity for a node.

        Creates ~/.bee-hive/{alias}/identities.json with a single 'local' identity.
        """

        # Validate inputs
        if not self.validate_alias(alias):
            raise ValueError("Alias must be alphanumeric (underscores and hyphens allowed)")

        # TODO: Uncomment this
        # if not self.validate_email(email):
        #     raise ValueError("Invalid email format")

        # if len(password) < 8:
        #     raise ValueError("Password must be at least 8 characters")

        if node_type not in ['heavy', 'light']:
            raise ValueError("Node type must be 'heavy' or 'light'")

        # Check if already exists
        if self.node_exists(alias):
            raise ValueError(f"Node '{alias}' already exists")

        print(f"[Identity] Generating cryptographic keypair for @{alias}...")

        # Generate RSA keypair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        # Create identity directory
        identity_dir = self.base_dir / alias
        identity_dir.mkdir(exist_ok=True)
        keys_dir = identity_dir / "keys"
        keys_dir.mkdir(exist_ok=True)

        # Save unencrypted private key for node daemon use
        # (Protected by file permissions - 0600 means only owner can read/write)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        private_key_file = keys_dir / "private_key.pem"
        private_key_file.write_bytes(private_pem)
        private_key_file.chmod(0o600)  # Owner read/write only

        # Save public key
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_key_file = keys_dir / "public_key.pem"
        public_key_file.write_bytes(public_pem)
        public_key_file.chmod(0o644)  # Owner read/write, others read

        # Store password hash for verification (not for encryption)
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode(),
            email.encode(),
            100000
        ).hex()

        # Create identity record (type: "local" for this node)
        identity = {
            "type": "local",
            "alias": alias,
            "email": email,
            "email_hash": hashlib.sha256(email.encode()).hexdigest(),
            "password_hash": password_hash,
            "public_key": base64.b64encode(public_pem).decode('utf-8'),
            "node_type": node_type,
            "created": time.time(),
            "last_used": None,
            "identity_dir": str(identity_dir)
        }

        # Create per-node identities.json with only the local identity
        identities = {alias: identity}
        identities_file = identity_dir / "identities.json"
        identities_file.write_text(json.dumps(identities, indent=2))
        identities_file.chmod(0o600)

        print(f"[Identity] Created identity: @{alias} ({email})")
        print(f"[Identity] Keys stored in: {keys_dir}")
        print(f"[Identity] Identities stored in: {identities_file}")

        return identity

    def verify_identity(self, password: str) -> Dict:
        """Verify local identity password (node-level operation)."""
        if not self.alias:
            raise ValueError("Cannot verify identity in machine mode")

        identity = self.get_local_identity()
        email = identity["email"]

        # Verify password hash
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode(),
            email.encode(),
            100000
        ).hex()

        if password_hash != identity.get("password_hash"):
            raise ValueError("Invalid password")

        # Update last used
        identity["last_used"] = time.time()
        identities = self._load_identities()
        identities[self.alias] = identity
        self._save_identities(identities)

        print(f"[Identity] Verified identity: @{self.alias}")

        return identity

    def get_key_paths(self) -> Tuple[str, str]:
        """Get paths to key files for the local identity (node-level operation)."""
        if not self.alias:
            raise ValueError("Cannot get key paths in machine mode")

        identity = self.get_local_identity()
        identity_dir = Path(identity["identity_dir"])
        keys_dir = identity_dir / "keys"

        private_key_file = keys_dir / "private_key.pem"
        public_key_file = keys_dir / "public_key.pem"

        if not private_key_file.exists():
            raise ValueError(f"Private key for '{self.alias}' not found")
        if not public_key_file.exists():
            raise ValueError(f"Public key for '{self.alias}' not found")

        return str(private_key_file), str(public_key_file)

    @staticmethod
    def get_key_paths_for_alias(alias: str) -> Tuple[str, str]:
        """Get paths to key files for any alias (machine-level operation)."""
        identity_dir = Path.home() / ".bee-hive" / alias
        keys_dir = identity_dir / "keys"

        private_key_file = keys_dir / "private_key.pem"
        public_key_file = keys_dir / "public_key.pem"

        if not private_key_file.exists():
            raise ValueError(f"Private key for '{alias}' not found")
        if not public_key_file.exists():
            raise ValueError(f"Public key for '{alias}' not found")

        return str(private_key_file), str(public_key_file)

    # === Peer Identity Management (NEW) ===

    def add_peer_identity(self, peer_alias: str, public_key_pem: bytes, node_type: str):
        """Add or update a peer identity in this node's identities.json.

        Args:
            peer_alias: Alias of the peer node
            public_key_pem: Public key in PEM format (bytes)
            node_type: Type of node ('heavy' or 'light')
        """
        if not self.alias:
            raise ValueError("Cannot add peer in machine mode")

        identities = self._load_identities()

        # Don't overwrite local identity
        if peer_alias in identities and identities[peer_alias].get("type") == "local":
            return

        now = time.time()

        if peer_alias in identities:
            # Update existing peer
            identities[peer_alias]["public_key"] = base64.b64encode(public_key_pem).decode()
            identities[peer_alias]["node_type"] = node_type
            identities[peer_alias]["last_seen"] = now
        else:
            # Add new peer
            identities[peer_alias] = {
                "type": "peer",
                "alias": peer_alias,
                "public_key": base64.b64encode(public_key_pem).decode(),
                "node_type": node_type,
                "first_seen": now,
                "last_seen": now
            }

        self._save_identities(identities)

    def get_peer_identity(self, peer_alias: str) -> Dict:
        """Get a peer identity."""
        identities = self._load_identities()
        if peer_alias in identities and identities[peer_alias].get("type") == "peer":
            return identities[peer_alias]
        return None

    def list_peer_identities(self) -> Dict[str, Dict]:
        """List all peer identities known to this node."""
        identities = self._load_identities()
        return {k: v for k, v in identities.items() if v.get("type") == "peer"}

    def get_all_identities(self) -> Dict[str, Dict]:
        """Get both local and peer identities."""
        return self._load_identities()

    # === Machine-Level Operations ===

    @staticmethod
    def list_local_nodes() -> list:
        """List all nodes registered on this machine (machine-level operation).

        Returns list of local identities from all nodes on this machine.
        """
        base_dir = Path.home() / ".bee-hive"
        local_nodes = []

        if not base_dir.exists():
            return local_nodes

        for node_dir in base_dir.iterdir():
            if node_dir.is_dir():
                identities_file = node_dir / "identities.json"
                if identities_file.exists():
                    try:
                        identities = json.loads(identities_file.read_text())
                        # Find the local identity for this node
                        for identity in identities.values():
                            if identity.get("type") == "local":
                                local_nodes.append(identity)
                                break
                    except (json.JSONDecodeError, KeyError):
                        continue

        return local_nodes

    def _load_identities(self) -> Dict:
        """Load identities registry for this node."""
        if not self.identities_file:
            raise ValueError("Cannot load identities in machine mode")

        if self.identities_file.exists():
            return json.loads(self.identities_file.read_text())
        return {}

    def _save_identities(self, identities: Dict):
        """Save identities registry for this node."""
        if not self.identities_file:
            raise ValueError("Cannot save identities in machine mode")

        self.identities_file.write_text(json.dumps(identities, indent=2))
        self.identities_file.chmod(0o600)
