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
    """Manages node identities with encrypted credentials."""

    def __init__(self, storage_dir: str = "~/.bee-hive"):
        self.storage_dir = Path(storage_dir).expanduser()
        self.storage_dir.mkdir(exist_ok=True)
        self.identities_file = self.storage_dir / "identities.json"

    def validate_alias(self, alias: str) -> bool:
        """Validate alias format (alphanumeric + underscores/hyphens)."""
        if not alias or not alias.replace('_', '').replace('-', '').isalnum():
            return False
        return True

    def validate_email(self, email: str) -> bool:
        """Basic email validation."""
        return '@' in email and '.' in email.split('@')[1]

    def identity_exists(self, alias: str) -> bool:
        """Check if identity exists."""
        identities = self._load_identities()
        return alias in identities

    def get_identity(self, alias: str) -> Dict:
        """Get identity information by alias."""
        identities = self._load_identities()
        if alias not in identities:
            raise ValueError(f"Identity '{alias}' not found")
        return identities[alias]

    def create_identity(self, alias: str, email: str, password: str, node_type: str) -> Dict:
        """Create new identity with validation."""

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
        if self.identity_exists(alias):
            raise ValueError(f"Identity '{alias}' already exists")

        print(f"[Identity] Generating cryptographic keypair for @{alias}...")

        # Generate RSA keypair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        # Create identity directory
        identity_dir = self.storage_dir / alias
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

        # Create identity record
        identity = {
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

        # Save to identities registry
        identities = self._load_identities()
        identities[alias] = identity
        self._save_identities(identities)

        print(f"[Identity] Created identity: @{alias} ({email})")
        print(f"[Identity] Keys stored in: {keys_dir}")

        return identity

    def verify_identity(self, alias: str, password: str) -> Dict:
        """Verify identity with password."""
        identities = self._load_identities()

        if alias not in identities:
            raise ValueError(f"Identity '{alias}' not found")

        identity = identities[alias]
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
        identities[alias] = identity
        self._save_identities(identities)

        print(f"[Identity] Verified identity: @{alias}")

        return identity

    def get_key_paths(self, alias: str) -> Tuple[str, str]:
        """Get paths to key files for a given alias."""
        identities = self._load_identities()

        if alias not in identities:
            raise ValueError(f"Identity '{alias}' not found")

        identity = identities[alias]
        identity_dir = Path(identity["identity_dir"])
        keys_dir = identity_dir / "keys"

        private_key_file = keys_dir / "private_key.pem"
        public_key_file = keys_dir / "public_key.pem"

        if not private_key_file.exists():
            raise ValueError(f"Private key for '{alias}' not found")
        if not public_key_file.exists():
            raise ValueError(f"Public key for '{alias}' not found")

        return str(private_key_file), str(public_key_file)

    def delete_identity(self, alias: str, password: str) -> bool:
        """Delete an identity after password verification."""
        # Verify password first
        self.verify_identity(alias, password)

        identities = self._load_identities()
        if alias not in identities:
            raise ValueError(f"Identity '{alias}' not found")

        identity = identities[alias]
        identity_dir = Path(identity["identity_dir"])

        # Remove identity directory and all contents (keys, etc.)
        if identity_dir.exists():
            import shutil
            shutil.rmtree(identity_dir)
            print(f"[Identity] Removed keys and data for @{alias}")

        # Remove from registry
        del identities[alias]
        self._save_identities(identities)

        print(f"[Identity] Deleted identity: @{alias}")
        return True

    def _load_identities(self) -> Dict:
        """Load identities registry."""
        if self.identities_file.exists():
            return json.loads(self.identities_file.read_text())
        return {}

    def _save_identities(self, identities: Dict):
        """Save identities registry."""
        self.identities_file.write_text(json.dumps(identities, indent=2))
        self.identities_file.chmod(0o600)
