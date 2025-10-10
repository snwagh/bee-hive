#!/usr/bin/env python3
import asyncio
import json
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional
import nats
import msgpack
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import secrets
from loguru import logger
from db import ComputationDB

class BaseNode:
    """Base class for all nodes in the network."""

    def __init__(self, node_id: str, nats_url: str, data_dir: str, private_key_path: str, public_key_path: str):
        self.node_id = node_id
        self.nats_url = nats_url
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # Setup logging
        log_path = self.data_dir / "node.log"
        logger.add(
            log_path,
            format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {message}",
            level="DEBUG",
            rotation="10 MB",
            retention="7 days",
        )
        logger.info(f"[{node_id}] Initializing base node")

        # Initialize database
        db_path = self.data_dir / "local.db"
        self.db = ComputationDB(db_path)
        logger.info(f"[{node_id}] Database initialized at {db_path}")

        # NATS connections
        self.nc: Optional[nats.NATS] = None
        self.js = None

        # Encryption keys - load from provided paths
        self.private_key = None
        self.public_key = None
        self.peer_keys: Dict[str, bytes] = {}  # node_id -> public_key

        # Load keys on initialization
        self._load_keys_from_paths(private_key_path, public_key_path)

        # State
        self.shutdown_event = asyncio.Event()
        self.active_computations: Dict[str, Any] = {}

        # IPC for CLI
        self.ipc_socket_path = Path(f"/tmp/flower-node-{node_id}.sock")
        self.ipc_server = None

    def _load_keys_from_paths(self, private_key_path: str, public_key_path: str):
        """Load keys from specified paths (created by IdentityManager)."""
        private_path = Path(private_key_path)
        public_path = Path(public_key_path)

        if not private_path.exists():
            raise ValueError(f"Private key not found at {private_path}")
        if not public_path.exists():
            raise ValueError(f"Public key not found at {public_path}")

        # Load private key (unencrypted for node daemon use)
        with open(private_path, 'rb') as f:
            self.private_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )

        # Load public key
        with open(public_path, 'rb') as f:
            self.public_key = serialization.load_pem_public_key(
                f.read(), backend=default_backend()
            )

        logger.info(f"[{self.node_id}] Keys loaded from identity")
    
    def encrypt_for_peer(self, data: bytes, peer_id: str) -> Dict[str, str]:
        """Encrypt data for a specific peer using hybrid encryption."""
        if peer_id not in self.peer_keys:
            logger.error(f"[{self.node_id}] Cannot encrypt for {peer_id}: no public key (known peers: {list(self.peer_keys.keys())})")
            return {"error": f"No public key for peer {peer_id}"}

        # Generate AES key
        aes_key = secrets.token_bytes(32)  # 256-bit key
        iv = secrets.token_bytes(16)  # 128-bit IV
        
        # Encrypt data with AES
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Pad data to multiple of 16 bytes
        pad_len = 16 - (len(data) % 16)
        padded_data = data + bytes([pad_len] * pad_len)
        
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Encrypt AES key with peer's RSA public key
        peer_public_key = serialization.load_pem_public_key(
            self.peer_keys[peer_id], backend=default_backend()
        )
        encrypted_key = peer_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return {
            "encrypted_data": base64.b64encode(encrypted_data).decode(),
            "encrypted_key": base64.b64encode(encrypted_key).decode(),
            "iv": base64.b64encode(iv).decode(),
            "sender": self.node_id
        }
    
    def decrypt_from_peer(self, encrypted_msg: Dict[str, str]) -> bytes:
        """Decrypt data from a peer."""
        # Decode from base64
        encrypted_data = base64.b64decode(encrypted_msg["encrypted_data"])
        encrypted_key = base64.b64decode(encrypted_msg["encrypted_key"])
        iv = base64.b64decode(encrypted_msg["iv"])
        
        # Decrypt AES key with our RSA private key
        aes_key = self.private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Decrypt data with AES
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # Remove padding
        pad_len = padded_data[-1]
        data = padded_data[:-pad_len]
        
        return data
    
    async def connect_nats(self):
        """Connect to NATS server."""
        self.nc = await nats.connect(self.nats_url)
        self.js = self.nc.jetstream()
        logger.info(f"[{self.node_id}] Connected to NATS at {self.nats_url}")

        # Create streams
        try:
            await self.js.add_stream(
                name="COMPUTATIONS",
                subjects=["comp.>"],
                retention="limits",
                max_msgs=1000,
            )
        except:
            pass  # Stream exists

        # Subscribe to peer registrations BEFORE registering (to avoid missing early nodes)
        await self.nc.subscribe("node.register", cb=self._handle_peer_registration)

        # Register and share public key
        await self.register_node()
    
    async def register_node(self):
        """Register node and share public key."""
        public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Store own public key for self-communication (when node is both aggregator and target)
        self.peer_keys[self.node_id] = public_key_pem
        logger.debug(f"[{self.node_id}] Stored own public key for self-communication")

        registration = {
            "node_id": self.node_id,
            "public_key": base64.b64encode(public_key_pem).decode(),
            "timestamp": datetime.utcnow().isoformat(),
            "node_type": self.get_node_type()
        }

        await self.nc.publish("node.register", msgpack.packb(registration))
        logger.info(f"[{self.node_id}] Registered with public key")
    
    async def _handle_peer_registration(self, msg):
        """Store peer public keys."""
        try:
            data = msgpack.unpackb(msg.data)
            peer_id = data["node_id"]

            if peer_id != self.node_id:
                public_key_pem = base64.b64decode(data["public_key"])
                self.peer_keys[peer_id] = public_key_pem
                logger.info(f"[{self.node_id}] Stored public key for {peer_id}")
        except Exception as e:
            logger.error(f"[{self.node_id}] Error handling registration: {e}")

    async def _refresh_peers_periodically(self):
        """Periodically re-publish registration to keep network view updated."""
        while not self.shutdown_event.is_set():
            try:
                await asyncio.sleep(30)  # Refresh every 30 seconds

                if self.shutdown_event.is_set():
                    break

                # Re-publish registration
                public_key_pem = self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )

                registration = {
                    "node_id": self.node_id,
                    "public_key": base64.b64encode(public_key_pem).decode(),
                    "timestamp": datetime.utcnow().isoformat(),
                    "node_type": self.get_node_type()
                }

                await self.nc.publish("node.register", msgpack.packb(registration))
                logger.info(f"[{self.node_id}] Peers refreshed (known peers: {len(self.peer_keys)})")

            except Exception as e:
                if not self.shutdown_event.is_set():
                    logger.error(f"[{self.node_id}] Error refreshing peers: {e}")
    
    async def start_ipc_server(self):
        """Start Unix socket server for CLI."""
        if self.ipc_socket_path.exists():
            self.ipc_socket_path.unlink()
        
        self.ipc_server = await asyncio.start_unix_server(
            self._handle_ipc_client,
            path=str(self.ipc_socket_path)
        )
        os.chmod(str(self.ipc_socket_path), 0o666)
        logger.info(f"[{self.node_id}] IPC server on {self.ipc_socket_path}")
    
    async def _handle_ipc_client(self, reader, writer):
        """Handle CLI commands."""
        try:
            data = await reader.read(65536)
            command = json.loads(data.decode())
            
            if command['type'] == 'submit':
                result = await self._submit_computation(command['data'])
            elif command['type'] == 'status':
                result = {
                    "node_id": self.node_id,
                    "type": self.get_node_type(),
                    "connected": self.nc.is_connected if self.nc else False,
                    "active": len(self.active_computations),
                    "peers": len(self.peer_keys)
                }
            elif command['type'] == 'list':
                result = {"computations": list(self.active_computations.keys())}
            else:
                result = {"error": f"Unknown command: {command['type']}"}
            
            writer.write(json.dumps(result).encode())
            await writer.drain()
        except Exception as e:
            writer.write(json.dumps({"error": str(e)}).encode())
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()
    
    async def _submit_computation(self, data: dict):
        """Submit computation to network - to be overridden."""
        raise NotImplementedError("Must be implemented by subclass")
    
    def get_node_type(self) -> str:
        """Return node type - to be overridden."""
        return "base"
    
    async def shutdown(self):
        """Graceful shutdown."""
        logger.info(f"[{self.node_id}] Shutting down...")

        if self.nc:
            try:
                if self.nc.is_connected:
                    await self.nc.flush()
                await self.nc.close()
            except Exception as e:
                logger.error(f"[{self.node_id}] Error during NATS shutdown: {e}")
        
        if self.ipc_server:
            self.ipc_server.close()
            await self.ipc_server.wait_closed()
            if self.ipc_socket_path.exists():
                self.ipc_socket_path.unlink()

        # Close database connection
        if self.db:
            self.db.close()
            logger.info(f"[{self.node_id}] Database closed")

        self.shutdown_event.set()
    
    async def run(self):
        """Main run loop - to be overridden."""
        raise NotImplementedError("Must be implemented by subclass")
