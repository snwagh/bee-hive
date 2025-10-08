#!/usr/bin/env python3
"""
Beehive Network - Authenticated P2P Node with End-to-End Encryption
Supports persistent identities, cryptographic authentication, and encrypted messaging
"""

import asyncio
import json
import sys
import time
import os
import hashlib
import base64
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
from datetime import datetime
from nats.aio.client import Client as NATS
from uuid import uuid4

# For cryptographic operations - install with: pip install cryptography nats-py
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


class IdentityManager:
    """Manages persistent cryptographic identities"""
    
    def __init__(self, storage_dir: str = "~/.beehive"):
        self.storage_dir = Path(storage_dir).expanduser()
        self.storage_dir.mkdir(exist_ok=True)
        self.identities_file = self.storage_dir / "identities.json"
        self.keys_dir = self.storage_dir / "keys"
        self.keys_dir.mkdir(exist_ok=True)
        
    def create_identity(self, handle: str, email: str, password: str) -> Dict:
        """Create a new identity with cryptographic keypair"""
        
        # Validate handle
        if not handle or not handle.replace('_', '').isalnum():
            raise ValueError("Handle must be alphanumeric (underscores allowed)")
        
        # Check if identity already exists
        if self.identity_exists(handle):
            raise ValueError(f"Identity {handle} already exists")
        
        print("Generating cryptographic keypair...")
        
        # Generate RSA keypair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        
        # Derive encryption password from user password
        key_password = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode(),
            email.encode(),
            100000
        ).hex()
        
        # Save private key (encrypted with password)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(
                key_password.encode()
            )
        )
        
        private_key_file = self.keys_dir / f"{handle}.key"
        private_key_file.write_bytes(private_pem)
        private_key_file.chmod(0o600)  # Restrict access to owner only
        
        # Save public key
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        public_key_file = self.keys_dir / f"{handle}.pub"
        public_key_file.write_bytes(public_pem)
        
        # Create identity record
        identity = {
            "handle": handle,
            "email": email,
            "email_hash": hashlib.sha256(email.encode()).hexdigest(),
            "public_key": base64.b64encode(public_pem).decode('utf-8'),
            "created": time.time(),
            "node_id": str(uuid4()),
            "last_used": None
        }
        
        # Save to identities file
        identities = self._load_identities()
        identities[handle] = identity
        self._save_identities(identities)
        
        print(f"✅ Created identity: @{handle} ({email})")
        print(f"   Private key saved to: {private_key_file}")
        print(f"   ⚠️  Keep your password safe! It cannot be recovered.")
        
        return identity
    
    def load_identity(self, handle: str, password: str) -> Tuple[Dict, Any, Any]:
        """Load an existing identity with authentication"""
        
        identities = self._load_identities()
        if handle not in identities:
            raise ValueError(f"Identity {handle} not found")
        
        identity = identities[handle]
        email = identity["email"]
        
        # Derive key password
        key_password = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode(),
            email.encode(),
            100000
        ).hex()
        
        # Load private key
        private_key_file = self.keys_dir / f"{handle}.key"
        if not private_key_file.exists():
            raise ValueError(f"Private key for {handle} not found")
        
        try:
            private_key = serialization.load_pem_private_key(
                private_key_file.read_bytes(),
                password=key_password.encode()
            )
        except Exception as e:
            raise ValueError(f"Invalid password for identity {handle}")
        
        # Load public key
        public_key_file = self.keys_dir / f"{handle}.pub"
        public_key = serialization.load_pem_public_key(
            public_key_file.read_bytes()
        )
        
        # Update last used timestamp
        identity["last_used"] = time.time()
        identities[handle] = identity
        self._save_identities(identities)
        
        print(f"✅ Authenticated as @{handle} ({email})")
        
        return identity, private_key, public_key
    
    def identity_exists(self, handle: str) -> bool:
        """Check if an identity exists"""
        identities = self._load_identities()
        return handle in identities
    
    def delete_identity(self, handle: str, password: str) -> bool:
        """Delete an identity (requires password verification)"""
        try:
            # Verify password first
            self.load_identity(handle, password)
            
            # Delete files
            private_key_file = self.keys_dir / f"{handle}.key"
            public_key_file = self.keys_dir / f"{handle}.pub"
            
            if private_key_file.exists():
                private_key_file.unlink()
            if public_key_file.exists():
                public_key_file.unlink()
            
            # Remove from identities
            identities = self._load_identities()
            if handle in identities:
                del identities[handle]
                self._save_identities(identities)
            
            print(f"✅ Deleted identity: @{handle}")
            return True
            
        except ValueError as e:
            print(f"❌ Failed to delete identity: {e}")
            return False
    
    def _load_identities(self) -> Dict:
        """Load all registered identities"""
        if self.identities_file.exists():
            return json.loads(self.identities_file.read_text())
        return {}
    
    def _save_identities(self, identities: Dict):
        """Save identities to file"""
        self.identities_file.write_text(json.dumps(identities, indent=2))
        self.identities_file.chmod(0o600)  # Restrict access
    
    def list_identities(self):
        """List all registered identities"""
        identities = self._load_identities()
        if not identities:
            print("No identities registered")
            print("Run with 'register' to create a new identity")
            return
        
        print("\n╔═══════════════════════════════════════════════════╗")
        print("║          Registered Identities                    ║")
        print("╠═══════════════════════════════════════════════════╣")
        
        for handle, info in identities.items():
            created = datetime.fromtimestamp(info["created"]).strftime("%Y-%m-%d %H:%M")
            last_used = "Never"
            if info.get("last_used"):
                last_used = datetime.fromtimestamp(info["last_used"]).strftime("%Y-%m-%d %H:%M")
            
            print(f"║ @{handle:<15} {info['email']:<25} ║")
            print(f"║   Created: {created}  Last used: {last_used} ║")
            print("╟───────────────────────────────────────────────────╢")
        
        print("╚═══════════════════════════════════════════════════╝")


class SecureP2PNode:
    """P2P Node with authentication and end-to-end encryption"""
    
    def __init__(self, nats_url: str, identity: Dict, private_key, public_key):
        self.nc = NATS()
        self.nats_url = nats_url
        self.identity = identity
        self.handle = identity["handle"]
        self.node_id = identity["node_id"]
        self.private_key = private_key
        self.public_key = public_key
        
        # Peer management
        self.peers = {}  # handle -> peer_info
        self.peer_keys = {}  # handle -> public_key
        
        # Metrics
        self.messages_sent = 0
        self.messages_received = 0
        self.encrypted_sent = 0
        self.encrypted_received = 0
        self.start_time = time.time()
        
        # Settings
        self.auto_encrypt = True  # Encrypt by default
        self.show_timestamps = True
        
    async def connect(self, use_tls: bool = False):
        """Connect to network with authenticated identity"""
        
        # Configure TLS if requested
        connect_options = {"servers": self.nats_url}
        
        if use_tls:
            import ssl
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE  # For self-signed certs
            connect_options["tls"] = ssl_ctx
            print("🔒 TLS enabled for transport security")
        
        # Connect to NATS
        await self.nc.connect(**connect_options)
        
        # Subscribe to channels
        await self.nc.subscribe("nodes.announce", cb=self._on_announce)
        await self.nc.subscribe("nodes.discover", cb=self._on_discover_request)
        await self.nc.subscribe(f"node.{self.handle}", cb=self._on_message)
        await self.nc.subscribe(f"node.{self.node_id}", cb=self._on_message)
        
        # Announce with signed identity
        await self._announce()
        
        # Request discovery
        await self._request_discovery()
        
        # Start heartbeat
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        
        print(f"✅ Node @{self.handle} connected and authenticated")
        print(f"🔑 Node ID: {self.node_id[:8]}...")
        print(f"{'🔒 End-to-end encryption: ENABLED' if self.auto_encrypt else '⚠️  End-to-end encryption: DISABLED'}")
        
    async def disconnect(self):
        """Gracefully disconnect from network"""
        if hasattr(self, '_heartbeat_task'):
            self._heartbeat_task.cancel()
        
        # Send departure announcement
        await self._announce(departure=True)
        
        await self.nc.drain()
        print(f"👋 Disconnected from network")
        
    def _sign_message(self, message: Dict) -> str:
        """Sign a message with private key"""
        message_bytes = json.dumps(message, sort_keys=True).encode()
        signature = self.private_key.sign(
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')
    
    def _verify_signature(self, message: Dict, signature: str, public_key) -> bool:
        """Verify message signature"""
        try:
            message_bytes = json.dumps(message, sort_keys=True).encode()
            signature_bytes = base64.b64decode(signature)
            public_key.verify(
                signature_bytes,
                message_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False
    
    def _encrypt_content(self, content: str, recipient_public_key) -> Dict:
        """Encrypt content using hybrid encryption (RSA + AES)"""
        
        # Generate AES key for this message
        aes_key = os.urandom(32)  # 256-bit key
        iv = os.urandom(16)  # 128-bit IV
        
        # Encrypt message with AES
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Pad message to AES block size
        content_bytes = content.encode('utf-8')
        padding_length = 16 - (len(content_bytes) % 16)
        padded_content = content_bytes + bytes([padding_length] * padding_length)
        
        # Encrypt
        encrypted_content = encryptor.update(padded_content) + encryptor.finalize()
        
        # Encrypt AES key with recipient's RSA public key
        encrypted_key = recipient_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return {
            "encrypted_content": base64.b64encode(encrypted_content).decode('utf-8'),
            "encrypted_key": base64.b64encode(encrypted_key).decode('utf-8'),
            "iv": base64.b64encode(iv).decode('utf-8')
        }
    
    def _decrypt_content(self, encrypted_data: Dict) -> Optional[str]:
        """Decrypt content using private key"""
        try:
            # Decode components
            encrypted_content = base64.b64decode(encrypted_data["encrypted_content"])
            encrypted_key = base64.b64decode(encrypted_data["encrypted_key"])
            iv = base64.b64decode(encrypted_data["iv"])
            
            # Decrypt AES key with our private key
            aes_key = self.private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Decrypt content with AES
            cipher = Cipher(
                algorithms.AES(aes_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            padded_content = decryptor.update(encrypted_content) + decryptor.finalize()
            
            # Remove padding
            padding_length = padded_content[-1]
            content = padded_content[:-padding_length].decode('utf-8')
            
            return content
            
        except Exception:
            return None
    
    async def _announce(self, departure: bool = False):
        """Announce node with cryptographic proof"""
        announcement = {
            "handle": self.handle,
            "node_id": self.node_id,
            "email_hash": self.identity["email_hash"],
            "public_key": self.identity["public_key"],
            "timestamp": time.time(),
            "type": "departure" if departure else "announce",
            "capabilities": {
                "encryption": True,
                "version": "1.0"
            }
        }
        
        # Sign the announcement
        signature = self._sign_message(announcement)
        
        signed_announcement = {
            "announcement": announcement,
            "signature": signature
        }
        
        await self.nc.publish(
            "nodes.announce",
            json.dumps(signed_announcement).encode()
        )
        
    async def _on_announce(self, msg):
        """Handle and verify node announcements"""
        try:
            data = json.loads(msg.data.decode())
            announcement = data.get("announcement", {})
            signature = data.get("signature", "")
            
            handle = announcement.get("handle")
            if not handle or handle == self.handle:
                return
            
            # Handle departures
            if announcement.get("type") == "departure":
                if handle in self.peers:
                    del self.peers[handle]
                    del self.peer_keys[handle]
                    print(f"👋 Peer departed: @{handle}")
                return
            
            # Decode and verify public key
            public_key_pem = base64.b64decode(announcement.get("public_key", ""))
            public_key = serialization.load_pem_public_key(public_key_pem)
            
            # Verify signature
            if not self._verify_signature(announcement, signature, public_key):
                print(f"⚠️  Invalid signature from @{handle}, ignoring")
                return
            
            # Valid peer discovered
            is_new = handle not in self.peers
            self.peers[handle] = announcement
            self.peer_keys[handle] = public_key
            
            if is_new:
                print(f"✅ Authenticated peer: @{handle}")
                
                # Announce back for bidirectional discovery
                if announcement.get("type") == "announce":
                    await asyncio.sleep(0.1)
                    await self._announce()
                    
        except Exception as e:
            print(f"Error processing announcement: {e}")
            
    async def _request_discovery(self):
        """Request peer discovery"""
        request = json.dumps({
            "from": self.handle,
            "type": "discover_request"
        })
        await self.nc.publish("nodes.discover", request.encode())
        
    async def _on_discover_request(self, msg):
        """Respond to discovery requests"""
        try:
            data = json.loads(msg.data.decode())
            if data.get("from") != self.handle:
                # Small random delay to avoid thundering herd
                await asyncio.sleep(0.1 * (hash(self.handle) % 10) / 10)
                await self._announce()
        except:
            pass
            
    async def _heartbeat_loop(self):
        """Periodic re-announcement and cleanup"""
        await asyncio.sleep(5)
        while True:
            try:
                await asyncio.sleep(30)
                await self._announce()
                
                # Clean up stale peers (optional)
                now = time.time()
                stale_peers = []
                for handle, info in self.peers.items():
                    if now - info.get("timestamp", 0) > 120:  # 2 minutes
                        stale_peers.append(handle)
                
                for handle in stale_peers:
                    del self.peers[handle]
                    del self.peer_keys[handle]
                    print(f"⏱️  Removed stale peer: @{handle}")
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Heartbeat error: {e}")
                
    async def _on_message(self, msg):
        """Handle authenticated and potentially encrypted messages"""
        try:
            data = json.loads(msg.data.decode())
            
            # Check if it's an encrypted message
            if "encrypted_payload" in data:
                await self._handle_encrypted_message(data)
            else:
                await self._handle_signed_message(data)
                
        except Exception as e:
            print(f"Message error: {e}")
    
    async def _handle_signed_message(self, data: Dict):
        """Handle signed (but not encrypted) message"""
        message_content = data.get("content", {})
        signature = data.get("signature", "")
        sender_handle = message_content.get("from")
        
        if sender_handle in self.peer_keys:
            # Verify signature with known public key
            public_key = self.peer_keys[sender_handle]
            if not self._verify_signature(message_content, signature, public_key):
                print(f"⚠️  Invalid message signature from @{sender_handle}")
                return
            verified = "✓"
        else:
            # Unknown sender - auto-discovery
            verified = "?"
            
        self.messages_received += 1
        
        # Format output
        timestamp = ""
        if self.show_timestamps:
            msg_time = datetime.fromtimestamp(message_content.get("timestamp", time.time()))
            timestamp = f"[{msg_time.strftime('%H:%M:%S')}] "
        
        print(f"\n{timestamp}[@{sender_handle}]{verified}: {message_content.get('msg')}")
    
    async def _handle_encrypted_message(self, data: Dict):
        """Handle encrypted message"""
        sender_handle = data.get("from")
        encrypted_payload = data.get("encrypted_payload", {})
        
        # Decrypt the content
        decrypted_json = self._decrypt_content(encrypted_payload)
        
        if not decrypted_json:
            print(f"\n⚠️  Failed to decrypt message from @{sender_handle}")
            return
        
        # Parse decrypted message
        message_content = json.loads(decrypted_json)
        
        # Verify signature if sender is known
        verified = "🔒"
        if sender_handle in self.peer_keys and "signature" in data:
            public_key = self.peer_keys[sender_handle]
            if self._verify_signature(message_content, data["signature"], public_key):
                verified = "🔒✓"
        
        self.encrypted_received += 1
        
        # Format output
        timestamp = ""
        if self.show_timestamps:
            msg_time = datetime.fromtimestamp(message_content.get("timestamp", time.time()))
            timestamp = f"[{msg_time.strftime('%H:%M:%S')}] "
        
        print(f"\n{timestamp}[@{sender_handle}]{verified}: {message_content.get('msg')}")
    
    async def send(self, target: str, message: str, encrypt: Optional[bool] = None):
        """Send message (encrypted by default if peer's key is available)"""
        
        # Determine if we should encrypt
        should_encrypt = self.auto_encrypt if encrypt is None else encrypt
        
        if should_encrypt and target in self.peer_keys:
            await self._send_encrypted(target, message)
        else:
            await self._send_signed(target, message)
    
    async def _send_signed(self, target: str, message: str):
        """Send signed (but not encrypted) message"""
        content = {
            "from": self.handle,
            "to": target,
            "msg": message,
            "timestamp": time.time()
        }
        
        signature = self._sign_message(content)
        
        signed_message = {
            "content": content,
            "signature": signature
        }
        
        await self.nc.publish(f"node.{target}", json.dumps(signed_message).encode())
        self.messages_sent += 1
        print(f"📤 Sent to @{target} (signed)")
    
    async def _send_encrypted(self, target: str, message: str):
        """Send encrypted and signed message"""
        if target not in self.peer_keys:
            print(f"⚠️  No encryption key for @{target}, sending signed only")
            await self._send_signed(target, message)
            return
        
        content = {
            "from": self.handle,
            "to": target,
            "msg": message,
            "timestamp": time.time()
        }
        
        # Encrypt the content
        recipient_key = self.peer_keys[target]
        encrypted_payload = self._encrypt_content(json.dumps(content), recipient_key)
        
        # Sign the content for authenticity
        signature = self._sign_message(content)
        
        # Create final message
        encrypted_message = {
            "from": self.handle,
            "encrypted_payload": encrypted_payload,
            "signature": signature
        }
        
        await self.nc.publish(f"node.{target}", json.dumps(encrypted_message).encode())
        self.encrypted_sent += 1
        print(f"🔒📤 Sent to @{target} (encrypted)")
    
    async def broadcast(self, message: str, encrypt: Optional[bool] = None):
        """Broadcast to all authenticated peers"""
        count = 0
        for peer_handle in list(self.peers.keys()):
            await self.send(peer_handle, message, encrypt)
            count += 1
        
        if count > 0:
            print(f"📡 Broadcasted to {count} peers")
        else:
            print("⚠️  No peers to broadcast to")
    
    async def refresh_peers(self):
        """Manually trigger peer discovery"""
        print("🔄 Refreshing peer list...")
        await self._request_discovery()
        await asyncio.sleep(1)  # Wait for responses
        print(f"Found {len(self.peers)} authenticated peers")
    
    async def status(self):
        """Show detailed node status"""
        uptime = time.time() - self.start_time
        uptime_str = f"{int(uptime // 3600)}h {int((uptime % 3600) // 60)}m {int(uptime % 60)}s"
        
        print("\n╔═══════════════════════════════════════════════════╗")
        print(f"║  Node Status: @{self.handle:<35} ║")
        print("╠═══════════════════════════════════════════════════╣")
        print(f"║ Identity:   {self.identity['email']:<38} ║")
        print(f"║ Node ID:    {self.node_id[:38]:<38} ║")
        print(f"║ Uptime:     {uptime_str:<38} ║")
        print(f"║ NATS:       {'Connected ✅' if self.nc.is_connected else 'Disconnected ❌':<38} ║")
        print("╟───────────────────────────────────────────────────╢")
        print(f"║ Peers:      {len(self.peers)} authenticated peers{' '*(30-len(str(len(self.peers))))} ║")
        if self.peers:
            for handle in list(self.peers.keys())[:5]:  # Show first 5
                print(f"║   • @{handle:<44} ║")
            if len(self.peers) > 5:
                print(f"║   ... and {len(self.peers)-5} more{' '*(39-len(str(len(self.peers)-5)))} ║")
        print("╟───────────────────────────────────────────────────╢")
        print(f"║ Messages Sent:      {self.messages_sent:<29} ║")
        print(f"║ Messages Received:  {self.messages_received:<29} ║")
        print(f"║ Encrypted Sent:     {self.encrypted_sent:<29} ║")
        print(f"║ Encrypted Received: {self.encrypted_received:<29} ║")
        print("╟───────────────────────────────────────────────────╢")
        print(f"║ Settings:                                         ║")
        print(f"║   Auto-encrypt: {'✅ Enabled' if self.auto_encrypt else '❌ Disabled':<36} ║")
        print(f"║   Timestamps:   {'✅ Shown' if self.show_timestamps else '❌ Hidden':<36} ║")
        print("╚═══════════════════════════════════════════════════╝")
    
    def toggle_encryption(self):
        """Toggle automatic encryption"""
        self.auto_encrypt = not self.auto_encrypt
        print(f"🔒 Auto-encryption: {'ENABLED' if self.auto_encrypt else 'DISABLED'}")
    
    def toggle_timestamps(self):
        """Toggle timestamp display"""
        self.show_timestamps = not self.show_timestamps
        print(f"🕐 Timestamps: {'SHOWN' if self.show_timestamps else 'HIDDEN'}")


async def interactive_loop(node: SecureP2PNode):
    """Interactive command loop"""
    
    print("\n╔═══════════════════════════════════════════════════╗")
    print("║              BEEHIVE NETWORK v1.0                 ║")
    print("╠═══════════════════════════════════════════════════╣")
    print("║ Commands:                                         ║")
    print("║   @<handle> <msg>  - Send to peer                ║")
    print("║   all <msg>        - Broadcast to all            ║")
    print("║   peers            - List connected peers        ║")
    print("║   refresh          - Refresh peer list           ║")
    print("║   status           - Show detailed status        ║")
    print("║   encrypt          - Toggle auto-encryption      ║")
    print("║   timestamps       - Toggle timestamps           ║")
    print("║   help             - Show this help              ║")
    print("║   quit             - Exit                        ║")
    print("╚═══════════════════════════════════════════════════╝\n")
    
    while True:
        try:
            line = await asyncio.get_event_loop().run_in_executor(
                None, input, f"[@{node.handle}]> "
            )
            
            if not line:
                continue
                
            parts = line.strip().split(maxsplit=1)
            if not parts:
                continue
                
            cmd = parts[0].lower()
            
            if cmd == "quit" or cmd == "exit":
                break
                
            elif cmd == "help" or cmd == "?":
                print("\nCommands:")
                print("  @<handle> <msg> - Send message to specific peer")
                print("  all <msg>       - Broadcast to all peers")
                print("  peers           - List authenticated peers")
                print("  refresh         - Refresh peer discovery")
                print("  status          - Show detailed node status")
                print("  encrypt         - Toggle automatic encryption")
                print("  timestamps      - Toggle timestamp display")
                print("  help            - Show this help")
                print("  quit            - Exit the program\n")
                
            elif cmd == "peers":
                if node.peers:
                    print(f"\nAuthenticated peers ({len(node.peers)}):")
                    for handle, info in node.peers.items():
                        caps = info.get("capabilities", {})
                        enc = "🔒" if caps.get("encryption") else ""
                        print(f"  • @{handle} {enc}")
                else:
                    print("No peers connected")
                    
            elif cmd == "refresh":
                await node.refresh_peers()
                
            elif cmd == "status":
                await node.status()
                
            elif cmd == "encrypt":
                node.toggle_encryption()
                
            elif cmd == "timestamps":
                node.toggle_timestamps()
                
            elif cmd == "all" and len(parts) > 1:
                await node.broadcast(parts[1])
                
            elif cmd.startswith("@") and len(parts) > 1:
                target = cmd[1:]  # Remove @
                await node.send(target, parts[1])
                
            elif len(parts) == 2:
                # Assume first word is handle if no @ prefix
                target = parts[0]
                message = parts[1]
                await node.send(target, message)
                
            else:
                print(f"Unknown command: {cmd}. Type 'help' for commands.")
                
        except (EOFError, KeyboardInterrupt):
            print("\n")
            break
        except Exception as e:
            print(f"Error: {e}")
            
    await node.disconnect()


async def main():
    import getpass
    
    # Initialize identity manager
    id_mgr = IdentityManager()
    
    # Parse arguments
    if len(sys.argv) < 2:
        print("\n🐝 BEEHIVE NETWORK - Secure P2P Communication")
        print("\nUsage: python node.py <nats_url> [command] [--tls]")
        print("\nCommands:")
        print("  connect  - Connect with existing identity (default)")
        print("  register - Register new identity")
        print("  list     - List registered identities")
        print("  delete   - Delete an identity")
        print("\nOptions:")
        print("  --tls    - Enable TLS for transport security")
        print("\nExample:")
        print("  python node.py nats://localhost:4222 register")
        print("  python node.py nats://20.81.248.221:4222 connect --tls")
        sys.exit(1)
    
    nats_url = sys.argv[1]
    command = "connect"  # Default command
    use_tls = "--tls" in sys.argv
    
    # Parse command
    for arg in sys.argv[2:]:
        if arg in ["connect", "register", "list", "delete"]:
            command = arg
            break
    
    if command == "list":
        id_mgr.list_identities()
        return
        
    elif command == "delete":
        print("\n=== Delete Identity ===")
        identities = id_mgr._load_identities()
        if not identities:
            print("No identities to delete")
            return
            
        print("Available identities:")
        for handle in identities:
            print(f"  - @{handle}")
            
        handle = input("\nHandle to delete: ").strip().lstrip("@")
        if not handle:
            return
            
        password = getpass.getpass("Password: ")
        id_mgr.delete_identity(handle, password)
        return
        
    elif command == "register":
        print("\n╔═══════════════════════════════════════════════════╗")
        print("║          Register New Beehive Identity            ║")
        print("╚═══════════════════════════════════════════════════╝")
        
        handle = input("Handle (e.g., alice): ").strip().lstrip("@")
        if not handle:
            print("Handle required")
            return
            
        email = input("Email: ").strip()
        if not email or "@" not in email:
            print("Valid email required")
            return
            
        password = getpass.getpass("Password (min 8 chars): ")
        if len(password) < 8:
            print("Password must be at least 8 characters")
            return
            
        confirm = getpass.getpass("Confirm password: ")
        
        if password != confirm:
            print("Passwords don't match")
            return
            
        try:
            identity = id_mgr.create_identity(handle, email, password)
            print(f"\n🎉 Identity @{handle} created successfully!")
            print("You can now connect using this identity")
            
            # Ask if they want to connect immediately
            connect_now = input("\nConnect now? (y/n): ").strip().lower()
            if connect_now != 'y':
                return
                
            # Load and connect
            identity, private_key, public_key = id_mgr.load_identity(handle, password)
            node = SecureP2PNode(nats_url, identity, private_key, public_key)
            await node.connect(use_tls=use_tls)
            await interactive_loop(node)
            
        except ValueError as e:
            print(f"❌ Registration failed: {e}")
        return
        
    else:  # Connect
        print("\n╔═══════════════════════════════════════════════════╗")
        print("║           Connect to Beehive Network              ║")
        print("╚═══════════════════════════════════════════════════╝")
        
        # List available identities
        identities = id_mgr._load_identities()
        if not identities:
            print("No identities found.")
            print("Run with 'register' to create a new identity.")
            return
            
        print("\nAvailable identities:")
        for handle in identities:
            print(f"  • @{handle}")
            
        handle = input("\nHandle: ").strip().lstrip("@")
        if not handle:
            return
            
        password = getpass.getpass("Password: ")
        
        try:
            # Load and authenticate identity
            identity, private_key, public_key = id_mgr.load_identity(handle, password)
            
            # Create authenticated node
            node = SecureP2PNode(nats_url, identity, private_key, public_key)
            await node.connect(use_tls=use_tls)
            
            # Enter interactive loop
            await interactive_loop(node)
            
        except ValueError as e:
            print(f"❌ Authentication failed: {e}")
        except Exception as e:
            print(f"❌ Connection failed: {e}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
