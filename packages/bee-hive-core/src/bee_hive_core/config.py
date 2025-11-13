#!/usr/bin/env python3
"""
Configuration for Bee-Hive Network
Centralized settings for the distributed LLM computation system.
"""

# NATS Server Configuration
# Use localhost for local development/testing, or set to remote server for production
DEFAULT_NATS_URL = "nats://localhost:4222"  # Local development
# DEFAULT_NATS_URL = "nats://20.81.248.221:4222"  # Azure production server

# Network Registry Configuration
REGISTRY_BUCKET_NAME = "node_registry"
REGISTRY_TTL = 3600  # 1 hour in seconds

# Heartbeat Configuration
HEARTBEAT_INTERVAL = 600  # 10 minutes in seconds
PEER_REFRESH_INTERVAL = 5  # 5 seconds (faster for local testing)

# Timeouts
NATS_CONNECT_TIMEOUT = 5  # seconds

# Computation Configuration
MODULUS = 2 ** 32  # Modulo for all secret sharing arithmetic operations
