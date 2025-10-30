#!/usr/bin/env python3
"""
Configuration for Bee-Hive Network
Centralized settings for the distributed LLM computation system.
"""

# NATS Server Configuration
DEFAULT_NATS_URL = "nats://20.81.248.221:4222"

# Network Registry Configuration
REGISTRY_BUCKET_NAME = "node_registry"
REGISTRY_TTL = 3600  # 1 hour in seconds

# Heartbeat Configuration
HEARTBEAT_INTERVAL = 600  # 10 minutes in seconds
PEER_REFRESH_INTERVAL = 30  # 30 seconds

# Timeouts
NATS_CONNECT_TIMEOUT = 5  # seconds
