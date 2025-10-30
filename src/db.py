#!/usr/bin/env python3
"""Database module for bee-hive network computation tracking."""
import sqlite3
import json
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
from config import MODULUS


class ComputationDB:
    """SQLite database for tracking computations across different node roles."""

    def __init__(self, db_path: Path):
        """Initialize database with schema."""
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._create_schema()

    def _create_schema(self):
        """Create tables for different computation roles."""
        cursor = self.conn.cursor()

        # Table 1: Computations proposed by this node
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS proposed_computations (
                id TEXT PRIMARY KEY,
                query TEXT NOT NULL,
                aggregators TEXT NOT NULL,  -- JSON list of aggregator node IDs
                targets TEXT NOT NULL,      -- JSON list of target node IDs
                deadline INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                status TEXT DEFAULT 'pending',  -- pending|completed
                final_result INTEGER,       -- Final aggregated result (mod 2**32)
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Table 2: Computations where this node is an aggregator
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS aggregator_computations (
                id TEXT PRIMARY KEY,
                proposer TEXT NOT NULL,
                query TEXT NOT NULL,
                targets TEXT NOT NULL,      -- JSON list of target node IDs
                shares TEXT,                -- JSON dict: {node_id: share_value}
                local_aggregated INTEGER,   -- Sum of shares (mod 2**32)
                status TEXT DEFAULT 'pending',  -- pending|aggregated|sent
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Table 3: Computations where this node is a participant/worker
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS participant_computations (
                id TEXT PRIMARY KEY,
                query TEXT NOT NULL,
                response INTEGER,           -- Generated response value (0-100)
                shares_generated TEXT,      -- JSON list of shares
                status TEXT DEFAULT 'pending',  -- pending|executed|sent
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        self.conn.commit()

    # ===== PROPOSED COMPUTATIONS (Proposer role) =====

    def insert_proposed(self, comp_id: str, query: str, aggregators: List[str],
                       targets: List[str], deadline: int) -> None:
        """Insert a new proposed computation."""
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO proposed_computations
            (id, query, aggregators, targets, deadline, timestamp, status)
            VALUES (?, ?, ?, ?, ?, ?, 'pending')
        """, (
            comp_id,
            query,
            json.dumps(aggregators),
            json.dumps(targets),
            deadline,
            datetime.utcnow().isoformat()
        ))
        self.conn.commit()

    def update_proposed_result(self, comp_id: str, final_result: int) -> None:
        """Update final result for a proposed computation."""
        cursor = self.conn.cursor()
        cursor.execute("""
            UPDATE proposed_computations
            SET final_result = ?, status = 'completed'
            WHERE id = ?
        """, (final_result % MODULUS, comp_id))
        self.conn.commit()

    def get_proposed(self, comp_id: str) -> Optional[Dict[str, Any]]:
        """Get a proposed computation by ID."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM proposed_computations WHERE id = ?", (comp_id,))
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None

    # ===== AGGREGATOR COMPUTATIONS (Aggregator role) =====

    def insert_aggregator(self, comp_id: str, proposer: str, query: str,
                         targets: List[str]) -> None:
        """Insert a computation where this node is an aggregator."""
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO aggregator_computations
            (id, proposer, query, targets, shares, status)
            VALUES (?, ?, ?, ?, '{}', 'pending')
        """, (comp_id, proposer, query, json.dumps(targets)))
        self.conn.commit()

    def add_share(self, comp_id: str, node_id: str, share_value: int) -> None:
        """Add a share from a participant node."""
        cursor = self.conn.cursor()

        # Get current shares
        cursor.execute("SELECT shares FROM aggregator_computations WHERE id = ?", (comp_id,))
        row = cursor.fetchone()
        if not row:
            return

        shares = json.loads(row['shares']) if row['shares'] else {}
        shares[node_id] = share_value

        cursor.execute("""
            UPDATE aggregator_computations
            SET shares = ?
            WHERE id = ?
        """, (json.dumps(shares), comp_id))
        self.conn.commit()

    def aggregate_shares(self, comp_id: str) -> int:
        """Sum all shares for a computation (mod 2**32) and update database."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT shares FROM aggregator_computations WHERE id = ?", (comp_id,))
        row = cursor.fetchone()
        if not row:
            return 0

        shares = json.loads(row['shares']) if row['shares'] else {}
        total = sum(shares.values()) % MODULUS

        cursor.execute("""
            UPDATE aggregator_computations
            SET local_aggregated = ?, status = 'aggregated'
            WHERE id = ?
        """, (total, comp_id))
        self.conn.commit()

        return total

    def mark_aggregator_sent(self, comp_id: str) -> None:
        """Mark aggregated result as sent to proposer."""
        cursor = self.conn.cursor()
        cursor.execute("""
            UPDATE aggregator_computations
            SET status = 'sent'
            WHERE id = ?
        """, (comp_id,))
        self.conn.commit()

    def get_aggregator(self, comp_id: str) -> Optional[Dict[str, Any]]:
        """Get an aggregator computation by ID."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM aggregator_computations WHERE id = ?", (comp_id,))
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None

    # ===== PARTICIPANT COMPUTATIONS (Worker role) =====

    def insert_participant(self, comp_id: str, query: str) -> None:
        """Insert a computation where this node is a participant."""
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO participant_computations
            (id, query, status)
            VALUES (?, ?, 'pending')
        """, (comp_id, query))
        self.conn.commit()

    def update_participant_execution(self, comp_id: str, response: int,
                                    shares: List[int]) -> None:
        """Update participant computation with response and shares."""
        cursor = self.conn.cursor()
        cursor.execute("""
            UPDATE participant_computations
            SET response = ?, shares_generated = ?, status = 'executed'
            WHERE id = ?
        """, (response, json.dumps(shares), comp_id))
        self.conn.commit()

    def mark_participant_sent(self, comp_id: str) -> None:
        """Mark participant shares as sent."""
        cursor = self.conn.cursor()
        cursor.execute("""
            UPDATE participant_computations
            SET status = 'sent'
            WHERE id = ?
        """, (comp_id,))
        self.conn.commit()

    def get_participant(self, comp_id: str) -> Optional[Dict[str, Any]]:
        """Get a participant computation by ID."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM participant_computations WHERE id = ?", (comp_id,))
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None

    # ===== UTILITY METHODS =====

    def close(self):
        """Close database connection."""
        self.conn.close()
