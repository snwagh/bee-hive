#!/usr/bin/env python3
import asyncio
import signal
from typing import Dict, List
import msgpack
from datetime import datetime
from light_node import LightNode
from loguru import logger
from db import MOD

class HeavyNode(LightNode):
    """Heavy node that coordinates and can also execute computations."""

    def __init__(self, node_id: str, nats_url: str, data_dir: str, private_key_path: str, public_key_path: str):
        super().__init__(node_id, nats_url, data_dir, private_key_path, public_key_path)
        self.aggregation_buffer: Dict[str, List] = {}  # comp_id -> list of results
        logger.info(f"[{node_id}] Initialized as heavy node (can also act as light)")
    
    def get_node_type(self) -> str:
        return "heavy"
    
    async def _handle_proposal(self, msg):
        """Handle computation proposal from proposer node."""
        try:
            encrypted_msg = msgpack.unpackb(msg.data)
            decrypted_data = self.decrypt_from_peer(encrypted_msg)
            comp = msgpack.unpackb(decrypted_data)

            comp_id = comp['id']
            proposer = comp['proposer']
            query = comp['query']
            aggregators = comp['aggregators']
            targets = comp['targets']

            logger.info(f"[{self.node_id}] Received proposal for computation {comp_id}")

            # Store computation in aggregator table
            self.db.insert_aggregator(comp_id, proposer, query, targets)
            self.active_computations[comp_id] = comp

            # Only the first aggregator broadcasts to targets
            is_first_aggregator = (aggregators[0] == self.node_id)

            if is_first_aggregator:
                logger.info(f"[{self.node_id}] I am the first aggregator, broadcasting to targets")

                broadcast_msg = {
                    "computation": comp,
                    "heavy_nodes": aggregators  # Tell targets where to send shares
                }

                # Send to each target on their specific channel
                for target_id in targets:
                    if target_id in self.peer_keys:
                        encrypted_broadcast = self.encrypt_for_peer(
                            msgpack.packb(broadcast_msg),
                            target_id
                        )
                        # Use target-specific channel instead of broadcast channel
                        await self.nc.publish(f"comp.broadcast.{target_id}", msgpack.packb(encrypted_broadcast))
                        logger.info(f"[{self.node_id}] Sent computation to target {target_id}")
                    else:
                        logger.warning(f"[{self.node_id}] No public key for target {target_id}")

            # Start collection and aggregation task
            asyncio.create_task(self._collect_and_aggregate(comp))

        except Exception as e:
            import traceback
            logger.error(f"[{self.node_id}] Error handling proposal: {e}")
            logger.debug(f"[{self.node_id}] Traceback: {traceback.format_exc()}")
    
    async def _handle_result(self, msg):
        """Handle share results from target nodes."""
        try:
            encrypted_msg = msgpack.unpackb(msg.data)
            decrypted_data = self.decrypt_from_peer(encrypted_msg)
            result = msgpack.unpackb(decrypted_data)

            comp_id = result['computation_id']
            node_id = result['node_id']
            share_value = result['share']

            logger.info(f"[{self.node_id}] Received share {share_value} from {node_id} for computation {comp_id}")

            # Add share to database
            self.db.add_share(comp_id, node_id, share_value)

            # Also add to buffer for tracking
            if comp_id not in self.aggregation_buffer:
                self.aggregation_buffer[comp_id] = []
            self.aggregation_buffer[comp_id].append(result)

        except Exception as e:
            logger.error(f"[{self.node_id}] Error handling result: {e}")
    
    async def _collect_and_aggregate(self, comp: dict):
        """Collect shares and aggregate (mod 2**32)."""
        comp_id = comp['id']
        deadline = comp.get('deadline', 30)
        proposer_id = comp['proposer']

        logger.info(f"[{self.node_id}] Waiting {deadline}s for shares for computation {comp_id}")

        # Wait for deadline
        await asyncio.sleep(deadline)

        # Aggregate shares from database (mod 2**32)
        aggregated_value = self.db.aggregate_shares(comp_id)

        num_shares = len(self.aggregation_buffer.get(comp_id, []))
        logger.info(f"[{self.node_id}] Aggregated {num_shares} shares for {comp_id}: {aggregated_value}")

        # Send aggregated result back to proposer
        aggregated = {
            "computation_id": comp_id,
            "aggregated_value": aggregated_value,
            "num_results": num_shares,
            "aggregator": self.node_id,
            "timestamp": datetime.utcnow().isoformat()
        }

        if proposer_id in self.peer_keys:
            encrypted = self.encrypt_for_peer(
                msgpack.packb(aggregated),
                proposer_id
            )
            await self.nc.publish(
                f"comp.final.{proposer_id}",
                msgpack.packb(encrypted)
            )
            logger.info(f"[{self.node_id}] Sent aggregated result {aggregated_value} to {proposer_id}")

            # Mark as sent in database
            self.db.mark_aggregator_sent(comp_id)
        else:
            logger.warning(f"[{self.node_id}] No public key for proposer {proposer_id}")

        # Clean up buffer
        if comp_id in self.aggregation_buffer:
            del self.aggregation_buffer[comp_id]
    
    async def _handle_discover(self, msg):
        """Override to respond as heavy node."""
        if msg.reply:
            await self.nc.publish(
                msg.reply,
                msgpack.packb([{
                    "node_id": self.node_id,
                    "type": "heavy"  # Identify as heavy
                }])
            )
    
    async def run(self):
        """Main run loop for heavy node."""
        # Setup - keys already loaded in __init__
        await self.connect_nats()
        await self.start_ipc_server()

        # Start periodic peer refresh
        asyncio.create_task(self._refresh_peers_periodically())

        # Heavy node subscriptions - use node-specific channel
        await self.nc.subscribe(f"comp.proposal.{self.node_id}", cb=self._handle_proposal)
        await self.nc.subscribe(f"comp.result.{self.node_id}", cb=self._handle_result)

        # Light node subscriptions (inherited functionality) - use node-specific channel
        await self.nc.subscribe(f"comp.broadcast.{self.node_id}", cb=self._handle_execute_broadcast)
        await self.nc.subscribe(f"comp.final.{self.node_id}", cb=self._handle_final_result)

        # Discovery
        await self.nc.subscribe("node.discover.heavy", cb=self._handle_discover)
        await self.nc.subscribe("node.discover.light", cb=self._handle_discover)  # Can respond to both

        # Signal handling
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, lambda: asyncio.create_task(self.shutdown()))

        logger.info(f"[{self.node_id}] Heavy node ready (can also act as light)!")
        await self.shutdown_event.wait()
