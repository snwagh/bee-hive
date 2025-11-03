#!/usr/bin/env python3
import asyncio
import json
import random
import signal
from typing import List
import msgpack
from datetime import datetime
from flower.base_node import BaseNode
from flower.dispatcher import ComputationDispatcher
from loguru import logger
from bee_hive_core.config import MODULUS
from bee_hive_core.types import Computation

class LightNode(BaseNode):
    """Light node that executes computations."""

    def __init__(self, node_id: str, nats_url: str, data_dir: str, private_key_path: str, public_key_path: str):
        super().__init__(node_id, nats_url, data_dir, private_key_path, public_key_path)
        self.dispatcher = ComputationDispatcher(self.data_dir)
        logger.info(f"[{node_id}] Initialized as light node")
    
    def get_node_type(self) -> str:
        return "light"
    
    def generate_secret_shares(self, value: int, num_shares: int) -> List[int]:
        """Generate N random shares that sum to value (mod 2**32)."""
        shares = [random.randint(0, MODULUS - 1) for _ in range(num_shares - 1)]
        last_share = (value - sum(shares)) % MODULUS
        shares.append(last_share)
        logger.debug(f"[{self.node_id}] Generated {num_shares} shares for value {value}")
        return shares
    
    async def execute_computation(self, computation: Computation) -> int:
        """
        Execute computation by dispatching to nectar.
        Returns the integer result value.
        Raises TimeoutError if no handler responds within deadline.
        """
        logger.info(f"[{self.node_id}] Executing computation {computation.comp_id}")

        # Dispatch to nectar (write .pending file)
        self.dispatcher.dispatch(computation)

        # Wait for result (poll for .complete file)
        result = await self.dispatcher.wait_for_result(
            computation.comp_id,
            timeout=computation.deadline
        )

        if result.status == "success":
            logger.info(f"[{self.node_id}] Computation {computation.comp_id} succeeded: {result.value}")
            return result.value
        elif result.status == "timeout":
            # No handler attached or handler didn't respond in time
            logger.warning(f"[{self.node_id}] Computation {computation.comp_id} timed out - no handler response")
            raise TimeoutError(f"No handler response within {computation.deadline}s")
        else:
            logger.error(f"[{self.node_id}] Computation {computation.comp_id} failed: {result.error}")
            raise RuntimeError(f"Computation failed: {result.error}")
    
    async def _handle_execute_broadcast(self, msg):
        """Handle execution request broadcast from heavy nodes."""
        try:
            # Decrypt the message
            encrypted_msg = msgpack.unpackb(msg.data)
            sender_id = encrypted_msg.get('sender', 'unknown')

            decrypted_data = self.decrypt_from_peer(encrypted_msg)
            data = msgpack.unpackb(decrypted_data)

            comp_dict = data['computation']
            heavy_nodes = data['heavy_nodes']  # List of heavy nodes to respond to
            comp_id = comp_dict['id']

            logger.info(f"[{self.node_id}] Received broadcast for computation {comp_id} from {sender_id}")

            # Store in participant table
            self.db.insert_participant(comp_id, comp_dict['query'])

            # Construct Computation object from the received data
            # Handle timestamp - ensure it's a float
            timestamp = comp_dict.get('timestamp', datetime.utcnow().timestamp())
            if isinstance(timestamp, str):
                timestamp = datetime.utcnow().timestamp()  # Use current time if invalid

            computation = Computation(
                comp_id=comp_id,
                query=comp_dict['query'],
                proposer=comp_dict.get('proposer', 'unknown'),
                aggregators=comp_dict.get('aggregators', heavy_nodes),
                targets=comp_dict.get('targets', []),
                deadline=comp_dict.get('deadline', 30),
                timestamp=float(timestamp),
                metadata=comp_dict.get('metadata', {})
            )

            # Execute computation
            try:
                response_value = await self.execute_computation(computation)
            except TimeoutError as e:
                # No handler or handler didn't respond - don't send shares
                logger.warning(f"[{self.node_id}] Skipping share distribution for {comp_id}: {e}")
                return
            except Exception as e:
                # Other execution errors - also don't send shares
                logger.error(f"[{self.node_id}] Execution failed for {comp_id}, skipping shares: {e}")
                return

            # Generate secret shares for N aggregators
            num_aggregators = len(heavy_nodes)
            shares = self.generate_secret_shares(response_value, num_aggregators)

            # Update database with execution results
            self.db.update_participant_execution(comp_id, response_value, shares)

            # Send one share to each heavy node
            for i, heavy_id in enumerate(heavy_nodes):
                if heavy_id in self.peer_keys:
                    share_value = shares[i]

                    response = {
                        "computation_id": comp_id,
                        "node_id": self.node_id,
                        "share": share_value,
                        "timestamp": datetime.utcnow().timestamp()
                    }

                    # Encrypt for the heavy node
                    encrypted = self.encrypt_for_peer(
                        msgpack.packb(response),
                        heavy_id
                    )

                    # Send to specific heavy node
                    await self.nc.publish(
                        f"comp.result.{heavy_id}",
                        msgpack.packb(encrypted)
                    )

                    logger.info(f"[{self.node_id}] Sent share {share_value} to {heavy_id}")

            # Mark shares as sent
            self.db.mark_participant_sent(comp_id)

        except Exception as e:
            try:
                encrypted_msg = msgpack.unpackb(msg.data)
                sender_id = encrypted_msg.get('sender', 'unknown')
                logger.error(f"[{self.node_id}] Error handling execution from {sender_id}: {e}")
            except:
                logger.error(f"[{self.node_id}] Error handling execution: {e}")
    
    async def _submit_computation(self, data: dict):
        """Submit computation to network (as proposer)."""
        import uuid
        comp_id = str(uuid.uuid4())[:8]

        query = data['query']
        aggregators = data.get('aggregators', [])
        targets = data.get('targets', [])
        deadline = data.get('deadline', 30)

        # Store in proposed table
        self.db.insert_proposed(comp_id, query, aggregators, targets, deadline)

        computation = {
            "id": comp_id,
            "proposer": self.node_id,
            "query": query,
            "aggregators": aggregators,
            "targets": targets,
            "deadline": deadline,
            "timestamp": datetime.utcnow().timestamp()
        }

        self.active_computations[comp_id] = computation

        # Send to each aggregator on their specific channel
        for aggregator_id in aggregators:
            if aggregator_id in self.peer_keys:
                encrypted = self.encrypt_for_peer(
                    msgpack.packb(computation),
                    aggregator_id
                )
                # Use aggregator-specific channel instead of shared channel
                await self.nc.publish(f"comp.proposal.{aggregator_id}", msgpack.packb(encrypted))
                logger.info(f"[{self.node_id}] Sent proposal to aggregator {aggregator_id}")
            else:
                logger.warning(f"[{self.node_id}] No public key for aggregator {aggregator_id}")

        logger.info(f"[{self.node_id}] Submitted computation {comp_id} to {len(aggregators)} aggregators")
        return {"status": "submitted", "id": comp_id, "aggregators": aggregators, "targets": targets}
    
    async def _handle_final_result(self, msg):
        """Handle aggregated result from heavy nodes (proposer receives this)."""
        try:
            encrypted_msg = msgpack.unpackb(msg.data)
            decrypted_data = self.decrypt_from_peer(encrypted_msg)
            result = msgpack.unpackb(decrypted_data)

            comp_id = result['computation_id']
            aggregated_value = result['aggregated_value']
            aggregator_id = result.get('aggregator')

            logger.info(f"[{self.node_id}] Received aggregated result for {comp_id} from {aggregator_id}: {aggregated_value}")

            # Store result in memory
            if comp_id in self.active_computations:
                if 'aggregator_results' not in self.active_computations[comp_id]:
                    self.active_computations[comp_id]['aggregator_results'] = []

                self.active_computations[comp_id]['aggregator_results'].append({
                    'aggregator': aggregator_id,
                    'value': aggregated_value
                })

                # Check if we have all aggregator results
                comp = self.active_computations[comp_id]
                expected_aggregators = len(comp.get('aggregators', []))
                received_aggregators = len(comp.get('aggregator_results', []))

                if received_aggregators == expected_aggregators:
                    # We have all results, perform final aggregation
                    await self._aggregate_final_results(comp_id)

        except Exception as e:
            logger.error(f"[{self.node_id}] Error handling final result: {e}")
    
    async def _aggregate_final_results(self, comp_id: str):
        """Aggregate results from all aggregators (mod 2**32) - proposer only."""
        comp = self.active_computations.get(comp_id)
        if not comp or comp.get('proposer') != self.node_id:
            return

        aggregator_results = comp.get('aggregator_results', [])
        if not aggregator_results:
            logger.warning(f"[{self.node_id}] No aggregator results for {comp_id}")
            return

        # Sum all aggregator values (mod 2**32)
        final_total = sum(r['value'] for r in aggregator_results) % MODULUS

        logger.info(f"[{self.node_id}] Final aggregated value for {comp_id}: {final_total}")
        logger.info(f"  Components: {[r['value'] for r in aggregator_results]}")

        # Update database
        self.db.update_proposed_result(comp_id, final_total)

        # Save final result to file for convenience
        final_file = self.data_dir / f"final_{comp_id}.json"
        with open(final_file, 'w') as f:
            json.dump({
                "computation_id": comp_id,
                "final_result": final_total,
                "aggregator_values": {r['aggregator']: r['value'] for r in aggregator_results},
                "timestamp": datetime.utcnow().timestamp()
            }, f, indent=2)

        logger.info(f"[{self.node_id}] Final result saved to {final_file}")
    
    async def _handle_discover(self, msg):
        """Respond to discovery requests."""
        if msg.reply:
            await self.nc.publish(
                msg.reply,
                msgpack.packb([{
                    "node_id": self.node_id,
                    "type": self.get_node_type()
                }])
            )
    
    async def run(self):
        """Main run loop for light node."""
        # Setup - keys already loaded in __init__
        await self.connect_nats()
        await self.start_ipc_server()

        # Start periodic peer refresh
        asyncio.create_task(self._refresh_peers_periodically())

        # Start heartbeat to keep alias alive in network registry
        asyncio.create_task(self._heartbeat_task())

        # Subscribe to node-specific broadcasts from heavy nodes
        await self.nc.subscribe(f"comp.broadcast.{self.node_id}", cb=self._handle_execute_broadcast)

        # Subscribe to final results
        await self.nc.subscribe(f"comp.final.{self.node_id}", cb=self._handle_final_result)

        # Subscribe to discovery
        await self.nc.subscribe("node.discover.light", cb=self._handle_discover)

        # Signal handling
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, lambda: asyncio.create_task(self.shutdown()))

        logger.info(f"[{self.node_id}] Light node ready!")
        await self.shutdown_event.wait()
