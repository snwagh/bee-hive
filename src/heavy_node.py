#!/usr/bin/env python3
import asyncio
import signal
from typing import Dict, List
import msgpack
from datetime import datetime
from light_node import LightNode

class HeavyNode(LightNode):
    """Heavy node that coordinates and can also execute computations."""

    def __init__(self, node_id: str, nats_url: str, data_dir: str, private_key_path: str, public_key_path: str):
        super().__init__(node_id, nats_url, data_dir, private_key_path, public_key_path)
        self.aggregation_buffer: Dict[str, List] = {}  # comp_id -> list of results
        print(f"[{node_id}] Initialized as heavy node (can also act as light)")
    
    def get_node_type(self) -> str:
        return "heavy"
    
    async def _handle_proposal(self, msg):
        """Handle computation proposal from any node."""
        try:
            encrypted_msg = msgpack.unpackb(msg.data)
            decrypted_data = self.decrypt_from_peer(encrypted_msg)
            comp = msgpack.unpackb(decrypted_data)
            
            print(f"[{self.node_id}] Received proposal for computation {comp['id']}")
            
            # Store computation
            self.active_computations[comp['id']] = comp
            
            # Get list of all heavy nodes (including self)
            heavy_nodes = await self._discover_heavy_nodes()
            
            # Broadcast to entire network
            broadcast_msg = {
                "computation": comp,
                "heavy_nodes": heavy_nodes  # Tell light nodes where to send shares
            }
            
            # Encrypt for broadcast (using a symmetric key for efficiency)
            # In production, use a group key or separate encryption per node
            for peer_id in self.peer_keys:
                encrypted_broadcast = self.encrypt_for_peer(
                    msgpack.packb(broadcast_msg),
                    peer_id
                )
                await self.nc.publish("comp.broadcast", msgpack.packb(encrypted_broadcast))
            
            print(f"[{self.node_id}] Broadcasted computation to network")
            
            # As a heavy node, we also execute if we have light capabilities
            # This is where heavy inherits from light
            await self._execute_as_light(comp, heavy_nodes)
            
            # Start collection task
            asyncio.create_task(self._collect_and_aggregate(comp))
        
        except Exception as e:
            print(f"[{self.node_id}] Error handling proposal: {e}")
    
    async def _execute_as_light(self, comp: dict, heavy_nodes: List[str]):
        """Execute computation as a light node (since heavy inherits from light)."""
        # Execute computation using parent class method
        result = await self.execute_computation(comp['query'])
        
        # Generate secret shares
        shares = self.generate_secret_shares(100)
        
        # Send shares to heavy nodes (including self)
        for i, heavy_id in enumerate(heavy_nodes[:2]):
            share_value = shares[i] if i < len(shares) else 0
            
            response = {
                "computation_id": comp['id'],
                "node_id": self.node_id,
                "result": result,
                "share": share_value,
                "share_index": i,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            if heavy_id == self.node_id:
                # Add to our own buffer directly
                if comp['id'] not in self.aggregation_buffer:
                    self.aggregation_buffer[comp['id']] = []
                self.aggregation_buffer[comp['id']].append(response)
            else:
                # Send to other heavy node
                if heavy_id in self.peer_keys:
                    encrypted = self.encrypt_for_peer(
                        msgpack.packb(response),
                        heavy_id
                    )
                    await self.nc.publish(
                        f"comp.result.{heavy_id}",
                        msgpack.packb(encrypted)
                    )
            
            print(f"[{self.node_id}] Sent share {share_value} to {heavy_id} (as light)")
    
    async def _handle_result(self, msg):
        """Handle results from light nodes."""
        try:
            encrypted_msg = msgpack.unpackb(msg.data)
            decrypted_data = self.decrypt_from_peer(encrypted_msg)
            result = msgpack.unpackb(decrypted_data)
            
            comp_id = result['computation_id']
            
            # Add to aggregation buffer
            if comp_id not in self.aggregation_buffer:
                self.aggregation_buffer[comp_id] = []
            
            self.aggregation_buffer[comp_id].append(result)
            
            print(f"[{self.node_id}] Received share {result['share']} from {result['node_id']}")
        
        except Exception as e:
            print(f"[{self.node_id}] Error handling result: {e}")
    
    async def _collect_and_aggregate(self, comp: dict):
        """Collect results and aggregate shares."""
        comp_id = comp['id']
        deadline = comp.get('deadline', 30)
        
        # Wait for deadline
        await asyncio.sleep(deadline)
        
        # Aggregate shares
        if comp_id in self.aggregation_buffer:
            results = self.aggregation_buffer[comp_id]
            
            # Sum all shares (MPC-style aggregation)
            total_shares = sum(r['share'] for r in results)
            
            print(f"[{self.node_id}] Aggregated {len(results)} results")
            print(f"[{self.node_id}] Total share value: {total_shares}")
            
            # Send aggregated result back to proposer
            aggregated = {
                "computation_id": comp_id,
                "aggregated_value": total_shares,
                "num_results": len(results),
                "aggregator": self.node_id,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            proposer_id = comp['proposer']
            if proposer_id in self.peer_keys:
                encrypted = self.encrypt_for_peer(
                    msgpack.packb(aggregated),
                    proposer_id
                )
                await self.nc.publish(
                    f"comp.final.{proposer_id}",
                    msgpack.packb(encrypted)
                )
                print(f"[{self.node_id}] Sent aggregated result to {proposer_id}")
            
            # Clean up buffer
            del self.aggregation_buffer[comp_id]
    
    async def _discover_heavy_nodes(self) -> List[str]:
        """Discover all heavy nodes in the network."""
        try:
            response = await self.nc.request(
                "node.discover.heavy",
                b"",
                timeout=2.0
            )
            if response.data:
                nodes = msgpack.unpackb(response.data)
                heavy_ids = [n['node_id'] for n in nodes if n.get('type') == 'heavy']
                
                # Add self if not in list
                if self.node_id not in heavy_ids:
                    heavy_ids.append(self.node_id)
                
                return heavy_ids[:2]  # Limit to 2 heavy nodes for MPC
        except:
            pass
        
        return [self.node_id]  # Default to self
    
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
        
        # Heavy node subscriptions
        await self.nc.subscribe("comp.proposal", cb=self._handle_proposal)
        await self.nc.subscribe(f"comp.result.{self.node_id}", cb=self._handle_result)
        
        # Light node subscriptions (inherited functionality)
        await self.nc.subscribe("comp.broadcast", cb=self._handle_execute_broadcast)
        await self.nc.subscribe(f"comp.final.{self.node_id}", cb=self._handle_final_result)
        
        # Discovery
        await self.nc.subscribe("node.discover.heavy", cb=self._handle_discover)
        await self.nc.subscribe("node.discover.light", cb=self._handle_discover)  # Can respond to both
        
        # Signal handling
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, lambda: asyncio.create_task(self.shutdown()))
        
        print(f"[{self.node_id}] Heavy node ready (can also act as light)!")
        await self.shutdown_event.wait()
