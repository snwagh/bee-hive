#!/usr/bin/env python3
import asyncio
import json
import random
import signal
from typing import Tuple
import msgpack
from datetime import datetime
from base_node import BaseNode

class LightNode(BaseNode):
    """Light node that executes computations."""
    
    def __init__(self, node_id: str, nats_url: str, data_dir: str):
        super().__init__(node_id, nats_url, data_dir)
        print(f"[{node_id}] Initialized as light node")
    
    def get_node_type(self) -> str:
        return "light"
    
    def generate_secret_shares(self, value: int = 100) -> Tuple[int, int]:
        """Generate two random values that sum to the given value (MPC-style)."""
        share1 = random.randint(0, value)
        share2 = value - share1
        return share1, share2
    
    async def execute_computation(self, query: str) -> str:
        """Execute the actual computation (simulated LLM call)."""
        print(f"[{self.node_id}] Executing: {query}")
        await asyncio.sleep(2)  # Simulate LLM processing
        
        # In real implementation, call Ollama here
        response = f"Response from {self.node_id}: Processed '{query}'"
        return response
    
    async def _handle_execute_broadcast(self, msg):
        """Handle execution request broadcast from heavy nodes."""
        try:
            # Decrypt the message
            encrypted_msg = msgpack.unpackb(msg.data)
            decrypted_data = self.decrypt_from_peer(encrypted_msg)
            data = msgpack.unpackb(decrypted_data)
            
            comp = data['computation']
            heavy_nodes = data['heavy_nodes']  # List of heavy nodes to respond to
            
            print(f"[{self.node_id}] Received broadcast for computation {comp['id']}")
            
            # Execute computation
            result = await self.execute_computation(comp['query'])
            
            # Generate secret shares (MPC-style) - total value of 100
            shares = self.generate_secret_shares(100)
            
            # Send one share to each heavy node
            for i, heavy_id in enumerate(heavy_nodes[:2]):  # Max 2 heavy nodes
                if heavy_id in self.peer_keys:
                    share_value = shares[i] if i < len(shares) else 0
                    
                    response = {
                        "computation_id": comp['id'],
                        "node_id": self.node_id,
                        "result": result,
                        "share": share_value,  # Secret share
                        "share_index": i,
                        "timestamp": datetime.utcnow().isoformat()
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
                    
                    print(f"[{self.node_id}] Sent share {share_value} to {heavy_id}")
        
        except Exception as e:
            print(f"[{self.node_id}] Error handling execution: {e}")
    
    async def _submit_computation(self, data: dict):
        """Submit computation to heavy nodes."""
        import uuid
        comp_id = str(uuid.uuid4())[:8]
        
        computation = {
            "id": comp_id,
            "proposer": self.node_id,
            "query": data['query'],
            "targets": data.get('targets', []),  # Target heavy nodes
            "deadline": data.get('deadline', 30),
            "timestamp": datetime.utcnow().isoformat()
        }
        
        self.active_computations[comp_id] = computation
        
        # Find heavy nodes to send to
        target_heavy = data.get('targets', [])
        if not target_heavy:
            # Discover heavy nodes
            response = await self.nc.request(
                "node.discover.heavy",
                b"",
                timeout=2.0
            )
            if response.data:
                nodes = msgpack.unpackb(response.data)
                target_heavy = [n['node_id'] for n in nodes if n.get('type') == 'heavy'][:2]
        
        # Send to heavy nodes
        for heavy_id in target_heavy:
            if heavy_id in self.peer_keys:
                encrypted = self.encrypt_for_peer(
                    msgpack.packb(computation),
                    heavy_id
                )
                await self.nc.publish("comp.proposal", msgpack.packb(encrypted))
        
        print(f"[{self.node_id}] Submitted computation {comp_id} to {len(target_heavy)} heavy nodes")
        return {"status": "submitted", "id": comp_id, "heavy_nodes": target_heavy}
    
    async def _handle_final_result(self, msg):
        """Handle aggregated result from heavy nodes."""
        try:
            encrypted_msg = msgpack.unpackb(msg.data)
            decrypted_data = self.decrypt_from_peer(encrypted_msg)
            result = msgpack.unpackb(decrypted_data)
            
            comp_id = result['computation_id']
            print(f"[{self.node_id}] Received aggregated result for {comp_id}")
            print(f"  Aggregated value: {result.get('aggregated_value', 'N/A')}")
            
            # Store result
            if comp_id in self.active_computations:
                self.active_computations[comp_id]['status'] = 'completed'
                self.active_computations[comp_id]['result'] = result
                
                # Save to file
                result_file = self.data_dir / f"result_{comp_id}.json"
                with open(result_file, 'w') as f:
                    json.dump({
                        "computation_id": comp_id,
                        "aggregated_value": result.get('aggregated_value'),
                        "heavy_node": result.get('aggregator'),
                        "timestamp": result.get('timestamp')
                    }, f, indent=2)
                
                # If we're the original proposer and received multiple results, aggregate
                if self.active_computations[comp_id]['proposer'] == self.node_id:
                    await self._aggregate_final_results(comp_id)
        
        except Exception as e:
            print(f"[{self.node_id}] Error handling final result: {e}")
    
    async def _aggregate_final_results(self, comp_id: str):
        """Aggregate results from multiple heavy nodes (proposer only)."""
        comp = self.active_computations.get(comp_id)
        if not comp or comp.get('proposer') != self.node_id:
            return
        
        # Wait a bit for all results
        await asyncio.sleep(2)
        
        # Aggregate all received values
        if 'final_values' not in comp:
            comp['final_values'] = []
        
        if 'result' in comp:
            comp['final_values'].append(comp['result'].get('aggregated_value', 0))
        
        total = sum(comp['final_values'])
        print(f"[{self.node_id}] Final aggregated value: {total}")
        
        # Save final result
        final_file = self.data_dir / f"final_{comp_id}.json"
        with open(final_file, 'w') as f:
            json.dump({
                "computation_id": comp_id,
                "final_total": total,
                "components": comp['final_values'],
                "timestamp": datetime.utcnow().isoformat()
            }, f, indent=2)
    
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
        # Setup
        self.load_keys()
        await self.connect_nats()
        await self.start_ipc_server()
        
        # Subscribe to broadcasts from heavy nodes
        await self.nc.subscribe("comp.broadcast", cb=self._handle_execute_broadcast)
        
        # Subscribe to final results
        await self.nc.subscribe(f"comp.final.{self.node_id}", cb=self._handle_final_result)
        
        # Subscribe to discovery
        await self.nc.subscribe("node.discover.light", cb=self._handle_discover)
        
        # Signal handling
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, lambda: asyncio.create_task(self.shutdown()))
        
        print(f"[{self.node_id}] Light node ready!")
        await self.shutdown_event.wait()
