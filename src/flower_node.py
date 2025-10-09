#!/usr/bin/env python3
import asyncio
import click
from light_node import LightNode
from heavy_node import HeavyNode

DEFAULT_NATS_URL = "nats://20.81.248.221:4222"

@click.command()
@click.argument('node_id')
@click.argument('node_type', type=click.Choice(['heavy', 'light']))
@click.option('--nats-url', default=DEFAULT_NATS_URL, help='NATS server URL')
@click.option('--data-dir', default='./data', help='Data directory')
def main(node_id, node_type, nats_url, data_dir):
    """Run a Flower Node in the Bee-Hive network."""
    
    # Create appropriate node instance
    if node_type == 'heavy':
        node = HeavyNode(node_id, nats_url, f"{data_dir}/{node_id}")
    else:
        node = LightNode(node_id, nats_url, f"{data_dir}/{node_id}")
    
    # Run the node
    try:
        asyncio.run(node.run())
    except KeyboardInterrupt:
        print(f"\n[{node_id}] Interrupted by user")
        # Shutdown is handled by signal handler
    except Exception as e:
        print(f"[{node_id}] Error: {e}")
        # Try to shutdown gracefully
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(node.shutdown())
        except:  # noqa: E722
            pass

if __name__ == '__main__':
    main()
