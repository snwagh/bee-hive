#!/usr/bin/env python3
import asyncio
import json
import sys
from pathlib import Path
import click

async def send_command(node_id: str, command: dict):
    """Send command to a flower node."""
    socket_path = Path(f"/tmp/flower-node-{node_id}.sock")
    
    if not socket_path.exists():
        raise click.ClickException(f"Node {node_id} not running (socket not found)")
    
    reader, writer = await asyncio.open_unix_connection(str(socket_path))
    
    try:
        writer.write(json.dumps(command).encode())
        await writer.drain()
        
        data = await reader.read(65536)
        return json.loads(data.decode())
    finally:
        writer.close()
        await writer.wait_closed()

@click.group()
def cli():
    """Bee-Hive Network CLI."""
    pass

@cli.command()
@click.argument('query')
@click.option('--node', '-n', default='heavy-1', help='Node to submit from')
@click.option('--targets', '-t', multiple=True, help='Target heavy nodes')
@click.option('--deadline', '-d', default=30, help='Deadline in seconds')
def submit(query, node, targets, deadline):
    """Submit a computation to the network."""
    command = {
        'type': 'submit',
        'data': {
            'query': query,
            'targets': list(targets),
            'deadline': deadline
        }
    }
    
    result = asyncio.run(send_command(node, command))
    
    if 'error' in result:
        click.echo(f"Error: {result['error']}", err=True)
    else:
        click.echo(f"✓ Computation submitted")
        click.echo(f"  ID: {result['id']}")
        click.echo(f"  Node: {node}")
        if 'heavy_nodes' in result:
            click.echo(f"  Heavy nodes: {', '.join(result['heavy_nodes'])}")

@cli.command()
@click.argument('node_id')
def status(node_id):
    """Get status of a node."""
    command = {'type': 'status'}
    result = asyncio.run(send_command(node_id, command))
    
    if 'error' in result:
        click.echo(f"Error: {result['error']}", err=True)
    else:
        click.echo(f"Node: {result['node_id']}")
        click.echo(f"Type: {result['type']}")
        click.echo(f"Connected: {result['connected']}")
        click.echo(f"Active: {result['active']} computations")
        click.echo(f"Known peers: {result['peers']}")

@cli.command()
@click.argument('node_id')
def list(node_id):
    """List computations on a node."""
    command = {'type': 'list'}
    result = asyncio.run(send_command(node_id, command))
    
    if 'error' in result:
        click.echo(f"Error: {result['error']}", err=True)
    else:
        comps = result.get('computations', [])
        if comps:
            click.echo("Active computations:")
            for comp_id in comps:
                click.echo(f"  • {comp_id}")
        else:
            click.echo("No active computations")

if __name__ == '__main__':
    cli()