"""IPC communication helpers for handler daemon"""

import asyncio
import json
from pathlib import Path


async def send_command(socket_path: Path, command: dict) -> dict:
    """Send command to handler daemon via IPC socket"""
    if not socket_path.exists():
        raise ConnectionError(f"Handler socket not found: {socket_path}")

    try:
        reader, writer = await asyncio.open_unix_connection(str(socket_path))

        # Send command
        message = json.dumps(command).encode() + b'\n'
        writer.write(message)
        await writer.drain()

        # Receive response
        data = await reader.readline()
        response = json.loads(data.decode())

        writer.close()
        await writer.wait_closed()

        return response
    except Exception as e:
        raise ConnectionError(f"Failed to communicate with handler: {e}")


async def start_ipc_server(socket_path: Path, handler_callback):
    """Start IPC server for handler daemon"""
    # Remove existing socket if present
    if socket_path.exists():
        socket_path.unlink()

    async def handle_client(reader, writer):
        try:
            data = await reader.readline()
            if not data:
                return

            command = json.loads(data.decode())
            response = await handler_callback(command)

            message = json.dumps(response).encode() + b'\n'
            writer.write(message)
            await writer.drain()
        except Exception as e:
            error_response = {"status": "error", "message": str(e)}
            writer.write(json.dumps(error_response).encode() + b'\n')
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_unix_server(handle_client, str(socket_path))
    return server
