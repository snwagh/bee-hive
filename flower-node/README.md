# Client side 

Client side install packages: `uv pip install nats-py cryptography`


```bash
# Register a new identity
python node.py nats://20.81.248.221:4222 register

# Connect with existing identity
python node.py nats://20.81.248.221:4222 connect

# Connect with TLS transport security
python node.py nats://20.81.248.221:4222 connect --tls

# List all identities
python node.py nats://20.81.248.221:4222 list

# Delete an identity
python node.py nats://20.81.248.221:4222 delete
```
