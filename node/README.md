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



1. First Time - Register Identity
```bash
# Terminal 1: Alice registers
python node.py nats://20.81.248.221:4222 register
# Enter: handle=alice, email=alice@example.com, password

# Terminal 2: Bob registers
python node.py nats://20.81.248.221:4222 register
# Enter: handle=bob, email=bob@example.com, password
```

2. Connect with Existing Identity
```bash
# Alice connects (only Alice can use this identity with correct password)
python node.py nats://20.81.248.221:4222 connect
# Enter: handle=alice, password

# Bob connects
python node.py nats://20.81.248.221:4222 connect
# Enter: handle=bob, password

# If someone tries to use alice's handle with wrong password - FAILS!
```

3. List Registered Identities
```bash
python node.py nats://20.81.248.221:4222 list
```
