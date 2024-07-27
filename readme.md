# Pythonic Implementation of Secure End-End Encrypted Messaging using Signal Protocol

This project presents a native implementation of the Signal Protocol for secure end-to-end messaging, using the `cryptography` library in Python. The project includes the development of a secure messaging application with a simple client-side GUI created using `PySide6` and a web-socket based messaging system utilizing `socketio`. The server adheres to the Signal Protocol Specification, storing only credentials and public keys, receiving only ciphertext, and enabling multiple concurrent two-way communications. The client application allows users to select chat partners and locally persist chat messages, enabling local chat history. The cryptographic infrastructure developed can be found in `client/utils.py`

For the Signal Protocol implementation, the Extended Triple Diffie-Hellman (X3DH) key agreement protocol and the Double Ratchet Algorithm were employed. The X3DH protocol facilitates the establishment of a shared secret key between two parties using their respective public keys, ensuring forward secrecy and cryptographic deniability. The Double Ratchet Algorithm was implemented to provide secure and synchronized key exchanges for continued communication.

The server uses `tinyDB` to store client information and acts as a communication conduit between clients without retaining any messages. The client-side application features a user-friendly interface for authentication, logging in, selecting chat partners, and viewing chat history. This project demonstrates the practical application of secure messaging protocols and provides a robust foundation for further development in secure communication systems.

[Link to Video Demonstration of the Implementation](https://youtu.be/DEt4LJ9cVp0?si=kW0laSq2_8GrXgHo)
[Link to Documentation and Implementation Report](https://github.com/rohankalbag/cryptography-signal-protocol/blob/main/docs.pdf)

### Dependencies
```python
pip install -r requirements.txt
```

### Run Server

```python
python3 server/server.py
```

### Run Chat Interface for Client

```python
python3 main.py
```