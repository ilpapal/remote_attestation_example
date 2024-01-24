# ---------------------------------------------------
# Example for Server w/ socket SSL communication 
# ---------------------------------------------------
# Creator   : Ilias Papalamprou
# Date      : 12/2023
# ---------------------------------------------------
import socket
import ssl
import Crypto.Random
from ecdh import DiffieHellman, get_key_hex, get_key_object
from colorama import Fore, init

# Server configurations (PORT > 1024 doesn't require sudo access)
HOST = "147.102.37.120"
PORT = 6666

# Server Client secure connection files
cert_file = "ssl_includes/server.crt"
key_file = "ssl_includes/server.key"

# Default Messages
att_rqrt_message = "attestation_rqst"

# ---------------------------------------------------
# Reference values for verification (don't share them with anyone!)
vrf_checksum = "e305267c3dfb2cf622af593cd02822b2966fa7a4a853e810b0471c8b9ac60a2a"
vrf_signature = "f8e2a7b1d6934c0f9dc5450e76a91b6e5e257db4c52e9f062d2464937d3a1c99"
bitstr_key = "privateer123"
# ---------------------------------------------------

# For reseting terminal text color
init(autoreset=True)


# Create a socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    # Keep the server connection open
    # while True:

    # TODO: Check if this works
    # Use this to prevent "OSError: [Errno 98] Address already in use"
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Bind the socket to a specific address and port
    server_socket.bind((HOST, PORT))

    # Listen for incoming connections
    server_socket.listen()

    print("#################################################################")
    print("Remote Attestation Server")
    print("Server listening on {} [Port: {}]".format(HOST, PORT))
    print("#################################################################")

    # Accept a client connection
    client_socket, client_address = server_socket.accept()

    # Wrap the socket with SSL/TLS
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(certfile=cert_file, keyfile=key_file)

    secure_client_socket = ssl_context.wrap_socket(
        client_socket, 
        server_side=True,
        do_handshake_on_connect=True,
    )

    # Send remote attestation request after successful connection along with a nonce
    print("Sending Remote Attestation request...")

    # Generate attestation request with the nonce
    nonce = Crypto.Random.get_random_bytes(8)
    nonce_hex = nonce.hex()
    att_request = att_rqrt_message + nonce_hex

    secure_client_socket.sendall(att_request.encode('utf-8'))

    # Receive and print the message from the client
    data_received = secure_client_socket.recv(144)
    data_received_utf8 = data_received.decode('utf-8')

    
    # Extract the different variables from the attestation report
    parsed_received = {}

    parsed_received['nonce'] = data_received_utf8[0:16]
    parsed_received['checksum'] = data_received_utf8[16:80]
    parsed_received['certificate'] = data_received_utf8[80:144]


    # Print received attestation report
    print("Received attestation report:")
    print("Nonce : {}".format(parsed_received['nonce']))
    print("Checksum : {}".format(parsed_received['checksum']))
    print("Certificate : {}".format(parsed_received['certificate']))

    print("#################################################################")
    print("Attestation result:")

    # Check if we received the correct values
    if (parsed_received['nonce'] != nonce_hex) or (parsed_received['checksum'] != vrf_checksum) or (parsed_received['certificate'] != vrf_signature):
        print(f"{Fore.RED}\u2718 Attestation failed")

        # Send message that the attestation failed
        att_status = "fail"
        secure_client_socket.sendall(att_status.encode('utf-8'))

    else:
        print(f"{Fore.GREEN}\u2713 Designer einai filos mou :)")

        # Send message that the attestation completed successfuly
        att_status = "pass"
        secure_client_socket.sendall(att_status.encode('utf-8'))

        # Receive the key request 
        data_received = secure_client_socket.recv(128)
        data_received_utf8 = data_received.decode('utf-8')      

        # Send the bitstream decryption key
        if data_received_utf8 == "bitstr_key":
            # print("Sending the bitstream decryption key...")
            # secure_client_socket.sendall(bitstr_key.encode('utf-8'))

            # TODO: Exchange the key using DH
            print("#################################################################")
            print("Sending the bitstream decryption key using ECDH...")
            server_ecdh = DiffieHellman()

            # Exchange public keys with the client
            public_key_hex = get_key_hex(server_ecdh.public_key)
            secure_client_socket.sendall(public_key_hex.encode('utf-8'))
            public_key_received = secure_client_socket.recv(1024)
            public_key_received_utf8 = public_key_received.decode('utf-8')
            public_key_received_bytes = bytes.fromhex(public_key_received_utf8)

            print("==========")
            print(public_key_hex)
            print("==========")
            print(public_key_received_utf8)
            print("==========")
            print(public_key_received_bytes)

            # received_public_key = serialization.load_der_public_key(
            #     public_key_received_bytes,
            #     backend=default_backend()
            # )

            # Complete the key exchange
            # bitstr_key_enc_ecdh = server_ecdh.encrypt(public_key_received_bytes, bitstr_key)
            bitstr_key_enc_ecdh = server_ecdh.encrypt(received_public_key, bitstr_key)
            bitstr_key_enc_ecdh_hex = bitstr_key_enc_ecdh.hex()
            secure_client_socket.sendall(bitstr_key_enc_ecdh_hex.encode('utf-8'))
            print("Completed key exchange")

        else:
            print("[Error] Unable to send the bitstream decryption key")


except KeyboardInterrupt:
    print("Server terminated by user.")

finally:
    print("Exiting...")
    server_socket.close()