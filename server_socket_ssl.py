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

import json
from kafka import KafkaProducer
from kafka.errors import KafkaError
import logging

from datetime import datetime, timezone


# Server configurations (PORT > 1024 doesn't require sudo access)
HOST = "147.102.37.120"
PORT = 6666

# ---------------------------------------------------
# KAFKA configuration settings
KAFKA_HOST = '10.160.3.213:9092'
KAFKA_TOPIC = 'evidence.attestation'
# ---------------------------------------------------

# Server Client secure connection files
cert_file = "ssl_includes/server.crt"
key_file = "ssl_includes/server.key"

# Default Messages
att_rqrt_message_service = "attestation_srvc"
att_rqrt_message_kernel = "attestation_krnl"

# ---------------------------------------------------
# Reference values for verification (don't share them with anyone!)
vrf_checksum_service = "2afe2f2a9bd500bba2e72e4a10d9cb4a49310dc06517a244cf66b598d74c49e6"
vrf_checksum = "2afe2f2a9bd500bba2e72e4a10d9cb4a49310dc06517a244cf66b598d74c49e6"
vrf_signature = "f8e2a7b1d6934c0f9dc5450e76a91b6e5e257db4c52e9f062d2464937d3a1c99"
bitstr_key = "privateer123"
# ---------------------------------------------------

# For development purposes
puf_response = "76ca128ac40c6da5183134a61337527f"

# ---------------------------------------------------
# vrf_checksum_service = "2afe2f2a9bd500bba2e72e4a10d9cb4a49310dc06517a244cf66b598d74c49e6"
# vrf_checksum = "2afe2f2a9bd500bba2e72e4a10d9cb4a49310dc06517a244cf66b598d74c49e6"
# ---------------------------------------------------


# For reseting terminal text color
init(autoreset=True)

# Create a socket
# server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

break_loop = False

# ---------------------------------------------------
# Auxiliary functions

def read_json_file(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)


def get_time():   
    # Get the current UTC time
    current_time = datetime.utcnow()

    # Format time ('Z' indicates UTC)
    formatted_time = current_time.strftime('%Y-%m-%dT%H:%M:%SZ')
    return formatted_time


# Create json format required for the blockchain
def generate_json(
    container_id, claim1, timestamp1, appraisal1, 
    claim2, timestamp2, appraisal2, 
    security_probe_timestamp, nonce, 
    signature_algorithm_type, signature, key_ref
):
    data = {
        "attestationReports": [
        {
                "containerID": container_id,
                "attestationReport": [
                    {
                        "claim": claim1,
                        "timestamp": timestamp1,
                        "appraisal": appraisal1
                    },
                    {
                        "claim": claim2,
                        "timestamp": timestamp2,
                        "appraisal": appraisal2
                    }
                ]
            }
        ],
        "securityProbeEvidence": {
            "timestamp": security_probe_timestamp,
            "nonce": nonce,
            "signatureAlgorithmType": signature_algorithm_type,
            "signature": signature,
            "keyRef": key_ref
        }
    }

    # Convert the dictionary to a JSON string
    json_data = json.dumps(data, indent=2)
    
    return json_data

# ---------------------------------------------------
# Configure logging
logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


# Create a producer with JSON serializer
# producer = KafkaProducer(
#     bootstrap_servers   = KAFKA_HOST,
#     value_serializer    = lambda v: json.dumps(v).encode('utf-8')
# )



try:
    # Keep the server connection open
    while True:
        # Create a socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # TODO: Check if this works
        # Use this to prevent "OSError: [Errno 98] Address already in use"
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Bind the socket to a specific address and port
        server_socket.bind((HOST, PORT))

        # Listen for incoming connections
        server_socket.listen()

        print("-----------------------------------------------------------------")
        print("Remote Attestation Server")
        print("Server listening on {} [Port: {}]".format(HOST, PORT))
        print("-----------------------------------------------------------------")

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

        # -----------------------------------------------------------------------------------
        # PART 1 - Verify attestation service 
        # -----------------------------------------------------------------------------------
        print("---------- Infrastructure attestation ----------")
        
        # Generate attestation request with the nonce
        nonce = Crypto.Random.get_random_bytes(8)
        nonce_hex = nonce.hex()
        print("Nonce:", nonce_hex)
        att_request = att_rqrt_message_service + nonce_hex

        secure_client_socket.sendall(att_request.encode('utf-8'))

        # Receive from the client
        data_received = secure_client_socket.recv(96)
        data_received_utf8 = data_received.decode('utf-8')
        timestamp_verify_service = get_time()

        # Extract the different variables from the attestation report
        parsed_received = {}

        parsed_received['nonce'] = data_received_utf8[0:16]
        parsed_received['checksum'] = data_received_utf8[16:80]

        # Print received attestation report
        print("-----------------------------------------------------------------")
        print("Received Attestation Report")
        print("Nonce : {}".format(parsed_received['nonce']))
        print("Checksum : {}".format(parsed_received['checksum']))
        print("-----------------------------------------------------------------")
        print("Reference Values")
        print("Checksum :", vrf_checksum_service)
        print("-----------------------------------------------------------------")
        print("Attestation result:")

        # Check if we received the correct values
        if (parsed_received['nonce'] != nonce_hex) or (parsed_received['checksum'] != vrf_checksum_service):
            print(f"{Fore.RED}\u2718 [Infrastructure] Attestation failed")

            # Send message that the attestation failed
            att_status = "fail"
            secure_client_socket.sendall(att_status.encode('utf-8'))

        else:
            print(f"{Fore.GREEN}\u2713 [Infrastructure] Successful Attestation")

            # Send message that the attestation completed successfully
            att_status = "pass"
            secure_client_socket.sendall(att_status.encode('utf-8'))


            # -----------------------------------------------------------------------------------
            # PART 2 - Verify FPGA kernel 
            # -----------------------------------------------------------------------------------
            print("---------- Accelerated kernel attestation ----------")

            # Generate attestation request with the nonce
            nonce = Crypto.Random.get_random_bytes(8)
            nonce_hex = nonce.hex()
            print("Nonce:", nonce_hex)
            att_request = att_rqrt_message_kernel + nonce_hex

            secure_client_socket.sendall(att_request.encode('utf-8'))

            # Receive from the client
            data_received = secure_client_socket.recv(144)
            data_received_utf8 = data_received.decode('utf-8')
            timestamp_verify_kernel = get_time()
            
            # Extract the different variables from the attestation report
            parsed_received = {}

            parsed_received['nonce'] = data_received_utf8[0:16]
            parsed_received['checksum'] = data_received_utf8[16:80]
            parsed_received['certificate'] = data_received_utf8[80:144]

            # Print received attestation report
            print("-----------------------------------------------------------------")
            print("Received Attestation Report")
            print("Nonce : {}".format(parsed_received['nonce']))
            print("Checksum : {}".format(parsed_received['checksum']))
            print("Certificate : {}".format(parsed_received['certificate']))
            print("-----------------------------------------------------------------")
            print("Reference Values")
            print("Checksum :", vrf_checksum)
            print("Certificate :", vrf_signature)
            print("-----------------------------------------------------------------")
            print("Attestation result:")

            # Check if we received the correct values
            if (parsed_received['nonce'] != nonce_hex) or (parsed_received['checksum'] != vrf_checksum) or (parsed_received['certificate'] != vrf_signature):
                print(f"{Fore.RED}\u2718 [Kernel] Attestation failed")

                # Send message that the attestation failed
                att_status = "fail"
                secure_client_socket.sendall(att_status.encode('utf-8'))

            else:
                print(f"{Fore.GREEN}\u2713 [Kernel] Successful Attestation")

                # Send message that the attestation completed successfully
                att_status = "pass"
                secure_client_socket.sendall(att_status.encode('utf-8'))

                # Receive the key request 
                data_received = secure_client_socket.recv(128)
                data_received_utf8 = data_received.decode('utf-8')      

                # Send the bitstream decryption key
                if data_received_utf8 == "bitstr_key":
                    # Exchange the key using DH
                    print("-----------------------------------------------------------------")
                    print("Sending the bitstream decryption key using ECDH...")
                    server_ecdh = DiffieHellman()

                    # Exchange public keys with the client
                    public_key_hex = get_key_hex(server_ecdh.public_key)
                    secure_client_socket.sendall(public_key_hex.encode('utf-8'))
                    public_key_received = secure_client_socket.recv(1024)
                    public_key_received_utf8 = public_key_received.decode('utf-8')
                    public_key_received_bytes = bytes.fromhex(public_key_received_utf8)
                    public_key_received_object = get_key_object(public_key_received_bytes)

                    # Complete the key exchange
                    bitstr_key_enc_ecdh = server_ecdh.encrypt(public_key_received_object, bitstr_key)
                    bitstr_key_enc_ecdh_hex = bitstr_key_enc_ecdh.hex()
                    secure_client_socket.sendall(bitstr_key_enc_ecdh_hex.encode('utf-8'))
                    print("Key Derivation Completed")

                else:
                    print("[Error] Unable to send the bitstream decryption key")


        # -------------------------------------------------------------------------------------
        # Upload the attestation results to the blockchain through KAFKA        
        # json_data = read_json_file('input_1.json')

        container_id = "edge_accelerator"
        claim1 = "edge_server_attestation_service"
        timestamp1 = timestamp_verify_service
        appraisal1 = None

        claim2 = "edge_accelerator_kernel"
        timestamp2 = timestamp_verify_kernel
        appraisal2 = None

        security_probe_timestamp = get_time()
        nonce = parsed_received['nonce']
        signature_algorithm_type = "ECDH-SHA256"
        signature = ""
        key_ref = ""


        json_data = generate_json(
            container_id, claim1, timestamp1, appraisal1, 
            claim2, timestamp2, appraisal2, 
            security_probe_timestamp, nonce, 
            signature_algorithm_type, signature, key_ref
        )


        future = producer.send(KAFKA_TOPIC, json_data)

        try:
            record_metadata = future.get(timeout=10)
            # Successful result returns assigned partition and offset
            print("[debug] topic : " + record_metadata.topic)
            print("[debug] partition : " + str(record_metadata.partition))
            print("[debug] offset : " + str(record_metadata.offset))

        except KafkaError as e:
            log.exception("Error sending message")
            pass

        producer.flush()
        producer.close()

        # -------------------------------------------------------------------------------------
        # Condition to break infinite loop
        if (break_loop == True):
            break

except KeyboardInterrupt:
    print("Server terminated by user.")

finally:
    print("Exiting...")
    print("-----------------------------------------------------------------")
    server_socket.close()
