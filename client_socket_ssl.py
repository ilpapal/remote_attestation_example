# ---------------------------------------------------
# Example for Client w/ socket SSL communication 
# ---------------------------------------------------
# Creator   : Ilias Papalamprou
# Date      : 12/2023
# ---------------------------------------------------
import socket
import ssl
import subprocess
from file_checksum import calculate_sha256_checksum
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from colorama import Fore, init


# Server configurations
HOST = '147.102.37.120'
PORT = 6666

# Server Client secure connection files
cert_file = 'ssl_includes/client.crt'
key_file = 'ssl_includes/client.key'

# Default Messages
att_request = "attestation_rqst"

# Acceleartion files
exec_file = "app_files/hello_world"
xclbin_file = "app_files/vadd_enc_signed.xclbin"
# xclbin_file = "app_files/vadd.xclbin"
bitstr_raw_file = "app_files/bitstream_raw_enc.bit"
xclbin_output_file = "app_files/output.xclbin"


# For reseting terminal text color
init(autoreset=True)

# Auxiliary functions to extract command output data
def extract_first_element(line):
    # Split the line by space and return the first element
    elements = line.split()
    return elements[0] if elements else None


# Calculate values required for remote attestation
def remote_attestation(nonce, input_file):
    # Extract bitstream from the xclbin application into a seperate file
    bitstr_section = "BITSTREAM:RAW:" + bitstr_raw_file
    subprocess.run(["xclbinutil", "--force", "--dump-section", bitstr_section, "--input", input_file])

    # Calculate bitstream checksum
    file_checksum = calculate_sha256_checksum(bitstr_raw_file)

    # Extract file signature
    get_signature_command = ["xclbinutil", "--input", xclbin_file, "--get-signature", "--quiet"]

    proc = subprocess.Popen(get_signature_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, _ = proc.communicate()
    output_str = output.decode('ascii')

    # Extract the signature from the command output
    if output_str != "":
        file_signature = extract_first_element(output_str)
        print("File Signature : {}".format(file_signature))
    else:
        file_signature = ""
        print("[Error] Unable to get file signature")

    # Generate attestation report including the received nonce
    attestation_report = nonce + file_checksum + file_signature

    return attestation_report


# Bitstream decryption function
def bitstream_decryption(input_file, bitstr_key):
    # Decrypt the bitstream file using OpenSSL and AES algorithm, with the received key after a successful attestation
    print("Decrypting bitstream...")
    bitstr_dec_raw = "app_files/bitstream_raw_dec.bit"
    subprocess.run(["openssl", "enc", "-d", "-aes-256-cbc", "-in", input_file, "-out", bitstr_dec_raw, "-k", bitstr_key, "-pbkdf2"])

    # Load the decrypted bitstream back to the xclbin file 
    print("Building the xclbin file")
    bitstr_section = "BITSTREAM:RAW:" + bitstr_dec_raw
    subprocess.run(["xclbinutil", "--force", "--input", xclbin_file, "--replace-section", bitstr_section, "--output", xclbin_output_file])

    # Remove the raw bitstream files
    print("Cleaning files...")
    subprocess.run(["rm", bitstr_dec_raw])
    subprocess.run(["rm", bitstr_raw_file])

# Main program function
def main():
    # Create a socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    try:
        client_socket.connect((HOST, PORT))

    # Print an error if the connection was unsuccessful
    except Exception as e:
        print("[Client] Connection error: {}".format(e))

    print("#################################################################")
    print("Edge Accelerator connected to {} [Port: {}]".format(HOST, PORT))
    print("#################################################################")

    # Wrap the socket with SSL/TLS
    ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

    # Disabling hostname verification
    ssl_context.check_hostname = False  

    # Disabling certificate verification
    ssl_context.verify_mode = ssl.CERT_NONE  

    # Load client certificate and private key
    ssl_context.load_cert_chain(certfile=cert_file, keyfile=key_file)
    secure_client_socket = ssl_context.wrap_socket(client_socket, server_hostname=HOST)

    # Receive and print the response from the server
    data_received = secure_client_socket.recv(1024)
    data_received_utf8 = data_received.decode('utf-8')

    # Perform remote attestation procedure if the correct request is received [att_rsqt + nonce]
    if data_received_utf8[0:16] == att_request:
        print("Initalizing Remote Attestation Protocol... [Received: {}]".format(data_received_utf8))

        # Get the nonce value
        nonce = data_received_utf8[16:32]

        # Remote attestation function
        attestation_report = remote_attestation(nonce, xclbin_file)

        # Send attestation report to the verification server
        print("#################################################################")
        print("Sending Attestation report to the Verification Server...")
        print(attestation_report)

        secure_client_socket.sendall(attestation_report.encode('utf-8'))

        print("#################################################################")
        print("Waiting for response...")

        data_received = secure_client_socket.recv(1024)
        data_received_utf8 = data_received.decode('utf-8')

        if data_received_utf8 == "fail":
            print(f"{Fore.RED}\u2718 Failed Attestation")
            secure_client_socket.close()

        elif data_received_utf8 == "pass":
            print(f"{Fore.GREEN}\u2713 Successful Attestation") 

            # Request the bitstream decryption key
            print("#################################################################")
            print("Getting bitstream decryption key from the server...")
            bitstr_key_rqst = "bitstr_key"
            secure_client_socket.sendall(bitstr_key_rqst.encode('utf-8'))

            # TODO: Exchange the key using DH
            data_received = secure_client_socket.recv(1024)
            bitstr_decryption_key = data_received.decode('utf-8')

            # Decrypt the bitstream and build the xclbin file
            print("#################################################################")
            bitstream_decryption(bitstr_raw_file, bitstr_decryption_key)
            
            # Load the .xclbin application to the FPGA
            print("#################################################################")
            # print("Loading the application to the accelerator...")            
            # subprocess.run(["xclbinutil", "--help"])

    else:
        print("[Error] - Received: {}".format(data_received_utf8))

        # Close the connection
        secure_client_socket.close()

if __name__ == "__main__":
    main()
