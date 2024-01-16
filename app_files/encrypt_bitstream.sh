#!/bin/bash 

# Simple bash script to add signature and encrypt bitstream from .xclbin file with OpenSSL and AES protocol

# Variables definition
INPUT_XCLBIN="vadd.xclbin"
XCLBIN_SIGNATURE="f8e2a7b1d6934c0f9dc5450e76a91b6e5e257db4c52e9f062d2464937d3a1c99"
BITSTR_KEY="privateer123"

# Filenames
INPUT_FILENAME=$(basename "$INPUT_XCLBIN" .xclbin)
XCLBIN_ENC="${INPUT_FILENAME}_enc.xclbin"
XCLBIN_ENC_SIGNED="${INPUT_FILENAME}_enc_signed.xclbin"

# Extract bitstream from the .xclbin application file
echo "Exctracting bitstream from file:" $INPUT_XCLBIN  
xclbinutil --input $INPUT_XCLBIN --dump-section BITSTREAM:RAW:bitstr_raw.bit --force

# Encrypt the bitstream using a user defined key
echo "Encrypting the bitstream using AES standard..."
openssl enc -aes-256-cbc -salt -in bitstr_raw.bit -out bitstr_raw_enc.bit -k $BITSTR_KEY -pbkdf2

# Replace the original bitstream with the encrypted
echo "Create .xclbin file with the encrypted bitstream..."
xclbinutil --input $INPUT_XCLBIN --replace-section BITSTREAM:RAW:bitstr_raw_enc.bit --force --output $XCLBIN_ENC

# Add user signature to the .xclbin application
echo "Adding user signature to" $XCLBIN_ENC
xclbinutil --input $XCLBIN_ENC --add-signature $XCLBIN_SIGNATURE --force --output $XCLBIN_ENC_SIGNED

# Calculate encrypted bitstream checksum for attestation
echo "Bitstream SHA-256 checksum:" 
sha256sum bitstr_raw_enc.bit

# Remove unecessary files
echo "Cleaning files..."
rm $XCLBIN_ENC
rm bitstr_raw.bit
rm bitstr_raw_enc.bit
echo "Done"