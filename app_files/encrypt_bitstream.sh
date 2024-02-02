#!/bin/bash 

# Simple bash script to add signature and encrypt bitstream from .xclbin file with OpenSSL and AES protocol

# Variables definition
INPUT_XCLBIN="hello_world_kernel/vadd.xclbin"
#INPUT_XCLBIN="lstm_dummy_kernel/lstm.xclbin"
XCLBIN_SIGNATURE="f8e2a7b1d6934c0f9dc5450e76a91b6e5e257db4c52e9f062d2464937d3a1c99"
BITSTR_KEY="privateer123"

# Filenames
INPUT_PATH=$(dirname "$INPUT_XCLBIN")
INPUT_FILENAME=$(basename "$INPUT_XCLBIN" .xclbin)
XCLBIN_ENC="${INPUT_PATH}/${INPUT_FILENAME}_enc.xclbin"
XCLBIN_ENC_SIGNED="${INPUT_PATH}/${INPUT_FILENAME}_enc_signed.xclbin"

# Extract bitstream from the .xclbin application file
echo "Exctracting bitstream from file:" $INPUT_XCLBIN  
xclbinutil --input $INPUT_XCLBIN --dump-section BITSTREAM:RAW:$INPUT_PATH/bitstr_raw.bit --force --quiet

# Encrypt the bitstream using a user defined key
echo "Encrypting the bitstream using AES standard..."
openssl enc -aes-256-cbc -salt -in $INPUT_PATH/bitstr_raw.bit -out $INPUT_PATH/bitstr_raw_enc.bit -k $BITSTR_KEY -pbkdf2

# Replace the original bitstream with the encrypted
echo "Create .xclbin file with the encrypted bitstream..."
xclbinutil --input $INPUT_XCLBIN --replace-section BITSTREAM:RAW:$INPUT_PATH/bitstr_raw_enc.bit --force --output $XCLBIN_ENC --quiet

# Add user signature to the .xclbin application
echo "Adding user signature to" $XCLBIN_ENC
xclbinutil --input $XCLBIN_ENC --add-signature $XCLBIN_SIGNATURE --force --output $XCLBIN_ENC_SIGNED --quiet

# Calculate encrypted bitstream checksum for attestation
echo "Bitstream SHA-256 checksum:" 
sha256sum $INPUT_PATH/bitstr_raw_enc.bit

# Remove unecessary files
echo "Cleaning temporary files..."
rm $XCLBIN_ENC
rm $INPUT_PATH/bitstr_raw.bit
rm $INPUT_PATH/bitstr_raw_enc.bit
echo "Done"
