## Remote Attestation Example

Remote Attestation Example written in Python. Establishes connection between a Server and Client using SSL sockets.

Useful for killing the Python process:

```
kill -9 $(ps -A | grep python | awk '{print $1}')
```

### ```xclbinutil``` commands

Extract Bitstream from ```.xclbinutil``` file

```
xclbinutil --dump-section BITSTREAM:RAW:bitstream.bit --input myfile.xclbin
```

Add signature to ```.xclbinutil``` file

```
xclbinutil -i lstm.xclbin --add-signature test --output lstm_signed.xclbin
```