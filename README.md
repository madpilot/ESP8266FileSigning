# Test code for verifying an ESP8266 binary for use with OTA

Using parts of the AxTLS library, I'm trying to get the ESP8266 to validate an binary sent via OTA.

## Setup

Generate a CA
```bash
openssl req -new -x509 -days 3650 -extensions v3_ca -keyout cert/ca.key.pem -out cert/ca.crt.pem
openssl x509 -outform der -in cert/ca.crt.pem -out cert/ca.crt.der.
xxd -i cert/ca.crt.der
```

Generate a developer certificate
```bash
openssl genrsa -out cert/developer.key.pem 2048
openssl req -out cert/developer.csr.pem -key cert/developer.key.pem -new
```

Sign the developer certificate
```bash
openssl x509 -req -in cert/developer.csr.pem -CA cert/ca.crt.pem -CAkey cert/ca.key.pem -CAcreateserial -out cert/developer.crt.pem -days 365
openssl x509 -outform der -in cert/developer.crt.pem -out cert/developer.crt.der.
cp cert/developer.crt.der /data/developer.crt.der
```

Sign the binary

```bash
openssl dgst -sha256 -sign cert/developer.key.pem -out data/sig256 data/data.txt
```

Upload the files in /data to the ESP8266 flash, recompile and upload the new firmware via Serial.

Open the console, and you should see a successful binary verification if the developer certificate was signed by the CA, and has can be decrypted from the signature and the hash matches the computed hash of the binary
