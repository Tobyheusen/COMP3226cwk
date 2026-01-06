#!/bin/bash
set -e

# Cleanup
rm -f *.key *.crt *.srl *.csr *.p12

# 1. Create CA
openssl genrsa -out ca.key 2048
openssl req -x509 -new -nodes -key ca.key -sha256 -days 1024 -out ca.crt -subj "/CN=MyLocalCA"

# 2. Create Server Cert (Add SAN for 127.0.0.1 and localhost)
openssl genrsa -out server.key 2048
# Create config file for SAN
cat > server.cnf <<EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = localhost

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
IP.1 = 127.0.0.1
DNS.1 = localhost
EOF

openssl req -new -key server.key -out server.csr -config server.cnf
# Sign server cert with extensions
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 500 -sha256 -extensions v3_req -extfile server.cnf

# 3. Create Client Cert
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -subj "/CN=MyMobileClient"
# Sign client cert
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 500 -sha256

# 4. Create PKCS#12 for Browser/Mobile import (Empty password)
openssl pkcs12 -export -out client.p12 -inkey client.key -in client.crt -certfile ca.crt -passout pass:

# Cleanup temp config
rm server.cnf

echo "Certificates generated in certs/"
echo " - ca.crt: Import as Trusted Root CA"
echo " - client.p12: Import into Browser/Mobile (No password)"
