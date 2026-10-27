#!/usr/bin/env bash
set -euo pipefail

fixture_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
key_dir="$(mktemp -d)"
trap 'rm -rf -- "$key_dir"' EXIT

openssl req -x509 -newkey rsa:2048 -nodes -sha256 \
  -keyout "$key_dir/root.key" -out "$fixture_dir/root.pem" \
  -days 3650 -subj '/CN=x509-trust Test Root' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:1' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign'

openssl req -new -newkey rsa:2048 -nodes \
  -keyout "$key_dir/intermediate.key" -out "$key_dir/intermediate.csr" \
  -subj '/CN=x509-trust Test Intermediate'

cat > "$key_dir/intermediate.ext" <<'EOF'
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF

openssl x509 -req -sha256 -in "$key_dir/intermediate.csr" \
  -CA "$fixture_dir/root.pem" -CAkey "$key_dir/root.key" -set_serial 2 \
  -out "$fixture_dir/intermediate.pem" -days 1825 \
  -extfile "$key_dir/intermediate.ext"

openssl req -new -newkey rsa:2048 -nodes \
  -keyout "$key_dir/leaf.key" -out "$key_dir/leaf.csr" \
  -subj '/CN=x509-trust Test Client'

cat > "$key_dir/leaf.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
subjectAltName=URI:https://client.example.org/app
EOF

openssl x509 -req -sha256 -in "$key_dir/leaf.csr" \
  -CA "$fixture_dir/intermediate.pem" -CAkey "$key_dir/intermediate.key" \
  -set_serial 3 -out "$fixture_dir/leaf.pem" -days 365 \
  -extfile "$key_dir/leaf.ext"

openssl req -x509 -newkey rsa:2048 -nodes -sha256 \
  -keyout "$key_dir/untrusted-root.key" \
  -out "$fixture_dir/untrusted-root.pem" \
  -days 3650 -subj '/CN=x509-trust Unrelated Test Root' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign'
