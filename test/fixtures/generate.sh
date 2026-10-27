#!/usr/bin/env bash
set -euo pipefail

fixture_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
work_dir="$(mktemp -d)"
output_dir="$work_dir/output"
trap 'rm -rf -- "$work_dir"' EXIT
mkdir -p "$output_dir/crl" "$output_dir/ocsp"

cat > "$work_dir/openssl.cnf" <<'EOF'
[ca]
default_ca = intermediate_ca

[test_policy]
commonName = supplied

[intermediate]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
crlDistributionPoints = URI:http://crl.example.test/root.crl
authorityInfoAccess = OCSP;URI:http://ocsp.example.test/root

[leaf]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
subjectAltName = URI:https://client.example.org/app
crlDistributionPoints = URI:http://crl.example.test/intermediate.crl
authorityInfoAccess = OCSP;URI:http://ocsp.example.test/intermediate

[crl_extensions]
authorityKeyIdentifier = keyid:always
EOF

for ca in root intermediate; do
  mkdir -p "$work_dir/$ca/newcerts"
  touch "$work_dir/$ca/index.txt"
  printf '1000\n' > "$work_dir/$ca/serial"
  printf '1000\n' > "$work_dir/$ca/crlnumber"

  cat >> "$work_dir/openssl.cnf" <<EOF

[${ca}_ca]
database = $work_dir/$ca/index.txt
new_certs_dir = $work_dir/$ca/newcerts
serial = $work_dir/$ca/serial
crlnumber = $work_dir/$ca/crlnumber
certificate = $output_dir/$ca.pem
private_key = $work_dir/$ca.key
default_md = sha256
default_days = 365
default_crl_days = 30
policy = test_policy
crl_extensions = crl_extensions
unique_subject = no
EOF
done

openssl req -x509 -newkey rsa:2048 -nodes -sha256 \
  -keyout "$work_dir/root.key" -out "$output_dir/root.pem" \
  -days 3650 -subj '/CN=x509-trust Test Root' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:1' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign'

openssl req -new -newkey rsa:2048 -nodes \
  -keyout "$work_dir/intermediate.key" -out "$work_dir/intermediate.csr" \
  -subj '/CN=x509-trust Test Intermediate'

openssl ca -batch -notext -config "$work_dir/openssl.cnf" -name root_ca \
  -in "$work_dir/intermediate.csr" -out "$output_dir/intermediate.pem" \
  -days 1825 -extensions intermediate

for client in leaf revoked-leaf; do
  openssl req -new -newkey rsa:2048 -nodes \
    -keyout "$work_dir/$client.key" -out "$work_dir/$client.csr" \
    -subj "/CN=x509-trust Test $client"

  openssl ca -batch -notext -config "$work_dir/openssl.cnf" \
    -name intermediate_ca -in "$work_dir/$client.csr" \
    -out "$output_dir/$client.pem" -extensions leaf
done

openssl req -x509 -newkey rsa:2048 -nodes -sha256 \
  -keyout "$work_dir/untrusted-root.key" \
  -out "$output_dir/untrusted-root.pem" \
  -days 3650 -subj '/CN=x509-trust Unrelated Test Root' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign'

openssl ca -gencrl -config "$work_dir/openssl.cnf" -name root_ca \
  -out "$output_dir/crl/root.crl.pem"
openssl ca -gencrl -config "$work_dir/openssl.cnf" -name intermediate_ca \
  -out "$output_dir/crl/intermediate-clean.crl.pem"

openssl ca -config "$work_dir/openssl.cnf" -name intermediate_ca \
  -revoke "$output_dir/revoked-leaf.pem" -crl_reason keyCompromise
openssl ca -gencrl -config "$work_dir/openssl.cnf" -name intermediate_ca \
  -out "$output_dir/crl/intermediate-revoked.crl.pem"
openssl ca -gencrl -config "$work_dir/openssl.cnf" -name intermediate_ca \
  -crl_lastupdate 20200101000000Z -crl_nextupdate 20200102000000Z \
  -out "$output_dir/crl/intermediate-expired.crl.pem"

function generate_ocsp_response() {
  local name="$1" issuer="$2" subject="$3" index="$4"

  # Recorded responses omit nonces so they can be reused in offline tests.
  openssl ocsp -issuer "$output_dir/$issuer.pem" \
    -cert "$output_dir/$subject.pem" -no_nonce \
    -reqout "$work_dir/request.der"
  openssl ocsp -index "$index" -CA "$output_dir/$issuer.pem" \
    -rsigner "$output_dir/$issuer.pem" -rkey "$work_dir/$issuer.key" \
    -reqin "$work_dir/request.der" -rmd sha256 -ndays 30 \
    -respout "$output_dir/ocsp/$name.der"
}

generate_ocsp_response good intermediate leaf "$work_dir/intermediate/index.txt"
generate_ocsp_response revoked intermediate revoked-leaf "$work_dir/intermediate/index.txt"
touch "$work_dir/unknown-index.txt"
generate_ocsp_response unknown intermediate leaf "$work_dir/unknown-index.txt"
generate_ocsp_response intermediate-good root intermediate "$work_dir/root/index.txt"

date -u '+%Y-%m-%dT%H:%M:%SZ' > "$output_dir/validation-time.txt"
cp -R "$output_dir/." "$fixture_dir/"
