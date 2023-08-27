#!/bin/bash
ATT=3f9855594d691b35095c35e5f7d64d37ad314d51368678582c719c34aa072afa.json
# URL for the trust bundle
URL="https://fulcio.sigstore.dev/api/v2/trustBundle"
# URL for the TSA Cert
TSA_CERT=https://freetsa.org/files/cacert.pem



# Fetch the trust bundle
response=$(curl -s "$URL")

# Extract and save the intermediate certificate
echo "$response" | jq -r '.chains[0].certificates[0]' > sigstore-int.crt

# Extract and save the root certificate
echo "$response" | jq -r '.chains[0].certificates[1]' > sigstore-root.crt

echo "Certificates have been saved to sigstore-int.crt and sigstore-root.crt"

policy-tool create -d $ATT -r sigstore-root.crt -i sigstore-int.crt -t $TSA_CERT > policy.json

#sign the policy
openssl genpkey -algorithm ed25519 -outform PEM -out policy-key.pem
openssl pkey -in policy-key.pem -pubout > policy.pub

witness sign -k policy-key.pem -o policy-signed.json -f policy.json

witness verify -k policy.pub -a 3f9855594d691b35095c35e5f7d64d37ad314d51368678582c719c34aa072afa.json -p policy-signed.json -f galadriel_Linux_x86_64.tar.gz.spdx.sbom 