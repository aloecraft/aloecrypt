#!/bin/bash
set -euo pipefail

rm -rf .test
mkdir -p .test
cp ../target/debug/aloecrypt ./.test
cd ./.test

echo "=== Generating keys ==="
./aloecrypt key new -o alice.pem -p passA
./aloecrypt key new -o bob.pem -p passB

echo ""
echo "=== Key info ==="
./aloecrypt key info -k alice.pem -p passA
./aloecrypt key info -k bob.pem -p passB

# Extract public keys for scripting
ALICE_PUB=$(./aloecrypt key pubkey -k alice.pem)
BOB_PUB=$(./aloecrypt key pubkey -k bob.pem)

echo ""
echo "Alice pubkey: ${ALICE_PUB}"
echo "Bob pubkey:   ${BOB_PUB}"

echo ""
echo "=== Pack (Alice -> Bob) ==="
echo '{"status": "classified", "message": "The eagle has landed."}' > secret.json
./aloecrypt pack secret.json "${BOB_PUB}" "[TEST_APP_ID_00]" -k alice.pem -p passA -o package.alo

echo ""
echo "=== Unpack (Bob, verifying Alice) ==="
./aloecrypt unpack package.alo "${ALICE_PUB}" -k bob.pem -p passB -o extracted.json

echo ""
echo "=== Round-trip result ==="
echo "Original:"
cat secret.json
echo "Extracted:"
cat extracted.json

echo ""
if diff -q secret.json extracted.json > /dev/null 2>&1; then
    echo "PASS: Round-trip successful"
else
    echo "FAIL: Files differ"
    exit 1
fi
