use ::aloecrypt::KeyPEM;
use ::aloecrypt::aloecrypt::AloecryptPackage;
use ::aloecrypt::keyfile::{Keyfile, key_unpack};
use serde::Deserialize;
use std::fs;

#[derive(Deserialize, Debug, PartialEq)]
struct ExpectedPayload {
    mission: String,
    status: String,
    magic_number: i32,
}

#[derive(Deserialize)]
struct TestMetadata {
    alice_pub: String,
    bob_pub: String,
    nonce: String,
    app_id: String,
}

#[test]
fn test_python_to_rust_interop() {
    let base_dir = "./.test_vectors"; // Path to where Python saved the files
    let password = b"interop_password";

    // 1. Load Metadata
    let meta_str = fs::read_to_string(format!("{}/metadata.json", base_dir))
        .expect("Run the python script first to generate metadata.json");
    let meta: TestMetadata = serde_json::from_str(&meta_str).unwrap();

    // 2. Load Alice and Bob's keys from Python's PEM files
    let alice_pem = fs::read_to_string(format!("{}/alice.pem", base_dir)).unwrap();
    let bob_pem = fs::read_to_string(format!("{}/bob.pem", base_dir)).unwrap();

    let alice_kf = Keyfile::loads(&alice_pem).unwrap();
    let bob_kf = Keyfile::loads(&bob_pem).unwrap();

    let _alice_kp = key_unpack(&alice_kf, password).expect("Failed to unlock Alice's key");
    let bob_kp = key_unpack(&bob_kf, password).expect("Failed to unlock Bob's key");

    // Assert that the public keys parsed by Rust match Python's hex output
    assert_eq!(hex::encode(bob_kp.public_key), meta.bob_pub);

    // 3. Load the binary package created by Python
    let pkg_bytes = fs::read(format!("{}/python_package.alo", base_dir)).unwrap();
    let package = AloecryptPackage::from_bytes(&pkg_bytes).expect("Failed to parse package bytes");

    // 4. Verify Header Cryptography
    assert_eq!(package.hdr.app_id_16, meta.app_id.as_bytes());
    assert_eq!(package.hdr.nonce_16, meta.nonce.as_bytes());
    assert_eq!(hex::encode(package.hdr.signer_key), meta.alice_pub);

    // VERIFY ED25519 SIGNATURE
    assert!(
        package.verify_hdr(),
        "Ed25519 Signature Verification Failed!"
    );

    // 5. Decrypt and Unpack (ChaCha20 -> LZ4 -> MsgPack)
    let unpacked_payload: ExpectedPayload = package
        .unpack(&bob_kp)
        .expect("Decryption or Decompression failed");

    // 6. Verify Content matches perfectly
    assert_eq!(unpacked_payload.mission, "interop");
    assert_eq!(unpacked_payload.status, "success");
    assert_eq!(unpacked_payload.magic_number, 42);
}
