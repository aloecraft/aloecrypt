use aloecrypt::kem::{KyberFullKEM, KyberPublicKEM, XKyberFullKEM};
use aloecrypt::signatory::{DilithiumSigner, DilithiumVerifier, XDilithiumSigner};

use aloecrypt::session::builder::{
    CounterPartyCHALLENGE, CounterPartySECRET, FullCIPHER, PartyCHALLENGE, PartyCIPHER, PartyINTRO,
    PartyRESPONSE, SessionBuilder,
};
use aloecrypt::session::message::{MsgACK, MsgHELLO, MsgSYN, MsgSYNACK, MsgWELCOME};
use aloecrypt::session::message::{MsgGOODBYE, MsgRETRY, MsgRESYN};
use aloecrypt::session::party::{XParty, XCounterParty};
use aloecrypt::session::session::XAloecryptSession;
use aloecrypt::session::{AloecryptSession, CounterParty, Party};
use aloecrypt::session::builder::FromSecretsInput;

use aloecrypt::traits::AloecryptEmpty;
use regex::Regex;
use serde_reflection::{Registry, Samples, Tracer, TracerConfig};
use std::io::Write;

fn generate_signer() {
    let signer = DilithiumSigner::empty();
    let verifier = DilithiumVerifier::empty();
    let xsigner = XDilithiumSigner::empty();
    let mut tracer = Tracer::new(TracerConfig::default());
    let mut samples = Samples::new();
    tracer.trace_value(&mut samples, &signer).unwrap();
    tracer.trace_value(&mut samples, &verifier).unwrap();
    tracer.trace_value(&mut samples, &xsigner).unwrap();
    let registry = tracer.registry().unwrap();
    let mut source = Vec::new();
    let config = serde_generate::CodeGeneratorConfig::new("aloecrypt".to_string())
        .with_encodings(vec![serde_generate::Encoding::Bincode]);
    let generator = serde_generate::python3::CodeGenerator::new(&config);
    generator.output(&mut source, &registry).unwrap();
    let output = String::from_utf8_lossy(&source).to_string();
    let re = Regex::new(r"typing\.Tuple\[(?:st\.uint8(?:,\s*)?)+\]").unwrap();
    let cleaned = re.replace_all(&output, "bytes");

    let re = Regex::new(r"st\.uint32").unwrap();
    let cleaned = re.replace_all(&output, "int");

    println!("{}", cleaned);
}

fn generate_message() {
    let msg_ack = MsgACK::empty();
    let msg_hello = MsgHELLO::empty();
    let msg_syn = MsgSYN::empty();
    let msg_synack = MsgSYNACK::empty();
    let msg_welcome = MsgWELCOME::empty();
    let mut tracer = Tracer::new(TracerConfig::default());
    let mut samples = Samples::new();
    tracer.trace_value(&mut samples, &msg_ack).unwrap();
    tracer.trace_value(&mut samples, &msg_hello).unwrap();
    tracer.trace_value(&mut samples, &msg_syn).unwrap();
    tracer.trace_value(&mut samples, &msg_synack).unwrap();
    tracer.trace_value(&mut samples, &msg_welcome).unwrap();
    let registry = tracer.registry().unwrap();
    let mut source = Vec::new();
    let config = serde_generate::CodeGeneratorConfig::new("aloecrypt".to_string())
        .with_encodings(vec![serde_generate::Encoding::Bincode]);
    let generator = serde_generate::python3::CodeGenerator::new(&config);
    generator.output(&mut source, &registry).unwrap();
    let output = String::from_utf8_lossy(&source).to_string();
    let re = Regex::new(r"typing\.Tuple\[(?:st\.uint8(?:,\s*)?)+\]").unwrap();
    let cleaned = re.replace_all(&output, "bytes");
    println!("{}", cleaned);
}

fn generate_session() {
    let party = Party::empty();
    let counter_party = CounterParty::empty();
    let aloecrypt_session = AloecryptSession::empty();
    let mut tracer = Tracer::new(TracerConfig::default());
    let mut samples = Samples::new();
    tracer.trace_value(&mut samples, &party).unwrap();
    tracer.trace_value(&mut samples, &counter_party).unwrap();
    tracer
        .trace_value(&mut samples, &aloecrypt_session)
        .unwrap();
    let registry = tracer.registry().unwrap();
    let mut source = Vec::new();
    let config = serde_generate::CodeGeneratorConfig::new("aloecrypt".to_string())
        .with_encodings(vec![serde_generate::Encoding::Bincode]);
    let generator = serde_generate::python3::CodeGenerator::new(&config);
    generator.output(&mut source, &registry).unwrap();
    let output = String::from_utf8_lossy(&source).to_string();
    let re = Regex::new(r"typing\.Tuple\[(?:st\.uint8(?:,\s*)?)+\]").unwrap();
    let cleaned = re.replace_all(&output, "bytes");
    println!("{}", cleaned);
}

fn generate_kem() {
    let full_kem = KyberFullKEM::empty();
    let public_kem = KyberPublicKEM::empty();
    let xkem = XKyberFullKEM::empty();
    let mut tracer = Tracer::new(TracerConfig::default());
    let mut samples = Samples::new();
    tracer.trace_value(&mut samples, &full_kem).unwrap();
    tracer.trace_value(&mut samples, &public_kem).unwrap();
    tracer.trace_value(&mut samples, &xkem).unwrap();
    let registry = tracer.registry().unwrap();
    let mut source = Vec::new();
    let config = serde_generate::CodeGeneratorConfig::new("aloecrypt".to_string())
        .with_encodings(vec![serde_generate::Encoding::Bincode]);
    let generator = serde_generate::python3::CodeGenerator::new(&config);
    generator.output(&mut source, &registry).unwrap();
    let output = String::from_utf8_lossy(&source).to_string();
    let re = Regex::new(r"typing\.Tuple\[(?:st\.uint8(?:,\s*)?)+\]").unwrap();
    let cleaned = re.replace_all(&output, "bytes");
    println!("{}", cleaned);
}

fn generate_builder() {
    let session_builder = SessionBuilder::empty();
    let full_cipher = FullCIPHER::empty();
    let party_challenge = PartyCHALLENGE::empty();
    let party_cipher = PartyCIPHER::empty();
    let party_challenge2 = CounterPartyCHALLENGE::empty();
    let party_intro = PartyINTRO::empty();
    let party_response = PartyRESPONSE::empty();
    let party_secret = CounterPartySECRET::empty();
    let mut tracer = Tracer::new(TracerConfig::default());
    let mut samples = Samples::new();
    tracer.trace_value(&mut samples, &session_builder).unwrap();
    tracer.trace_value(&mut samples, &full_cipher).unwrap();
    tracer.trace_value(&mut samples, &party_challenge).unwrap();
    tracer.trace_value(&mut samples, &party_cipher).unwrap();
    tracer.trace_value(&mut samples, &party_challenge2).unwrap();
    tracer.trace_value(&mut samples, &party_intro).unwrap();
    tracer.trace_value(&mut samples, &party_response).unwrap();
    tracer.trace_value(&mut samples, &party_secret).unwrap();
    let registry = tracer.registry().unwrap();
    let mut source = Vec::new();
    let config = serde_generate::CodeGeneratorConfig::new("aloecrypt".to_string())
        .with_encodings(vec![serde_generate::Encoding::Bincode]);
    let generator = serde_generate::python3::CodeGenerator::new(&config);
    generator.output(&mut source, &registry).unwrap();
    let output = String::from_utf8_lossy(&source).to_string();
    let re = Regex::new(r"typing\.Tuple\[(?:st\.uint8(?:,\s*)?)+\]").unwrap();
    let cleaned = re.replace_all(&output, "bytes");
    let re = Regex::new(r"st\.uint32").unwrap();
    let cleaned = re.replace_all(&output, "int");
    println!("{}", cleaned);
}
fn generate_traits_py() {
    // (prefix, python_class, python_import, traits)
    // Each trait maps to a fixed set of methods with known signatures.
    let bindings: &[(&str, &str, &str, &[&str])] = &[
        ("dilithium_signer", "DilithiumSigner", "aloecrypt.signatory", &["addressable", "signable", "hashable", "signer", "verifier", "password_pem", "empty"]),
        ("dilithium_verifier", "DilithiumVerifier", "aloecrypt.signatory", &["addressable", "signable", "hashable", "verifier", "pem", "empty"]),
        ("x_dilithium_signer", "XDilithiumSigner", "aloecrypt.signatory", &["addressable", "pem", "empty"]),
        ("kyber_kem", "KyberFullKEM", "aloecrypt.kem", &["addressable", "signable", "hashable", "encapsulator", "decapsulator", "password_pem", "empty"]),
        ("kyber_public_kem", "KyberPublicKEM", "aloecrypt.kem", &["addressable", "signable", "hashable", "encapsulator", "pem", "empty"]),
        ("x_kyber_kem", "XKyberFullKEM", "aloecrypt.kem", &["addressable", "pem", "empty"]),
        ("session", "AloecryptSession", "aloecrypt.session", &["addressable", "hashable", "password_pem", "empty"]),
        ("x_session", "XAloecryptSession", "aloecrypt.session", &["pem", "empty"]),
        ("session_builder", "SessionBuilder", "aloecrypt.session.builder", &["addressable", "hashable", "empty"]),
        ("party_intro", "PartyINTRO", "aloecrypt.session.builder", &["hashable", "empty"]),
        ("party_cipher", "PartyCIPHER", "aloecrypt.session.builder", &["hashable", "empty"]),
        ("party_challenge", "PartyCHALLENGE", "aloecrypt.session.builder", &["hashable", "empty"]),
        ("party_response", "PartyRESPONSE", "aloecrypt.session.builder", &["hashable", "empty"]),
        ("counter_party_secret", "CounterPartySECRET", "aloecrypt.session.builder", &["hashable", "empty"]),
        ("counter_party_challenge", "CounterPartyCHALLENGE", "aloecrypt.session.builder", &["hashable", "empty"]),
        ("from_secrets_input", "FromSecretsInput", "aloecrypt.session.builder", &["hashable", "empty"]),
        ("party", "Party", "aloecrypt.session", &["addressable", "hashable", "empty"]),
        ("counter_party", "CounterParty", "aloecrypt.session", &["addressable", "hashable", "empty"]),
        ("msg_hello", "MsgHELLO", "aloecrypt.session.message", &["hashable", "pem", "empty"]),
        ("msg_syn", "MsgSYN", "aloecrypt.session.message", &["hashable", "pem", "empty"]),
        ("msg_ack", "MsgACK", "aloecrypt.session.message", &["hashable", "pem", "empty"]),
        ("msg_synack", "MsgSYNACK", "aloecrypt.session.message", &["hashable", "pem", "empty"]),
        ("msg_welcome", "MsgWELCOME", "aloecrypt.session.message", &["hashable", "pem", "empty"]),
        ("msg_goodbye", "MsgGOODBYE", "aloecrypt.session.message", &["pem", "empty"]),
        ("msg_retry", "MsgRETRY", "aloecrypt.session.message", &["pem", "empty"]),
        ("msg_resyn", "MsgRESYN", "aloecrypt.session.message", &["pem", "empty"]),
    ];

    let mut out = String::new();
    out.push_str("# Auto-generated from aloecrypt traits — do not edit\n");
    out.push_str("from aloecrypt._plugin import _pack, _unpack, plugin\n\n");

    // Collect imports by module
    let mut imports: std::collections::BTreeMap<&str, Vec<&str>> = std::collections::BTreeMap::new();
    for (_, class, module, _) in bindings {
        imports.entry(module).or_default().push(class);
    }
    for (module, classes) in &imports {
        let mut unique: Vec<&str> = classes.clone();
        unique.sort();
        unique.dedup();
        out.push_str(&format!("from {} import {}\n", module, unique.join(", ")));
    }
    out.push_str("\n");

    for (prefix, class, _, traits) in bindings {
        out.push_str(&format!("\n# ── {} ──\n", class));

        for tr in *traits {
            match *tr {
                "addressable" => {
                    out.push_str(&format!(
r#"
{cls}.address = property(lambda self: plugin.call("{pfx}_address", _pack(self)))
{cls}.root_address = property(lambda self: plugin.call("{pfx}_root_address", _pack(self)))
{cls}.is_root = lambda self: bool(plugin.call("{pfx}_is_root", _pack(self))[0])
{cls}.generation = lambda self: int.from_bytes(plugin.call("{pfx}_generation", _pack(self)), "little")
"#, cls=class, pfx=prefix));
                }
                "signable" => {
                    out.push_str(&format!(
r#"
{cls}.signing_material = lambda self: plugin.call("{pfx}_signing_material", _pack(self))
{cls}.signature_bytes = lambda self: plugin.call("{pfx}_signature", _pack(self))
{cls}.signed_by = lambda self: plugin.call("{pfx}_signed_by", _pack(self))
"#, cls=class, pfx=prefix));
                }
                "hashable" => {
                    out.push_str(&format!(
r#"
{cls}.hash = lambda self: plugin.call("{pfx}_hash", _pack(self))
"#, cls=class, pfx=prefix));
                }
                "signer" => {
                    out.push_str(&format!(
r#"
{cls}.sign = lambda self, message: plugin.call("{pfx}_sign", _pack(self, message))
{cls}.sign_hex = lambda self, message: self.sign(message).hex()
{cls}.may_sign = lambda self: bool(plugin.call("{pfx}_may_sign", _pack(self))[0])
"#, cls=class, pfx=prefix));
                }
                "verifier" => {
                    out.push_str(&format!(
r#"
{cls}.verify = lambda self, material, sig_bytes: bool(plugin.call("{pfx}_verify", _pack(self, material, sig_bytes))[0])
{cls}.may_verify = lambda self: bool(plugin.call("{pfx}_may_verify", _pack(self))[0])
"#, cls=class, pfx=prefix));
                }
                "pem" => {
                    out.push_str(&format!(
r#"
{cls}.to_pem = lambda self: plugin.call("{pfx}_to_pem", _pack(self)).decode()
{cls}.from_pem = classmethod(lambda cls, pem: cls(**_unpack(plugin.call("{pfx}_from_pem", pem.encode()))))
"#, cls=class, pfx=prefix));
                }
                "password_pem" => {
                    out.push_str(&format!(
r#"
{cls}.to_x_pem = lambda self, password, salt: plugin.call("{pfx}_to_x_pem", _pack(self, password, salt)).decode()
{cls}.from_x_pem = classmethod(lambda cls, pem, password, salt: cls(**_unpack(plugin.call("{pfx}_from_x_pem", _pack(pem, password, salt)))))
{cls}.x_pub_loads = classmethod(lambda cls, pem: _unpack(plugin.call("{pfx}_x_pub_loads", pem.encode())))
"#, cls=class, pfx=prefix));
                }
                "encapsulator" => {
                    out.push_str(&format!(
r#"
def _{pfx}_encapsulate(self):
    result = _unpack(plugin.call("{pfx}_encapsulate", _pack(self)))
    return bytes(result[0]), bytes(result[1])
{cls}.encapsulate = _{pfx}_encapsulate
"#, cls=class, pfx=prefix));
                }
                "decapsulator" => {
                    out.push_str(&format!(
r#"
{cls}.decapsulate = lambda self, ciphertext: plugin.call("{pfx}_decapsulate", _pack(self, list(ciphertext)))
"#, cls=class, pfx=prefix));
                }
                "empty" => {
                    out.push_str(&format!(
r#"
{cls}.to_bytes = lambda self: plugin.call("{pfx}_to_bytes", _pack(self))
{cls}.from_bytes = classmethod(lambda cls, data: cls(**_unpack(plugin.call("{pfx}_from_bytes", bytes(data)))))
{cls}.byte_sz = classmethod(lambda cls: int.from_bytes(plugin.call("{pfx}_byte_sz", b""), "little"))
"#, cls=class, pfx=prefix));
                }
                _ => {}
            }
        }
    }

    std::fs::write("python/traits.py", &out).unwrap();
    println!("wrote python/traits.py");
}

pub fn main() {
    generate_traits_py();
    let mut tracer = Tracer::new(TracerConfig::default());
    let mut samples = Samples::new();

    // trace everything once
    tracer
        .trace_value(&mut samples, &DilithiumSigner::empty())
        .unwrap();
    tracer
        .trace_value(&mut samples, &DilithiumVerifier::empty())
        .unwrap();
    tracer
        .trace_value(&mut samples, &XDilithiumSigner::empty())
        .unwrap();
    tracer
        .trace_value(&mut samples, &KyberFullKEM::empty())
        .unwrap();
    tracer
        .trace_value(&mut samples, &KyberPublicKEM::empty())
        .unwrap();
    tracer
        .trace_value(&mut samples, &XKyberFullKEM::empty())
        .unwrap();
    tracer.trace_value(&mut samples, &MsgACK::empty()).unwrap();
    tracer
        .trace_value(&mut samples, &MsgHELLO::empty())
        .unwrap();
    tracer.trace_value(&mut samples, &MsgSYN::empty()).unwrap();
    tracer
        .trace_value(&mut samples, &MsgSYNACK::empty())
        .unwrap();
    tracer
        .trace_value(&mut samples, &MsgWELCOME::empty())
        .unwrap();
    tracer.trace_value(&mut samples, &Party::empty()).unwrap();
    tracer
        .trace_value(&mut samples, &CounterParty::empty())
        .unwrap();
    tracer
        .trace_value(&mut samples, &AloecryptSession::empty())
        .unwrap();
    tracer
        .trace_value(&mut samples, &SessionBuilder::empty())
        .unwrap();
    tracer
        .trace_value(&mut samples, &FullCIPHER::empty())
        .unwrap();
    tracer
        .trace_value(&mut samples, &PartyCHALLENGE::empty())
        .unwrap();
    tracer
        .trace_value(&mut samples, &PartyCIPHER::empty())
        .unwrap();
    tracer
        .trace_value(&mut samples, &CounterPartyCHALLENGE::empty())
        .unwrap();
    tracer
        .trace_value(&mut samples, &PartyINTRO::empty())
        .unwrap();
    tracer
        .trace_value(&mut samples, &PartyRESPONSE::empty())
        .unwrap();
    tracer
        .trace_value(&mut samples, &CounterPartySECRET::empty())
        .unwrap();
    tracer
        .trace_value(&mut samples, &FromSecretsInput::empty())
        .unwrap();
    tracer
        .trace_value(&mut samples, &XParty::empty())
        .unwrap();
    tracer
        .trace_value(&mut samples, &XCounterParty::empty())
        .unwrap();
    tracer
        .trace_value(&mut samples, &XAloecryptSession::empty())
        .unwrap();
    tracer
        .trace_value(&mut samples, &MsgGOODBYE::empty())
        .unwrap();
    tracer
        .trace_value(&mut samples, &MsgRETRY::empty())
        .unwrap();
    tracer
        .trace_value(&mut samples, &MsgRESYN::empty())
        .unwrap();

    let registry = tracer.registry().unwrap();

    // define which type names belong in which file
    let files: &[(&str, &[&str])] = &[
        (
            "python/signatory.py",
            &["DilithiumSigner", "DilithiumVerifier", "XDilithiumSigner"],
        ),
        (
            "python/kem.py",
            &["KyberFullKEM", "KyberPublicKEM", "XKyberFullKEM"],
        ),
        (
            "python/session/message.py",
            &["MsgACK", "MsgHELLO", "MsgSYN", "MsgSYNACK", "MsgWELCOME", "MsgGOODBYE", "MsgRETRY", "MsgRESYN"],
        ),
        (
            "python/session/__init__.py",
            &["AloecryptSession", "XAloecryptSession"],
        ),
        (
            "python/session/party.py",
            &["Party", "CounterParty", "XParty", "XCounterParty"],
        ),
        (
            "python/session/builder.py",
            &[
                "SessionBuilder",
                "FullCIPHER",
                "PartyCIPHER",
                "PartyCHALLENGE",
                "PartyChallenge",
                "PartyINTRO",
                "PartyRESPONSE",
                "CounterPartySECRET",
                "CounterPartyCHALLENGE",
                "PartySecret",
                "FromSecretsInput",
            ],
        ),
    ];

    let re_tuple = Regex::new(r"typing\.Tuple\[(?:st\.uint8(?:,\s*)?)+\]").unwrap();
    let re_uint32 = Regex::new(r"st\.uint32").unwrap();
    let re_uint64 = Regex::new(r"st\.uint64").unwrap();
    let re_serde_import = Regex::new(r"import serde_types as st").unwrap();
    let re_class = Regex::new(r"class (\w+):").unwrap();
    let config = serde_generate::CodeGeneratorConfig::new("aloecrypt".to_string());

    for (filename, type_names) in files {
        // build a filtered registry with only the types for this file
        let filtered: Registry = registry
            .iter()
            .filter(|(name, _)| type_names.contains(&name.as_str()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        let mut source = Vec::new();
        let generator = serde_generate::python3::CodeGenerator::new(&config);
        generator.output(&mut source, &filtered).unwrap();

        let output = String::from_utf8_lossy(&source).to_string();
        let cleaned = re_tuple.replace_all(&output, "bytes").to_string();
        let cleaned = re_uint32.replace_all(&cleaned, "int").to_string();
        let cleaned = re_uint64.replace_all(&cleaned, "int").to_string();
        let cleaned = re_serde_import.replace_all(&cleaned, "").to_string();
        let cleaned = re_class.replace_all(&cleaned, "class $1(_PluginModel):").to_string();
        let cleaned = format!("from aloecrypt._plugin import _PluginModel\n{}", cleaned);
        let cleaned = cleaned.replace("@dataclass(frozen=True)\n", "");
        let cleaned = cleaned.replace("from dataclasses import dataclass\n", "");
        let cleaned = cleaned.replace("import typing\n", "");
        let cleaned = cleaned.replace("# pyre-strict\n", "");
        let cleaned = re_class.replace_all(&cleaned, "class $1(_PluginModel):").to_string();

        std::fs::create_dir_all(std::path::Path::new(filename).parent().unwrap()).unwrap();
        std::fs::write(filename, cleaned).unwrap();
        println!("wrote {}", filename);
    }
    println!("Registry keys: {:?}", registry.keys().collect::<Vec<_>>());
}
