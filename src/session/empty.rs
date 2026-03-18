use super::builder::*;
use super::message::*;
use super::party::*;
use super::session::*;
use super::*;
use crate::consts::*;
use crate::kem::KyberFullKEM;
use crate::kem::KyberPublicKEM;
use crate::signatory::DilithiumSigner;
use crate::signatory::DilithiumVerifier;
use crate::traits::*;
use crate::types::*;

use crate::impl_empty_default;
use crate::impl_empty_from_bytes;
use crate::impl_empty_obj;
use crate::impl_empty_size;
use crate::impl_empty_to_bytes;

impl AloecryptEmpty for PartyINTRO {
    impl_empty_obj!(PartyINTRO;
        address:     [u8][ADDRESS_SZ],
        nonce:       [u8][SESSION_NONCE_SZ],
        stable_kem:  {KyberPublicKEM},
        session_kem: {KyberPublicKEM},
        verifier:    {DilithiumVerifier},
    );
    impl_empty_to_bytes!(PartyINTRO;
        address:     [u8][ADDRESS_SZ],
        nonce:       [u8][SESSION_NONCE_SZ],
        stable_kem:  {KyberPublicKEM},
        session_kem: {KyberPublicKEM},
        verifier:    {DilithiumVerifier},
    );
    impl_empty_from_bytes!(PartyINTRO;
        address:     [u8][ADDRESS_SZ],
        nonce:       [u8][SESSION_NONCE_SZ],
        stable_kem:  {KyberPublicKEM},
        session_kem: {KyberPublicKEM},
        verifier:    {DilithiumVerifier},
    );
}

impl AloecryptEmpty for PartyCIPHER {
    impl_empty_obj!(PartyCIPHER;
        stable_cipher:  [u8][CIPHER_SZ],
        session_cipher: [u8][CIPHER_SZ],
        signature:      [u8][SIGNATURE_SZ],
    );
    impl_empty_to_bytes!(PartyCIPHER;
        stable_cipher:  [u8][CIPHER_SZ],
        session_cipher: [u8][CIPHER_SZ],
        signature:      [u8][SIGNATURE_SZ],
    );
    impl_empty_from_bytes!(PartyCIPHER;
        stable_cipher:  [u8][CIPHER_SZ],
        session_cipher: [u8][CIPHER_SZ],
        signature:      [u8][SIGNATURE_SZ],
    );
}

impl AloecryptEmpty for FullCIPHER {
    impl_empty_obj!(FullCIPHER;
        stable_cipher:  [u8][CIPHER_SZ],
        session_cipher: [u8][CIPHER_SZ],
        stable_secret:  [u8][SECRET_SZ],
        session_secret: [u8][SECRET_SZ],
        signature:      [u8][SIGNATURE_SZ],
    );
    impl_empty_to_bytes!(FullCIPHER;
        stable_cipher:  [u8][CIPHER_SZ],
        session_cipher: [u8][CIPHER_SZ],
        stable_secret:  [u8][SECRET_SZ],
        session_secret: [u8][SECRET_SZ],
        signature:      [u8][SIGNATURE_SZ],
    );
    impl_empty_from_bytes!(FullCIPHER;
        stable_cipher:  [u8][CIPHER_SZ],
        session_cipher: [u8][CIPHER_SZ],
        stable_secret:  [u8][SECRET_SZ],
        session_secret: [u8][SECRET_SZ],
        signature:      [u8][SIGNATURE_SZ],
    );
}

impl AloecryptEmpty for CounterPartySECRET {
    impl_empty_obj!(CounterPartySECRET;
        stable_secret:  [u8][SECRET_SZ],
        session_secret: [u8][SECRET_SZ],
        signature:      [u8][SIGNATURE_SZ],
    );
    impl_empty_to_bytes!(CounterPartySECRET;
        stable_secret:  [u8][SECRET_SZ],
        session_secret: [u8][SECRET_SZ],
        signature:      [u8][SIGNATURE_SZ],
    );
    impl_empty_from_bytes!(CounterPartySECRET;
        stable_secret:  [u8][SECRET_SZ],
        session_secret: [u8][SECRET_SZ],
        signature:      [u8][SIGNATURE_SZ],
    );
}

impl AloecryptEmpty for PartyCHALLENGE {
    impl_empty_obj!(PartyCHALLENGE;
        encrypted_challenge: [u8][ENCRYPTED_NONCE_SZ],
        encrypted_check:     [u8][ENCRYPTED_NONCE_SZ],
    );
    impl_empty_to_bytes!(PartyCHALLENGE;
        encrypted_challenge: [u8][ENCRYPTED_NONCE_SZ],
        encrypted_check:     [u8][ENCRYPTED_NONCE_SZ],
    );
    impl_empty_from_bytes!(PartyCHALLENGE;
        encrypted_challenge: [u8][ENCRYPTED_NONCE_SZ],
        encrypted_check:     [u8][ENCRYPTED_NONCE_SZ],
    );
}

impl AloecryptEmpty for PartyRESPONSE {
    impl_empty_obj!(PartyRESPONSE;
        decrypted_challenge: [u8][SESSION_NONCE_SZ],
    );
    impl_empty_to_bytes!(PartyRESPONSE;
        decrypted_challenge: [u8][SESSION_NONCE_SZ],
    );
    impl_empty_from_bytes!(PartyRESPONSE;
        decrypted_challenge: [u8][SESSION_NONCE_SZ],
    );
}

impl AloecryptEmpty for CounterPartyCHALLENGE {
    impl_empty_obj!(CounterPartyCHALLENGE;
        decrypted_challenge: [u8][SESSION_NONCE_SZ],
        decrypted_check:     [u8][SESSION_NONCE_SZ],
    );
    impl_empty_to_bytes!(CounterPartyCHALLENGE;
        decrypted_challenge: [u8][SESSION_NONCE_SZ],
        decrypted_check:     [u8][SESSION_NONCE_SZ],
    );
    impl_empty_from_bytes!(CounterPartyCHALLENGE;
        decrypted_challenge: [u8][SESSION_NONCE_SZ],
        decrypted_check:     [u8][SESSION_NONCE_SZ],
    );
}

impl AloecryptEmpty for FromSecretsInput {
    impl_empty_obj!(FromSecretsInput;
        stable_secret_a:  [u8][SECRET_SZ],
        session_secret_a: [u8][SECRET_SZ],
        signature_a:      [u8][SIGNATURE_SZ],
        nonce_a:          [u8][SESSION_NONCE_SZ],
        address_a:        [u8][ADDRESS_SZ],
        stable_secret_b:  [u8][SECRET_SZ],
        session_secret_b: [u8][SECRET_SZ],
        signature_b:      [u8][SIGNATURE_SZ],
        nonce_b:          [u8][SESSION_NONCE_SZ],
        address_b:        [u8][ADDRESS_SZ],
        session_salt:     [u8][SESSION_SALT_SZ],
    );
    impl_empty_to_bytes!(FromSecretsInput;
        stable_secret_a:  [u8][SECRET_SZ],
        session_secret_a: [u8][SECRET_SZ],
        signature_a:      [u8][SIGNATURE_SZ],
        nonce_a:          [u8][SESSION_NONCE_SZ],
        address_a:        [u8][ADDRESS_SZ],
        stable_secret_b:  [u8][SECRET_SZ],
        session_secret_b: [u8][SECRET_SZ],
        signature_b:      [u8][SIGNATURE_SZ],
        nonce_b:          [u8][SESSION_NONCE_SZ],
        address_b:        [u8][ADDRESS_SZ],
        session_salt:     [u8][SESSION_SALT_SZ],
    );
    impl_empty_from_bytes!(FromSecretsInput;
        stable_secret_a:  [u8][SECRET_SZ],
        session_secret_a: [u8][SECRET_SZ],
        signature_a:      [u8][SIGNATURE_SZ],
        nonce_a:          [u8][SESSION_NONCE_SZ],
        address_a:        [u8][ADDRESS_SZ],
        stable_secret_b:  [u8][SECRET_SZ],
        session_secret_b: [u8][SECRET_SZ],
        signature_b:      [u8][SIGNATURE_SZ],
        nonce_b:          [u8][SESSION_NONCE_SZ],
        address_b:        [u8][ADDRESS_SZ],
        session_salt:     [u8][SESSION_SALT_SZ],
    );
}

impl AloecryptEmpty for SessionBuilder {
    impl_empty_obj!(SessionBuilder;
        delegate_signer:        {DilithiumSigner},
        stable_kem:             {KyberFullKEM},
        session_kem:            {KyberFullKEM},
        nonce:                  [u8][SESSION_NONCE_SZ],
        challenge_nonce:        [u8][SESSION_NONCE_SZ],
        session_salt:           (option [u8][SESSION_SALT_SZ]),
        signature:              (option [u8][SIGNATURE_SZ]),
        cipher:                 (option {FullCIPHER}),
        counterparty_intro:     (option {PartyINTRO}),
        counterparty_cipher:    (option {CounterPartySECRET}),
        counterparty_challenge: (option {CounterPartyCHALLENGE}),
        build_ready:            bool,
    );
    impl_empty_to_bytes!(SessionBuilder;
        delegate_signer:        {DilithiumSigner},
        stable_kem:             {KyberFullKEM},
        session_kem:            {KyberFullKEM},
        nonce:                  [u8][SESSION_NONCE_SZ],
        challenge_nonce:        [u8][SESSION_NONCE_SZ],
        session_salt:           (option [u8][SESSION_SALT_SZ]),
        signature:              (option [u8][SIGNATURE_SZ]),
        cipher:                 (option {FullCIPHER}),
        counterparty_intro:     (option {PartyINTRO}),
        counterparty_cipher:    (option {CounterPartySECRET}),
        counterparty_challenge: (option {CounterPartyCHALLENGE}),
        build_ready:            bool,
    );
    impl_empty_from_bytes!(SessionBuilder;
        delegate_signer:        {DilithiumSigner},
        stable_kem:             {KyberFullKEM},
        session_kem:            {KyberFullKEM},
        nonce:                  [u8][SESSION_NONCE_SZ],
        challenge_nonce:        [u8][SESSION_NONCE_SZ],
        session_salt:           (option [u8][SESSION_SALT_SZ]),
        signature:              (option [u8][SIGNATURE_SZ]),
        cipher:                 (option {FullCIPHER}),
        counterparty_intro:     (option {PartyINTRO}),
        counterparty_cipher:    (option {CounterPartySECRET}),
        counterparty_challenge: (option {CounterPartyCHALLENGE}),
        build_ready:            bool,
    );
}

impl AloecryptEmpty for MsgHELLO {
    impl_empty_obj!(MsgHELLO;
        address: [u8][ADDRESS_SZ],
        intro:   {PartyINTRO},
    );
    impl_empty_to_bytes!(MsgHELLO;
        address: [u8][ADDRESS_SZ],
        intro:   {PartyINTRO},
    );
    impl_empty_from_bytes!(MsgHELLO;
        address: [u8][ADDRESS_SZ],
        intro:   {PartyINTRO},
    );
}

impl AloecryptEmpty for MsgSYN {
    impl_empty_obj!(MsgSYN;
        syn_to:      [u8][SESSION_NONCE_SZ],
        syn_address: [u8][ADDRESS_SZ],
        intro:  {PartyINTRO},
        cipher: {PartyCIPHER},
    );
    impl_empty_to_bytes!(MsgSYN;
        syn_to:      [u8][SESSION_NONCE_SZ],
        syn_address: [u8][ADDRESS_SZ],
        intro:  {PartyINTRO},
        cipher: {PartyCIPHER},
    );
    impl_empty_from_bytes!(MsgSYN;
        syn_to:      [u8][SESSION_NONCE_SZ],
        syn_address: [u8][ADDRESS_SZ],
        intro:  {PartyINTRO},
        cipher: {PartyCIPHER},
    );
}

impl AloecryptEmpty for MsgACK {
    impl_empty_obj!(MsgACK;
        ack_to:      [u8][SESSION_NONCE_SZ],
        ack_address: [u8][ADDRESS_SZ],
        cipher:    {PartyCIPHER},
        challenge: {PartyCHALLENGE},
    );
    impl_empty_to_bytes!(MsgACK;
        ack_to:      [u8][SESSION_NONCE_SZ],
        ack_address: [u8][ADDRESS_SZ],
        cipher:    {PartyCIPHER},
        challenge: {PartyCHALLENGE},
    );
    impl_empty_from_bytes!(MsgACK;
        ack_to:      [u8][SESSION_NONCE_SZ],
        ack_address: [u8][ADDRESS_SZ],
        cipher:    {PartyCIPHER},
        challenge: {PartyCHALLENGE},
    );
}

impl AloecryptEmpty for MsgSYNACK {
    impl_empty_obj!(MsgSYNACK;
        syn_ack:            [u8][SESSION_SALT_SZ],
        challenge:          {PartyCHALLENGE},
        challenge_response: {PartyRESPONSE},
    );
    impl_empty_to_bytes!(MsgSYNACK;
        syn_ack:            [u8][SESSION_SALT_SZ],
        challenge:          {PartyCHALLENGE},
        challenge_response: {PartyRESPONSE},
    );
    impl_empty_from_bytes!(MsgSYNACK;
        syn_ack:            [u8][SESSION_SALT_SZ],
        challenge:          {PartyCHALLENGE},
        challenge_response: {PartyRESPONSE},
    );
}

impl AloecryptEmpty for MsgWELCOME {
    impl_empty_obj!(MsgWELCOME;
        challenge_response: {PartyRESPONSE},
    );
    impl_empty_to_bytes!(MsgWELCOME;
        challenge_response: {PartyRESPONSE},
    );
    impl_empty_from_bytes!(MsgWELCOME;
        challenge_response: {PartyRESPONSE},
    );
}

impl AloecryptEmpty for MsgGOODBYE {
    impl_empty_obj!(MsgGOODBYE;
        session_salt: [u8][SESSION_SALT_SZ],
        address:      [u8][ADDRESS_SZ],
    );
    impl_empty_to_bytes!(MsgGOODBYE;
        session_salt: [u8][SESSION_SALT_SZ],
        address:      [u8][ADDRESS_SZ],
    );
    impl_empty_from_bytes!(MsgGOODBYE;
        session_salt: [u8][SESSION_SALT_SZ],
        address:      [u8][ADDRESS_SZ],
    );
}

impl AloecryptEmpty for MsgRETRY {
    impl_empty_obj!(MsgRETRY;
        address:      [u8][ADDRESS_SZ],
    );
    impl_empty_to_bytes!(MsgRETRY;
        address:      [u8][ADDRESS_SZ],
    );
    impl_empty_from_bytes!(MsgRETRY;
        address:      [u8][ADDRESS_SZ],
    );
}

impl AloecryptEmpty for MsgRESYN {
    impl_empty_obj!(MsgRESYN;
        address:  [u8][ADDRESS_SZ],
        intro:    {PartyINTRO},
    );
    impl_empty_to_bytes!(MsgRESYN;
        address:  [u8][ADDRESS_SZ],
        intro:    {PartyINTRO},
    );
    impl_empty_from_bytes!(MsgRESYN;
        address:  [u8][ADDRESS_SZ],
        intro:    {PartyINTRO},
    );
}

impl AloecryptEmpty for Party {
    impl_empty_obj!(Party;
        nonce:             [u8][SESSION_NONCE_SZ],
        session_signature: [u8][SIGNATURE_SZ],
        delegate_signer:   {DilithiumSigner},
        stable_kem:        {KyberFullKEM},
        session_kem:       {KyberFullKEM},
        stable_secret:     [u8][SECRET_SZ],
        session_secret:    [u8][SECRET_SZ],
    );
    impl_empty_to_bytes!(Party;
        nonce:             [u8][SESSION_NONCE_SZ],
        session_signature: [u8][SIGNATURE_SZ],
        delegate_signer:   {DilithiumSigner},
        stable_kem:        {KyberFullKEM},
        session_kem:       {KyberFullKEM},
        stable_secret:     [u8][SECRET_SZ],
        session_secret:    [u8][SECRET_SZ],
    );
    impl_empty_from_bytes!(Party;
        nonce:             [u8][SESSION_NONCE_SZ],
        session_signature: [u8][SIGNATURE_SZ],
        delegate_signer:   {DilithiumSigner},
        stable_kem:        {KyberFullKEM},
        session_kem:       {KyberFullKEM},
        stable_secret:     [u8][SECRET_SZ],
        session_secret:    [u8][SECRET_SZ],
    );
}

impl AloecryptEmpty for CounterParty {
    impl_empty_obj!(CounterParty;
        address:        [u8][ADDRESS_SZ],
        nonce:          [u8][SESSION_NONCE_SZ],
        signature:      [u8][SIGNATURE_SZ],
        stable_kem:     {KyberPublicKEM},
        session_kem:    {KyberPublicKEM},
        verifier:       {DilithiumVerifier},
        stable_secret:  [u8][SECRET_SZ],
        session_secret: [u8][SECRET_SZ],
    );
    impl_empty_to_bytes!(CounterParty;
        address:        [u8][ADDRESS_SZ],
        nonce:          [u8][SESSION_NONCE_SZ],
        signature:      [u8][SIGNATURE_SZ],
        stable_kem:     {KyberPublicKEM},
        session_kem:    {KyberPublicKEM},
        verifier:       {DilithiumVerifier},
        stable_secret:  [u8][SECRET_SZ],
        session_secret: [u8][SECRET_SZ],
    );
    impl_empty_from_bytes!(CounterParty;
        address:        [u8][ADDRESS_SZ],
        nonce:          [u8][SESSION_NONCE_SZ],
        signature:      [u8][SIGNATURE_SZ],
        stable_kem:     {KyberPublicKEM},
        session_kem:    {KyberPublicKEM},
        verifier:       {DilithiumVerifier},
        stable_secret:  [u8][SECRET_SZ],
        session_secret: [u8][SECRET_SZ],
    );
}

impl AloecryptEmpty for AloecryptSession {
    impl_empty_obj!(AloecryptSession;
        party:         {Party},
        counter_party: {CounterParty},
        session_salt:  [u8][SESSION_SALT_SZ],
    );
    impl_empty_to_bytes!(AloecryptSession;
        party:         {Party},
        counter_party: {CounterParty},
        session_salt:  [u8][SESSION_SALT_SZ],
    );
    impl_empty_from_bytes!(AloecryptSession;
        party:         {Party},
        counter_party: {CounterParty},
        session_salt:  [u8][SESSION_SALT_SZ],
    );
}

impl AloecryptEmpty for XParty {
    impl_empty_obj!(XParty;
        nonce: [u8][SESSION_NONCE_SZ],
        session_signature: [u8][SIGNATURE_SZ],
        x_delegate_signer: {XDilithiumSigner},
        x_stable_kem: {XKyberFullKEM},
        x_session_kem: {XKyberFullKEM},
        x_stable_secret: [u8][SECRET_SZ+ENCRYPTED_TAG_SZ],
        x_session_secret: [u8][SECRET_SZ+ENCRYPTED_TAG_SZ],
    );
    impl_empty_to_bytes!(XParty;
        nonce: [u8][SESSION_NONCE_SZ],
        session_signature: [u8][SIGNATURE_SZ],
        x_delegate_signer: {XDilithiumSigner},
        x_stable_kem: {XKyberFullKEM},
        x_session_kem: {XKyberFullKEM},
        x_stable_secret: [u8][SECRET_SZ+ENCRYPTED_TAG_SZ],
        x_session_secret: [u8][SECRET_SZ+ENCRYPTED_TAG_SZ],
    );
    impl_empty_from_bytes!(XParty;
        nonce: [u8][SESSION_NONCE_SZ],
        session_signature: [u8][SIGNATURE_SZ],
        x_delegate_signer: {XDilithiumSigner},
        x_stable_kem: {XKyberFullKEM},
        x_session_kem: {XKyberFullKEM},
        x_stable_secret: [u8][SECRET_SZ+ENCRYPTED_TAG_SZ],
        x_session_secret: [u8][SECRET_SZ+ENCRYPTED_TAG_SZ],
    );
}

impl AloecryptEmpty for XCounterParty {
    impl_empty_obj!(XCounterParty;
        address: [u8][ADDRESS_SZ],
        nonce: [u8][SESSION_NONCE_SZ],
        signature: [u8][SIGNATURE_SZ],
        stable_kem: {KyberPublicKEM},
        session_kem: {KyberPublicKEM},
        verifier: {DilithiumVerifier},
        x_stable_secret: [u8][SECRET_SZ+ENCRYPTED_TAG_SZ],
        x_session_secret: [u8][SECRET_SZ+ENCRYPTED_TAG_SZ],
        crypt_nonce: [u8][CHACHA_NONCE_SZ]
    );
    impl_empty_to_bytes!(XCounterParty;
        address: [u8][ADDRESS_SZ],
        nonce: [u8][SESSION_NONCE_SZ],
        signature: [u8][SIGNATURE_SZ],
        stable_kem: {KyberPublicKEM},
        session_kem: {KyberPublicKEM},
        verifier: {DilithiumVerifier},
        x_stable_secret: [u8][SECRET_SZ+ENCRYPTED_TAG_SZ],
        x_session_secret: [u8][SECRET_SZ+ENCRYPTED_TAG_SZ],
        crypt_nonce: [u8][CHACHA_NONCE_SZ]
    );
    impl_empty_from_bytes!(XCounterParty;
        address: [u8][ADDRESS_SZ],
        nonce: [u8][SESSION_NONCE_SZ],
        signature: [u8][SIGNATURE_SZ],
        stable_kem: {KyberPublicKEM},
        session_kem: {KyberPublicKEM},
        verifier: {DilithiumVerifier},
        x_stable_secret: [u8][SECRET_SZ+ENCRYPTED_TAG_SZ],
        x_session_secret: [u8][SECRET_SZ+ENCRYPTED_TAG_SZ],
        crypt_nonce: [u8][CHACHA_NONCE_SZ]
    );
}

impl AloecryptEmpty for XAloecryptSession {
    impl_empty_obj!(XAloecryptSession;
        x_party:         {XParty},
        x_counter_party: {XCounterParty},
        x_session_salt:  [u8][SESSION_SALT_SZ + ENCRYPTED_TAG_SZ],
        un_hash:         [u8][HASH_SZ],
        priv_hash:       [u8][HASH_SZ],
    );
    impl_empty_to_bytes!(XAloecryptSession;
        x_party:         {XParty},
        x_counter_party: {XCounterParty},
        x_session_salt:  [u8][SESSION_SALT_SZ + ENCRYPTED_TAG_SZ],
        un_hash:         [u8][HASH_SZ],
        priv_hash:       [u8][HASH_SZ],
    );
    impl_empty_from_bytes!(XAloecryptSession;
        x_party:         {XParty},
        x_counter_party: {XCounterParty},
        x_session_salt:  [u8][SESSION_SALT_SZ + ENCRYPTED_TAG_SZ],
        un_hash:         [u8][HASH_SZ],
        priv_hash:       [u8][HASH_SZ],
    );
}
