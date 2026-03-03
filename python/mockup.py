from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
import hashlib

def to_curve25519_public_key(id_pub: ed25519.Ed25519PublicKey | bytes) -> x25519.X25519PublicKey:
    P = 2**255 - 19
    id_pub_bytes = id_pub.public_bytes_raw() if isinstance(id_pub, ed25519.Ed25519PublicKey) else id_pub
    # --- Algorithm: Public Key Fix (The Birational Map) ---
    # Ed25519 public key is (x, y). The bytes are 'y' with 'x's sign bit in the MSB.
    y_int = int.from_bytes(id_pub_bytes, 'little')
    y = y_int & ((1 << 255) - 1) # Mask out the 256th bit (the x-sign bit)

    # Map y -> u: u = (1 + y) * inv(1 - y) (mod P)
    u = ((1 + y) * pow(1 - y, -1, P)) % P
    u_bytes = u.to_bytes(32, 'little')
    return x25519.X25519PublicKey.from_public_bytes(u_bytes)

def to_curve25519_private_key(id_priv: ed25519.Ed25519PrivateKey | bytes) -> x25519.X25519PrivateKey:
    id_priv_bytes = id_priv.private_bytes_raw() if isinstance(id_priv, ed25519.Ed25519PrivateKey) else id_priv
    hash_output = hashlib.sha512(id_priv_bytes).digest()
    x_priv_scalar = bytearray(hash_output[:32])

    # "Clamping": Necessary for X25519 interop
    x_priv_scalar[0] &= 248
    x_priv_scalar[31] &= 127
    x_priv_scalar[31] |= 64

    return x25519.X25519PrivateKey.from_private_bytes(bytes(x_priv_scalar))

if False:
    id_priv = ed25519.Ed25519PrivateKey.generate()
    id_pub = id_priv.public_key()

    x_priv_derived = to_curve25519_private_key(id_priv)
    x_pub_derived = to_curve25519_public_key(id_pub)

    assert x_priv_derived.public_key() == x_pub_derived

    print(f"""
        {x_priv_derived.public_key().public_bytes_raw().hex()}
        {x_pub_derived.public_bytes_raw().hex()}
    """)


from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import serialization

KEY_ITERS = 4096
COM_STRUCT_ID = b"AloeBuffer.0"
MAGIC_BYTES = bytes([0x41,0x4c,0x4f,0x45,0x43,0x52,0x59,0x50,0x54,0x69,0x61,0x6d,0x6d,0x69,0x6b,0x65])

from pydantic import BaseModel, ConfigDict
from itertools import batched
from uuid import uuid7
import hashlib

class Keyfile(BaseModel):
    model_config = ConfigDict(ser_json_bytes='hex')
    cid: bytes
    public_key: bytes
    inner: bytes

    @property
    def PEM(self)-> str:
        pem_bytes = self.cid + self.inner + self.public_key
        return f"""-----BEGIN ALOECRYPT KEYFILE-----
{"\n".join([bytes(_).hex() for _ in batched(pem_bytes,32)])}
-----END ALOECRYPT KEYFILE-----
"""

    @classmethod
    def loads(cls, pem: str)-> "Keyfile":
        pem = "".join([_.strip() for _ in pem.split("\n")])
        assert pem.startswith("-----BEGIN ALOECRYPT KEYFILE-----")
        assert pem.endswith("-----END ALOECRYPT KEYFILE-----")
        pem = pem.replace("-----BEGIN ALOECRYPT KEYFILE-----","")
        pem = pem.replace("-----END ALOECRYPT KEYFILE-----","")
        return cls(
            cid = bytes.fromhex(pem[:32]),
            inner = bytes.fromhex(pem[32:128]),
            public_key = bytes.fromhex(pem[128:]),
        )

class PeerKey(BaseModel):
    model_config = ConfigDict(ser_json_bytes='hex')
    public_key: bytes

    @classmethod
    def from_bytes(cls, d:bytes)->"PeerKey":
        return cls(public_key=d)
    
    @property
    def x_pubkey(self)->x25519.X25519PublicKey:
        return to_curve25519_public_key(ed25519.Ed25519PublicKey.from_public_bytes(self.public_key))
    
    def send_encrypt(self, my_privkey: x25519.X25519PrivateKey | bytes, d: bytes, peer_nonce: bytes)->bytes:
        my_privkey = x25519.X25519PrivateKey.from_private_bytes(my_privkey) if isinstance(my_privkey, bytes) else my_privkey
        struct = hashlib.pbkdf2_hmac('sha256', my_privkey.exchange(self.x_pubkey), peer_nonce, KEY_ITERS)
        chacha_cipher = ChaCha20Poly1305(struct)
        return chacha_cipher.encrypt(COM_STRUCT_ID, d, peer_nonce)

    def recv_decrypt(self, my_privkey: x25519.X25519PrivateKey | bytes, d: bytes, peer_nonce: bytes)->bytes:
        my_privkey = x25519.X25519PrivateKey.from_private_bytes(my_privkey) if isinstance(my_privkey, bytes) else my_privkey
        struct = hashlib.pbkdf2_hmac('sha256', my_privkey.exchange(self.x_pubkey), peer_nonce, KEY_ITERS)
        chacha_cipher = ChaCha20Poly1305(struct)
        return chacha_cipher.decrypt(COM_STRUCT_ID, d, peer_nonce)
    
    def verify(self, sig: bytes, d:bytes)->bool:
        verifying_key = ed25519.Ed25519PublicKey.from_public_bytes(self.public_key)
        try:
            verifying_key.verify(sig, d)
            return True
        except:
            return False
        
    @property
    def PEM(self)-> str:
        pem_bytes = self.cid + self.inner + self.public_key
        return f"""-----BEGIN ALOECRYPT PEERKEY-----
{"\n".join([bytes(_).hex() for _ in batched(pem_bytes,32)])}
-----END ALOECRYPT PEERKEY-----
"""

    @classmethod
    def loads(cls, pem: str)-> "Keyfile":
        pem = "".join([_.strip() for _ in pem.split("\n")])
        assert pem.startswith("-----BEGIN ALOECRYPT PEERKEY-----")
        assert pem.endswith("-----END ALOECRYPT PEERKEY-----")
        pem = pem.replace("-----BEGIN ALOECRYPT PEERKEY-----","")
        pem = pem.replace("-----END ALOECRYPT PEERKEY-----","")
        return cls(
            cid = bytes.fromhex(pem[:32]),
            inner = bytes.fromhex(pem[32:128]),
            public_key = bytes.fromhex(pem[128:]),
        )

class Keypair(BaseModel):
    model_config = ConfigDict(ser_json_bytes='hex')
    cid: bytes
    private_key: bytes
    public_key: bytes

    @classmethod
    def new(cls):
        key = ed25519.Ed25519PrivateKey.generate()
        private_key = key.private_bytes_raw()
        public_key = key.public_key().public_bytes_raw()
        cid = uuid7().bytes
        return cls(private_key=private_key, public_key=public_key, cid=cid)
    
    @property
    def PEM(self)-> str:
        pem_bytes = self.cid + self.private_key + self.public_key
        return f"""-----BEGIN ALOECRYPT ver.1-----
{"\n".join([bytes(_).hex() for _ in batched(pem_bytes,32)])}
-----END ALOECRYPT ver.1-----
"""
    @property
    def x_pubkey(self)->x25519.X25519PublicKey:
        return to_curve25519_public_key(ed25519.Ed25519PublicKey.from_public_bytes(self.public_key))
    
    @property
    def x_privkey(self)->x25519.X25519PrivateKey:
        return to_curve25519_private_key(ed25519.Ed25519PrivateKey.from_private_bytes(self.private_key))

    def self_encrypt(self, d: bytes)->bytes:
        struct = hashlib.pbkdf2_hmac('sha256', self.x_privkey.exchange(self.x_pubkey), self.cid, KEY_ITERS)
        chacha_cipher = ChaCha20Poly1305(struct)
        return chacha_cipher.encrypt(COM_STRUCT_ID, d, self.cid)

    def self_decrypt(self, d: bytes)->bytes:
        struct = hashlib.pbkdf2_hmac('sha256', self.x_privkey.exchange(self.x_pubkey), self.cid, KEY_ITERS)
        chacha_cipher = ChaCha20Poly1305(struct)
        return chacha_cipher.decrypt(COM_STRUCT_ID, d, self.cid)
    
    def sign(self, d:bytes)->bytes:
        signing_key = ed25519.Ed25519PrivateKey.from_private_bytes(self.private_key)
        return signing_key.sign(d)
    
    def verify(self, sig: bytes, d:bytes)->bool:
        verifying_key = ed25519.Ed25519PublicKey.from_public_bytes(self.public_key)
        try:
            verifying_key.verify(sig, d)
            return True
        except:
            return False
        
    @classmethod
    def loads(cls, pem: str)-> "Keypair":
        pem = "".join([_.strip() for _ in pem.split("\n")])
        assert pem.startswith("-----BEGIN ALOECRYPT ver.1-----")
        assert pem.endswith("-----END ALOECRYPT ver.1-----")
        pem = pem.replace("-----BEGIN ALOECRYPT ver.1-----","")
        pem = pem.replace("-----END ALOECRYPT ver.1-----","")
        return cls(
            cid = bytes.fromhex(pem[:32]),
            private_key = bytes.fromhex(pem[32:96]),
            public_key = bytes.fromhex(pem[96:]),
        )

def key_pack(keypair: Keypair, password: str | bytes)-> Keyfile:
    secret = password.encode() if isinstance(password, str) else password
    struct = hashlib.pbkdf2_hmac('sha256', secret, keypair.cid, KEY_ITERS)
    chacha_cipher = ChaCha20Poly1305(struct)
    inner=chacha_cipher.encrypt(COM_STRUCT_ID, keypair.private_key, keypair.cid)
    return Keyfile(cid=keypair.cid, public_key=keypair.public_key, inner=inner)

def key_unpack(keyfile: Keyfile, password: str | bytes)-> Keypair:
    secret = password.encode() if isinstance(password, str) else password
    struct = hashlib.pbkdf2_hmac('sha256', secret, keyfile.cid, KEY_ITERS)
    chacha_cipher = ChaCha20Poly1305(struct)
    private_key=chacha_cipher.decrypt(COM_STRUCT_ID, keyfile.inner, keyfile.cid)
    return Keypair(cid=keyfile.cid, public_key=keyfile.public_key, private_key=private_key)

if False:

    keypair = Keypair.new()
    keyfile = key_pack(keypair, "My Password")

    # unencrypted keys:
    # ========
    keypair_pem = keypair.PEM
    loaded_keypair = Keypair.loads(keypair_pem)

    # encrypted keys:
    # ========
    keyfile_pem = keyfile.PEM
    loaded_keyfile = Keyfile.loads(keyfile_pem)

    reloaded_keypair = key_unpack(loaded_keyfile, "My Password")

if False:
    print(f"""
{keypair.cid}\n{loaded_keypair.cid}\n{reloaded_keypair.cid}\n
{keypair.public_key}\n{loaded_keypair.public_key}\n{reloaded_keypair.public_key}\n
{keypair.private_key}\n{loaded_keypair.private_key}\n{reloaded_keypair.private_key}\n
====
{keyfile.cid}\n{loaded_keyfile.cid}\n
{keyfile.public_key}\n{loaded_keyfile.public_key}\n
{keyfile.inner}\n{loaded_keyfile.inner}\n
""")

# print(f"{keypair.PEM}\n{keyfile.PEM}\n{reloaded_keypair.PEM}")



from pydantic import Field
from typing import Optional
from datetime import datetime, UTC
import msgpack
import lz4.frame
import math

MAX_FOOTER_BYTES = 2**16
FOOTER_LEN_BYTES = int(math.log2(MAX_FOOTER_BYTES) / 8)
HDR_SZ_BYTES = 176

ts_bytes_now = lambda: int(datetime.now(UTC).timestamp()*1000).to_bytes(8, byteorder='little', signed=False)

class AloecryptFooter(BaseModel):
    description: Optional[str] = Field("")
    metadata: Optional[dict[str,str]] = Field({})
    created_at: Optional[bytes] = Field(default_factory=ts_bytes_now, max_length=8)

    @classmethod
    def from_bytes(cls, d:bytes)->AloecryptFooter:
        assert d[-len(MAGIC_BYTES):] == MAGIC_BYTES
        return AloecryptFooter(**msgpack.loads(lz4.frame.decompress(d)))
        
    @staticmethod
    def get_footer_bytes(d:bytes)-> bytes:
        assert d[-len(MAGIC_BYTES):] == MAGIC_BYTES
        ftr_len =  int.from_bytes(
            d[-(FOOTER_LEN_BYTES + len(MAGIC_BYTES)):-len(MAGIC_BYTES)], byteorder='little', signed=False)
        return d[-(ftr_len + FOOTER_LEN_BYTES + len(MAGIC_BYTES)):]

    def to_bytes(self):
        ftr_bytes = lz4.frame.compress(msgpack.dumps(self.model_dump()))
        ftr_len = len(ftr_bytes) 
        assert ftr_len < MAX_FOOTER_BYTES - (len(MAGIC_BYTES) + FOOTER_LEN_BYTES)
        return ftr_bytes + ftr_len.to_bytes(2, byteorder='little', signed=False) + MAGIC_BYTES

class AloecryptHeader(BaseModel):
    peer_addr: Optional[bytes] = Field(bytes([0]*32), min_length=32, max_length=32)
    signer_key: bytes = Field(min_length=32, max_length=32)
    nonce_16: bytes = Field(min_length=16, max_length=16)
    app_id_16: bytes = Field(min_length=16, max_length=16)
    signature: bytes = Field(min_length=64, max_length=64)

    @classmethod
    def sign(cls, d: bytes, app_id_16:bytes, nonce_16: bytes, signer_keypair: Keypair, peer_addr:bytes = bytes([0]*32)) -> "AloecryptHeader":
        payload = b''
        payload += peer_addr
        payload += signer_keypair.public_key
        payload += nonce_16
        payload += app_id_16
        payload += d
        signature = signer_keypair.sign(payload)
        signer_key = signer_keypair.public_key
        return cls(
            nonce_16=nonce_16,
            app_id_16=app_id_16,
            signer_key=signer_key,
            peer_addr=peer_addr,
            signature=signature)
    
    def verify(self, d: bytes)->bool:
        peer_key = PeerKey.from_bytes(self.signer_key)
        payload = b''
        payload += self.peer_addr
        payload += self.signer_key
        payload += self.nonce_16
        payload += self.app_id_16
        payload += d
        return peer_key.verify(self.signature, payload)
    
    @classmethod
    def from_bytes(cls, d:bytes)->AloecryptHeader:
        assert d[:16] == MAGIC_BYTES
        return cls(
            peer_addr = d[16:48],
            signer_key = d[48:80],
            app_id_16 = d[80:96],
            nonce_16 = d[96:112],
            signature = d[112:HDR_SZ_BYTES],
        )

    def to_bytes(self):
        return  MAGIC_BYTES + self.peer_addr + self.signer_key + self.app_id_16 + self.nonce_16 + self.signature

class AloecryptPackage(BaseModel):
    hdr: AloecryptHeader
    payload: bytes
    ftr: AloecryptFooter

    @classmethod
    def pack(cls, o, signer_keypair:Keypair, peer_addr: bytes, app_id_16: bytes, nonce_16: bytes) -> "AloecryptPackage":
        packed = msgpack.dumps(o)
        compressed = lz4.frame.compress(packed)
        payload = PeerKey.from_bytes(peer_addr).send_encrypt(signer_keypair.x_privkey, compressed, nonce_16)
        header = AloecryptHeader.sign(payload, peer_addr=peer_addr, signer_keypair=signer_keypair, app_id_16=app_id_16, nonce_16=nonce_16)
        footer = AloecryptFooter()
        return cls(hdr=header, payload=payload, ftr=footer)
    
    def unpack(self, my_privkey: Keypair):
        decrypted = PeerKey.from_bytes(self.hdr.signer_key).recv_decrypt(my_privkey.x_privkey, self.payload, self.hdr.nonce_16)
        inflated = lz4.frame.decompress(decrypted)
        return msgpack.loads(inflated)
    
    @classmethod
    def from_bytes(cls, d:bytes)->"AloecryptPackage":
        ftr_bytes = AloecryptFooter.get_footer_bytes(d)
        ftr_len = len(ftr_bytes)
        assert len(d) > HDR_SZ_BYTES + ftr_len
        ftr = AloecryptFooter.from_bytes(ftr_bytes)
        hdr = AloecryptHeader.from_bytes(d[:HDR_SZ_BYTES])
        payload = d[HDR_SZ_BYTES:-ftr_len]
        return cls(ftr=ftr,hdr=hdr,payload=payload)

    def verify_hdr(self)->bool:
        return self.hdr.verify(self.payload)

    def to_bytes(self):
        return self.hdr.to_bytes() + self.payload + self.ftr.to_bytes()

identity_A = Keypair.new()
identity_B = Keypair.new()
identity_C = Keypair.new()
identity_D = Keypair.new()

test_obj = {}
test_obj["identity_A"] = identity_A.model_dump()
test_obj["identity_B"] = identity_B.model_dump()
test_obj["identity_C"] = identity_C.model_dump()
test_obj["identity_D"] = identity_D.model_dump()

import random
nonce_16 = random.randbytes(16)
app_id_16 = b'[_IDENTITY-TEST]'
package = AloecryptPackage.pack(test_obj, app_id_16=app_id_16, nonce_16=nonce_16, signer_keypair=identity_A, peer_addr=identity_B.public_key)

pkg_bytes = package.to_bytes()

reloaded_package = AloecryptPackage.from_bytes(pkg_bytes)

assert reloaded_package.hdr.app_id_16 == app_id_16
assert reloaded_package.hdr.nonce_16 == nonce_16
assert reloaded_package.hdr.peer_addr == identity_B.public_key
assert reloaded_package.verify_hdr()
reloaded_package.unpack(my_privkey=identity_B)