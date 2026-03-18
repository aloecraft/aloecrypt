use super::*;
use crate::crypt::*;

const KYBER_FULL_TAG: &str = "Aloecrypt KyberFullKEM";
const KYBER_PUBLIC_TAG: &str = "Aloecrypt KyberPublicKEM";
const CIPHER_PEM_TAG: &str = "Aloecrypt Cipher";

impl AloecryptPasswordPEM<KyberPublicKEM> for KyberFullKEM {
    fn pem_hdr_tag() -> String {
        panic!("Should use XKyberFullKEM PEM ")
    }
    fn pem_ftr_tag() -> String {
        panic!("Should use XKyberFullKEM PEM ")
    }
    fn pem_sz() -> usize {
        panic!("Should use XKyberFullKEM PEM ")
    }
    fn x_pem(&self, password: &[u8], salt: &[u8], mut os_rng: &mut impl SysRng) -> String {
        let x_kem = self
            .lock_with_password(&password, &salt, &mut os_rng)
            .expect("lock_with_password failed during PEM export");
        x_kem.pem()
    }
    fn x_loads(pem: &str, password: &[u8], salt: &[u8]) -> Result<Self, AloecryptError>
    where
        Self: Sized,
    {
        let x_kem = XKyberFullKEM::loads(pem)?;
        let loaded = KyberFullKEM::unlock_with_password(x_kem, &password, &salt)?;
        if loaded.kyb_privkey.hash() != x_kem.kyb_priv_hash {
            return Err(AloecryptError::LoadPEMPrivKeyHash);
        }
        if loaded.hash() != x_kem.un_hash {
            return Err(AloecryptError::LoadPEMHash);
        }
        Ok(loaded)
    }

    fn x_pub_loads(pem: &str) -> Result<KyberPublicKEM, AloecryptError>
    where
        Self: Sized,
    {
        let x_kem = XKyberFullKEM::loads(pem)?;
        Ok(x_kem.read_public())
    }
}
