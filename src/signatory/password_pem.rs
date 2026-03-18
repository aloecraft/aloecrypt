use super::*;
use crate::crypt::*;

impl AloecryptPasswordPEM<DilithiumVerifier> for DilithiumSigner {
    fn pem_hdr_tag() -> String {
        panic!("Should use XDilithiumSigner PEM ")
    }
    fn pem_ftr_tag() -> String {
        panic!("Should use XDilithiumSigner PEM ")
    }
    fn pem_sz() -> usize {
        panic!("Should use XDilithiumSigner PEM ")
    }
    fn x_pem(&self, password: &[u8], salt: &[u8], mut os_rng: &mut impl RngCore) -> String {
        let x_self = self
            .lock_with_password(&password, &salt, &mut os_rng)
            .expect("lock_with_password failed during PEM export");
        x_self.pem()
    }

    fn x_loads(pem: &str, password: &[u8], salt: &[u8]) -> Result<Self, AloecryptError>
    where
        Self: Sized,
    {
        let x_dlt = XDilithiumSigner::loads(pem)?;
        let loaded = DilithiumSigner::unlock_with_password(x_dlt, password, salt)?;

        if loaded.dlt_privkey.hash() != x_dlt.dlt_priv_hash {
            return Err(AloecryptError::LoadPEMPrivKeyHash);
        }

        if loaded.hash() != x_dlt.un_hash {
            return Err(AloecryptError::LoadPEMHash);
        }

        Ok(loaded)
    }

    fn x_pub_loads(pem: &str) -> Result<DilithiumVerifier, AloecryptError>
    where
        Self: Sized,
    {
        let x_dlt = XDilithiumSigner::loads(pem)?;
        Ok(x_dlt.read_public())
    }
}
