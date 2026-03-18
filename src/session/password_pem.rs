use super::session::*;
use super::*;
use crate::crypt::*;

impl AloecryptPasswordPEM<CounterParty> for AloecryptSession {
    fn pem_hdr_tag() -> String {
        panic!("Should use XAloecryptSession PEM")
    }
    fn pem_ftr_tag() -> String {
        panic!("Should use XAloecryptSession PEM")
    }
    fn pem_sz() -> usize {
        panic!("Should use XAloecryptSession PEM")
    }

    fn x_pem(&self, password: &[u8], salt: &[u8], mut os_rng: &mut impl SysRng) -> String {
        let x_session = self
            .lock_with_password(password, salt, &mut os_rng)
            .expect("lock_with_password failed during PEM export");
        x_session.pem()
    }

    fn x_loads(pem: &str, password: &[u8], salt: &[u8]) -> Result<Self, AloecryptError>
    where
        Self: Sized,
    {
        let x_session = XAloecryptSession::loads(pem)?;
        let loaded = AloecryptSession::unlock_with_password(x_session, password, salt)?;

        if loaded.priv_hash() != x_session.priv_hash {
            return Err(AloecryptError::LoadPEMPrivKeyHash);
        }

        if loaded.hash() != x_session.un_hash {
            return Err(AloecryptError::LoadPEMHash);
        }

        Ok(loaded)
    }

    fn x_pub_loads(pem: &str) -> Result<CounterParty, AloecryptError>
    where
        Self: Sized,
    {
        let x_session = XAloecryptSession::loads(pem)?;
        Ok(CounterParty {
            address: x_session.x_counter_party.address,
            nonce: x_session.x_counter_party.nonce,
            signature: x_session.x_counter_party.signature,
            stable_kem: x_session.x_counter_party.stable_kem,
            session_kem: x_session.x_counter_party.session_kem,
            verifier: x_session.x_counter_party.verifier,
            stable_secret: EMPTY_SECRET,
            session_secret: EMPTY_SECRET,
        })
    }
}
