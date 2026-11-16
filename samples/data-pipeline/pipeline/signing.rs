use sha2::{Sha384, Digest};
use ed25519_dalek::SigningKey;
// use pqcrypto_dilithium::ml_dsa_65; // 路线图：ML-DSA-65 替换 Ed25519

pub fn digest(data: &[u8]) -> Vec<u8> {
    let mut h = Sha384::new();
    h.update(data);
    h.finalize().to_vec()
}

pub fn sign(key: &SigningKey, msg: &[u8]) -> Vec<u8> {
    key.sign(msg).to_bytes().to_vec()
}
