use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};

pub use hex::encode;

pub enum Algorithm {
    SHA1,
    SHA256,
    SHA512,
}

/// create a cryptographic hash from a string (sha1, sha256, sha512)
/// ```
/// use rust_utilities::crypto::sha::{Algorithm, CryptographicHash};
///
/// let mut sha1 = CryptographicHash::new(Algorithm::SHA1);
/// sha1.update(b"test sha1 hash");
///
/// let hash = hex::encode(sha1.finalize());
///
/// assert_eq!(hash, "7726bd9560e1ad4a1a4f056cae5c0c9ea8bacfc2".to_string())
/// ```
#[derive(Debug, Clone)]
pub enum CryptographicHash {
    Sha1(Sha1),
    Sha256(Sha256),
    Sha512(Sha512),
}

impl CryptographicHash {
    /// Create a new hasher
    pub fn new(algo: Algorithm) -> Self {
        match algo {
            Algorithm::SHA1 => Self::Sha1(Sha1::new()),
            Algorithm::SHA256 => Self::Sha256(Sha256::new()),
            Algorithm::SHA512 => Self::Sha512(Sha512::new()),
        }
    }

    /// Set a value for hasher
    pub fn update(&mut self, input: &[u8]) {
        match self {
            Self::Sha1(sha1) => sha1.update(input),
            Self::Sha256(sha256) => sha256.update(input),
            Self::Sha512(sha512) => sha512.update(input),
        }
    }

    /// Compute hash
    pub fn finalize(&mut self) -> Vec<u8> {
        match self {
            Self::Sha1(sha1) => sha1.finalize_reset().to_vec(),
            Self::Sha256(sha256) => sha256.finalize_reset().to_vec(),
            Self::Sha512(sha512) => sha512.finalize_reset().to_vec(),
        }
    }

    /// Computing a hash in one function
    /// ```
    /// use rust_utilities::crypto::sha::{Algorithm, CryptographicHash};
    ///
    /// // hash &str using SHA1
    /// let hash_string = hex::encode(CryptographicHash::hash(Algorithm::SHA1, "test".as_bytes()));
    /// ```
    pub fn hash(algo: Algorithm, input: &[u8]) -> Vec<u8> {
        let mut hasher = Self::new(algo);

        hasher.update(input);

        hasher.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::{Algorithm, CryptographicHash};

    #[test]
    fn sha1() {
        let mut sha1 = CryptographicHash::new(Algorithm::SHA1);
        sha1.update(b"test sha1 hash");

        let hash = hex::encode(sha1.finalize());

        assert_eq!(hash, "7726bd9560e1ad4a1a4f056cae5c0c9ea8bacfc2".to_string())
    }

    #[test]
    fn sha256() {
        let mut sha256 = CryptographicHash::new(Algorithm::SHA256);
        sha256.update(b"test sha256 hash");

        let hash = hex::encode(sha256.finalize());

        assert_eq!(
            hash,
            "eaf6e4198f39ccd63bc3e957d43bf4ef67f12c318c8e3cdc2567a37339902dac".to_string()
        )
    }

    #[test]
    fn sha512() {
        let mut sha512 = CryptographicHash::new(Algorithm::SHA512);
        sha512.update(b"test sha512 hash");

        let hash = hex::encode(sha512.finalize());

        assert_eq!(
            hash,
            "b43b4d7178014c92f55be828d66c9f98211fc67b385f7790a5b4b2fcb89fe1831645b5a4c17f3f7f11d8f34d2800a77a2b8faa5a0fb9d6b8f7befbc29a9ce795".to_string()
        )
    }
}
