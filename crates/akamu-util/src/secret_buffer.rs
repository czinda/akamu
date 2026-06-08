use native_ossl::util::SecretBuf;
use std::fmt;
use std::ops::Deref;

/// A secure byte buffer that zeroes memory on drop via `OPENSSL_cleanse`.
///
/// Use for all secret values (passwords, keys, tokens) that should not
/// linger in process memory after use.
pub struct SecretBuffer {
    inner: SecretBuf,
}

impl Clone for SecretBuffer {
    fn clone(&self) -> Self {
        Self::from_bytes(self.as_bytes())
    }
}

impl SecretBuffer {
    pub fn from_string(s: String) -> Self {
        Self::from_bytes(s.as_bytes())
    }

    pub fn from_bytes(b: &[u8]) -> Self {
        Self {
            inner: SecretBuf::from_slice(b),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.inner.as_ref()
    }

    pub fn to_string_lossy(&self) -> String {
        String::from_utf8_lossy(self.as_bytes()).into_owned()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl AsRef<[u8]> for SecretBuffer {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

impl Deref for SecretBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.inner.as_ref()
    }
}

impl fmt::Debug for SecretBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBuffer([redacted], {} bytes)", self.len())
    }
}
