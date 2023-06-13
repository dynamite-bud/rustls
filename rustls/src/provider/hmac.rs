pub(crate) trait Hmac: Send + Sync {
    fn open_key(&self, key: &[u8]) -> Box<dyn Key>;
}

/// Maximum support HMAC tag size: supports up to SHA512.
const HMAC_MAX_TAG: usize = 64;

/// A HMAC tag, stored as a value.
pub struct Tag {
    buf: [u8; HMAC_MAX_TAG],
    used: usize,
}

impl Tag {
    pub(crate) fn new(bytes: &[u8]) -> Self {
        let mut tag = Self {
            buf: [0u8; HMAC_MAX_TAG],
            used: bytes.len(),
        };
        tag.buf[..bytes.len()].copy_from_slice(bytes);
        tag
    }
}

impl AsRef<[u8]> for Tag {
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.used]
    }
}

pub(crate) trait Key {
    /// Calculates a tag over `data`.
    fn one_shot(&self, data: &[u8]) -> Tag;

    /// Starts a new incremental HMAC computation.
    fn start(&self) -> Box<dyn Incremental>;

    /// Returns the length of the tag returned by a computation using
    /// this key.
    fn tag_len(&self) -> usize;
}

pub(crate) trait Incremental {
    /// Add `data` to computation.
    fn update(self: Box<Self>, data: &[u8]) -> Box<dyn Incremental>;

    /// Finish the computation, returning the resulting tag.
    fn finish(self: Box<Self>) -> Tag;
}
