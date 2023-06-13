trait Hmac {
    fn open_key(key: &[u8]) -> Box<Key>;
}

/// Maximum support HMAC tag size: supports up to SHA512.
const HMAC_MAX_TAG: usize = 64;

/// A HMAC tag, stored as a value.
struct Tag {
    buf: [u8; HMAC_MAX_TAG],
    used: usize,
}

trait Key {
    /// Calculates a tag over `data`.
    fn one_shot(data: &[u8]) -> Tag;

    /// Starts a new incremental HMAC computation.
    fn start() -> Box<Incremental>;
}

trait Incremental {
    /// Add `data` to computation.
    fn update(self: Box<Self>, data: &[u8]) -> Box<Self>;

    /// Finish the computation, returning the resulting tag.
    fn finish(self: Box<Self>) -> Tag;
}

