use crate::provider;
use ring;

pub(crate) struct Hmac(&'static ring::hmac::Algorithm);

pub(crate) static HMAC_SHA256: Hmac = Hmac(&ring::hmac::HMAC_SHA256);
pub(crate) static HMAC_SHA384: Hmac = Hmac(&ring::hmac::HMAC_SHA384);
pub(crate) static HMAC_SHA512: Hmac = Hmac(&ring::hmac::HMAC_SHA512);

impl Into<provider::hmac::Tag> for ring::hmac::Tag {
    fn into(self) -> provider::hmac::Tag {
        provider::hmac::Tag::new(self.as_ref())
    }
}

impl provider::hmac::Hmac for Hmac {
    fn open_key(&self, key: &[u8]) -> Box<dyn provider::hmac::Key> {
        Box::new(Key(ring::hmac::Key::new(*self.0, key)))
    }

    fn hash_output_len(&self) -> usize {
        self.0.digest_algorithm().output_len
    }
}

struct Key(ring::hmac::Key);

impl provider::hmac::Key for Key {
    fn one_shot(&self, data: &[u8]) -> provider::hmac::Tag {
        ring::hmac::sign(&self.0, data).into()
    }

    fn start(&self) -> Box<dyn provider::hmac::Incremental> {
        Box::new(Incremental(ring::hmac::Context::with_key(&self.0)))
    }

    fn tag_len(&self) -> usize {
        self.0
            .algorithm()
            .digest_algorithm()
            .output_len
    }
}

struct Incremental(ring::hmac::Context);

impl provider::hmac::Incremental for Incremental {
    fn update(mut self: Box<Self>, data: &[u8]) -> Box<dyn provider::hmac::Incremental> {
        self.0.update(data);
        self
    }

    fn finish(self: Box<Self>) -> provider::hmac::Tag {
        self.0.sign().into()
    }
}
