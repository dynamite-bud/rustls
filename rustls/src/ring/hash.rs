use crate::msgs::enums::HashAlgorithm;
use crate::provider;
use ring;

pub(crate) struct Hash(&'static ring::digest::Algorithm, HashAlgorithm);

pub(crate) static SHA256: Hash = Hash(&ring::digest::SHA256, HashAlgorithm::SHA256);
pub(crate) static SHA384: Hash = Hash(&ring::digest::SHA384, HashAlgorithm::SHA384);

impl Into<provider::hash::Output> for ring::digest::Digest {
    fn into(self) -> provider::hash::Output {
        provider::hash::Output::new(self.as_ref())
    }
}

impl provider::hash::Hash for Hash {
    fn algorithm(&self) -> HashAlgorithm {
        self.1
    }

    fn start(&self) -> Box<dyn provider::hash::Context> {
        Box::new(Context(ring::digest::Context::new(self.0)))
    }
}

struct Context(ring::digest::Context);

impl provider::hash::Context for Context {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn fork(&self) -> Box<dyn provider::hash::Context> {
        Box::new(Self(self.0.clone()))
    }

    fn finish(self: Box<Self>) -> provider::hash::Output {
        self.0.finish().into()
    }
}
