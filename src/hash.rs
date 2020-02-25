use crate::Scalar;

pub trait Blake2b512 {
    fn new(personalization: &[u8]) -> Self;
    fn update(&mut self, data: &[u8]);
    fn finalize(&self) -> [u8; 64];
}

#[cfg(feature = "blake2b_simd")]
/// Provides Blake2b512 implementation using blake2b_simd
pub struct StdBlake2b512 {
    state: blake2b_simd::State,
}

#[cfg(feature = "blake2b_simd")]
impl Blake2b512 for StdBlake2b512 {
    fn new(personalization: &[u8]) -> Self {
        let state = blake2b_simd::Params::new()
            .hash_length(64)
            .personal(personalization)
            .to_state();
        Self { state }
    }

    fn update(&mut self, data: &[u8]) {
        self.state.update(data);
    }

    fn finalize(&self) -> [u8; 64] {
        *self.state.finalize().as_array()
    }
}

/// Provides H^star, the hash-to-scalar function used by RedJubjub.
pub struct HStar<H: Blake2b512> {
    state: H,
}

impl<H: Blake2b512> Default for HStar<H> {
    fn default() -> Self {
        let state = H::new(b"Zcash_RedJubjubH");
        Self { state }
    }
}

impl<H: Blake2b512> HStar<H> {
    /// Add `data` to the hash, and return `Self` for chaining.
    pub fn update(mut self, data: &[u8]) -> Self {
        self.state.update(data);
        self
    }

    /// Consume `self` to compute the hash output.
    pub fn finalize(self) -> Scalar {
        Scalar::from_bytes_wide(&self.state.finalize())
    }
}
