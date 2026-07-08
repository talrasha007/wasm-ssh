//! Random number source plumbing.
//!
//! `ssh-core` never depends on `getrandom` directly - the host (wasm-bindgen crate, or the
//! native test harness) is responsible for supplying actual entropy by implementing
//! [`SecureRandom`] and passing it into [`crate::session::Session::new`].
//!
//! An adapter newtype bridges that single trait into `rand_core` 0.10, required by
//! `x25519-dalek`/`crypto-bigint`. `rsa`/`ssh-key` also depend on the older `rand_core` 0.6, but
//! `ssh-core` never needs to hand them a caller-supplied RNG directly - RSA client-auth signing
//! (PKCS#1v1.5) is deterministic, and `ssh-key`'s own key-generation helpers manage their RNG
//! internally - so no 0.6-flavored adapter lives here. `rand_core` 0.6 is still a workspace
//! dependency purely for test fixtures (generating throwaway keypairs via `PrivateKey::random`).

/// A source of cryptographically secure random bytes, supplied by the host environment.
///
/// In `wasm-ssh-bindgen` this is backed by `getrandom` (`crypto.getRandomValues()` via the
/// `wasm_js` backend); in native tests it can be backed by the OS RNG or a seeded PRNG for
/// reproducibility.
pub trait SecureRandom {
    fn fill(&mut self, buf: &mut [u8]);
}

/// Adapts any [`SecureRandom`] to `rand_core` 0.10's RNG traits, as required by `x25519-dalek`
/// and `crypto-bigint`.
///
/// rand_core 0.10 restructured its trait hierarchy around fallibility: you implement the
/// fallible [`rand_core_10::TryRng`] (with `Error = Infallible`) and the infallible `Rng`/
/// `RngCore` traits come for free via blanket impls. [`rand_core_10::TryCryptoRng`] is a marker
/// with no methods of its own, so it still needs an explicit (empty) impl.
pub(crate) struct RngCore10<'a, R: SecureRandom>(pub &'a mut R);

impl<R: SecureRandom> rand_core_10::TryRng for RngCore10<'_, R> {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> core::result::Result<u32, Self::Error> {
        let mut buf = [0u8; 4];
        self.0.fill(&mut buf);
        Ok(u32::from_le_bytes(buf))
    }

    fn try_next_u64(&mut self) -> core::result::Result<u64, Self::Error> {
        let mut buf = [0u8; 8];
        self.0.fill(&mut buf);
        Ok(u64::from_le_bytes(buf))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> core::result::Result<(), Self::Error> {
        self.0.fill(dst);
        Ok(())
    }
}

impl<R: SecureRandom> rand_core_10::TryCryptoRng for RngCore10<'_, R> {}

#[cfg(test)]
mod tests {
    use super::*;

    struct CountingRng(u8);
    impl SecureRandom for CountingRng {
        fn fill(&mut self, buf: &mut [u8]) {
            for b in buf {
                *b = self.0;
                self.0 = self.0.wrapping_add(1);
            }
        }
    }

    #[test]
    fn rng_core_10_adapter_fills_bytes() {
        use rand_core_10::Rng;
        let mut rng = CountingRng(10);
        let mut adapter = RngCore10(&mut rng);
        let mut buf = [0u8; 3];
        adapter.fill_bytes(&mut buf);
        assert_eq!(buf, [10, 11, 12]);
    }
}
