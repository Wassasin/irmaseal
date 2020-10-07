use core::marker::Unpin;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, TryFutureExt};
use hmac::Mac;
use rand::{CryptoRng, Rng};
use std::vec::Vec;

use crate::stream::*;
use crate::*;

/// Sealer for an bytestream, which converts it into an IRMAseal encrypted bytestream.
pub struct Sealer<'a, C: CryptoRng + Rng> {
    identity: &'a Identity,
    rng: &'a mut C,
    ciphertext_keys: [u8; 144],
    aes_key: [u8; 32],
    mac_key: [u8; 32],
}

impl<'a, C: CryptoRng + Rng> Sealer<'a, C> {
    pub fn new(
        identity: &'a Identity,
        pk: &PublicKey,
        rng: &'a mut C,
    ) -> Result<Sealer<'a, C>, Error> {
        let (c, k) = ibe::kiltz_vahlis_one::encrypt(&pk.0, &identity.derive(), rng);
        let (aes_key, mac_key) = crate::stream::util::derive_keys(&k);

        let ciphertext_keys = c.to_bytes();

        Ok(Sealer {
            identity,
            rng,
            ciphertext_keys,
            aes_key,
            mac_key,
        })
    }

    pub async fn seal<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &mut self,
        mut input: R,
        mut output: W,
    ) -> Result<(), Error> {
        let iv = crate::stream::util::generate_iv(&mut self.rng);

        let mut aes = SymCrypt::new(&self.aes_key.into(), &iv.into()).await;
        let mut hmac = Verifier::new_varkey(&self.mac_key).unwrap();

        self.write_metadata(&mut output, &mut hmac).await?;

        hmac.input(&iv);
        output
            .write_all(&iv)
            // TODO: Check error messages
            .map_err(|_| Error::UpstreamWritableError)
            .await?;

        let mut buffer = [0u8; BLOCKSIZE];
        loop {
            let input_length = input
                .read(&mut buffer)
                // TODO: Check error messages
                .map_err(|_| Error::UpstreamWritableError)
                .await?;
            if input_length == 0 {
                break;
            }
            let block = &mut buffer[..input_length];
            aes.encrypt(block).await;
            hmac.input(block);
            output
                .write_all(block)
                // TODO: Check error messages
                .map_err(|_| Error::UpstreamWritableError)
                .await?;
        }

        let code = hmac.result_reset().code();
        output
            .write_all(&code)
            // TODO: Check error messages
            .map_err(|_| Error::UpstreamWritableError)
            .await?;

        output
            .flush()
            // TODO: Check error messages
            .map_err(|_| Error::UpstreamWritableError)
            .await
    }

    async fn write_metadata<W: AsyncWrite + Unpin>(
        &self,
        mut output: W,
        hmac: &mut Verifier,
    ) -> Result<(), Error> {
        hmac.input(&PRELUDE);
        output
            .write_all(&PRELUDE)
            // TODO: Check error messages
            .map_err(|_| Error::UpstreamWritableError)
            .await?;
        hmac.input(&[FORMAT_VERSION]);
        output
            .write_all(&[FORMAT_VERSION])
            // TODO: Check error messages
            .map_err(|_| Error::UpstreamWritableError)
            .await?;

        // TODO: Fix when merging Rowan's metadata changes.
        let mut tmp = Vec::new();
        self.identity.write_to(&mut tmp)?;
        hmac.input(tmp.as_slice());
        output
            .write_all(tmp.as_slice())
            // TODO: Check error messages
            .map_err(|_| Error::UpstreamWritableError)
            .await?;

        hmac.input(&self.ciphertext_keys);
        output
            .write_all(&self.ciphertext_keys)
            // TODO: Check error messages
            .map_err(|_| Error::UpstreamWritableError)
            .await?;
        Ok(())
    }
}

impl Writable for Verifier {
    fn write(&mut self, buf: &[u8]) -> Result<(), Error> {
        self.input(buf);
        Ok(())
    }
}
