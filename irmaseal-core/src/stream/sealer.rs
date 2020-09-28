use arrayvec::ArrayVec;
use core::marker::Unpin;
use futures::{stream, TryFutureExt};
use futures::{Sink, SinkExt, Stream, StreamExt};
use hmac::Mac;
use rand::{CryptoRng, Rng};
use std::vec::Vec;

use crate::stream::*;
use crate::*;

/// Sealer for an bytestream, which converts it into an IRMAseal encrypted bytestream.
pub struct Sealer<'a, R: Rng + CryptoRng> {
    identity: &'a Identity,
    ciphertext_keys: [u8; 144],
    aes_key: [u8; 32],
    mac_key: [u8; 32],
    rng: &'a mut R,
}

impl<'a, R: Rng + CryptoRng> Sealer<'a, R> {
    pub async fn new(
        identity: &'a Identity,
        pk: &PublicKey,
        rng: &'a mut R,
    ) -> Result<Sealer<'a, R>, Error> {
        let (c, k) = ibe::kiltz_vahlis_one::encrypt(&pk.0, &identity.derive(), rng);
        let (aes_key, mac_key) = crate::stream::util::derive_keys(&k);

        let ciphertext_keys = c.to_bytes();

        Ok(Sealer {
            identity,
            ciphertext_keys,
            aes_key,
            mac_key,
            rng,
        })
    }

    pub async fn seal(
        &mut self,
        mut input: impl Stream<Item = u8> + Unpin,
        mut output: impl Sink<u8> + Unpin,
    ) -> Result<(), Error> {
        let iv = crate::stream::util::generate_iv(self.rng);

        let mut aes = SymCrypt::new(&self.aes_key.into(), &iv.into()).await;
        let mut hmac = Verifier::new_varkey(&self.mac_key).unwrap();

        self.write_metadata(&mut output, &mut hmac).await?;

        hmac.input(&iv);
        stream::iter(&iv)
            .map(|byte| Ok(*byte))
            .forward(&mut output)
            .map_err(|_| Error::UpstreamWritableError)
            .await?;

        let mut buffer: ArrayVec<[u8; BLOCKSIZE]> = ArrayVec::new();
        while let Some(byte) = input.next().await {
            buffer.push(byte);
            if buffer.is_full() {
                self.seal_block(&mut buffer, &mut output, &mut aes, &mut hmac)
                    .await?;
            }
        }
        if !buffer.is_empty() {
            self.seal_block(&mut buffer, &mut output, &mut aes, &mut hmac)
                .await?;
        }
        let code = hmac.result_reset().code();
        let code_stream = stream::iter(code);

        code_stream
            .map(|byte| Ok(byte))
            .forward(&mut output)
            // TODO: Check error messages
            .map_err(|_| Error::UpstreamWritableError)
            .await?;

        output
            .close()
            // TODO: Check error messages
            .map_err(|_| Error::UpstreamWritableError)
            .await?;

        output
            .flush()
            // TODO: Check error messages
            .map_err(|_| Error::UpstreamWritableError)
            .await
    }

    async fn seal_block(
        &mut self,
        buffer: &mut ArrayVec<[u8; BLOCKSIZE]>,
        mut output: impl Sink<u8> + Unpin,
        aes: &mut SymCrypt,
        hmac: &mut Verifier,
    ) -> Result<(), Error> {
        let block = buffer.as_mut_slice();
        aes.encrypt(block).await;
        hmac.input(block);
        stream::iter(block)
            .map(|byte| Ok(*byte))
            .forward(&mut output)
            // TODO: Check error messages
            .map_err(|_| Error::UpstreamWritableError)
            .await?;
        buffer.clear();
        Ok(())
    }

    async fn write_metadata(
        &self,
        mut output: impl Sink<u8> + Unpin,
        hmac: &mut Verifier,
    ) -> Result<(), Error> {
        hmac.input(&PRELUDE);
        stream::iter(&PRELUDE)
            .map(|byte| Ok(*byte))
            .forward(&mut output)
            .map_err(|_| Error::UpstreamWritableError)
            .await?;
        hmac.input(&[FORMAT_VERSION]);
        stream::iter(&[FORMAT_VERSION])
            .map(|byte| Ok(*byte))
            .forward(&mut output)
            .map_err(|_| Error::UpstreamWritableError)
            .await?;

        // TODO: Fix when merging Rowan's metadata changes.
        let mut tmp = Vec::new();
        self.identity.write_to(&mut tmp)?;
        hmac.input(tmp.as_slice());
        stream::iter(&tmp)
            .map(|byte| Ok(*byte))
            .forward(&mut output)
            .map_err(|_| Error::UpstreamWritableError)
            .await?;

        hmac.input(&self.ciphertext_keys);
        stream::iter(self.ciphertext_keys.iter())
            .map(|byte| Ok(*byte))
            .forward(&mut output)
            .map_err(|_| Error::UpstreamWritableError)
            .await

        // TODO write IV
    }
}

impl Writable for Verifier {
    fn write(&mut self, buf: &[u8]) -> Result<(), Error> {
        self.input(buf);
        Ok(())
    }
}
