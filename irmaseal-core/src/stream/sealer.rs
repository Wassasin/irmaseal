use hmac::Mac;
use rand::{CryptoRng, Rng};
use std::vec::Vec;
use futures::{Stream, StreamExt, Sink, SinkExt};
use futures::stream;
use arrayvec::ArrayVec;
use std::marker::Unpin;

use crate::stream::*;
use crate::*;

/// Sealer for an bytestream, which converts it into an IRMAseal encrypted bytestream.
pub struct Sealer {
    aes: SymCrypt,
    hmac: Verifier,
    metadata: Vec<u8>,
}

impl Sealer {
    pub async fn new<R: Rng + CryptoRng>(
        i: &Identity,
        pk: &PublicKey,
        rng: &mut R,
    ) -> Result<Sealer, Error> {
        let (c, k) = ibe::kiltz_vahlis_one::encrypt(&pk.0, &i.derive(), rng);

        let (aeskey, mackey) = crate::stream::util::derive_keys(&k);
        let iv = crate::stream::util::generate_iv(rng);

        let aes = SymCrypt::new(&aeskey.into(), &iv.into()).await;
        let mut hmac = Verifier::new_varkey(&mackey).unwrap();

        let ciphertext = c.to_bytes();

        let mut metadata = Vec::new();

        hmac.input(&PRELUDE);
        metadata.extend(&PRELUDE);

        hmac.input(&[FORMAT_VERSION]);
        metadata.extend(&[FORMAT_VERSION]);

        i.write_to(&mut hmac)?;
        i.write_to(&mut metadata)?;

        hmac.input(&ciphertext);
        metadata.extend(ciphertext.iter());

        hmac.input(&iv);
        metadata.extend(&iv);

        Ok(Sealer { aes, hmac, metadata })
    }

    pub async fn seal(
        &mut self,
        mut input: impl Stream<Item = u8> + Unpin,
        mut output: impl Sink<u8> + Unpin
    ) -> Result<(), Error> {
        //TODO: Check whether final byte is not included here
        let metadata_stream = stream::iter(self.metadata.iter());
        let result = metadata_stream.map(|byte| Ok(*byte)).forward(&mut output).await;
        if result.is_err() {
            // TODO: Check error messages
            return Err(Error::UpstreamWritableError);
        }

        let mut buffer: ArrayVec<[u8; BLOCKSIZE]> = ArrayVec::new();
        while let Some(byte) = input.next().await {
            buffer.push(byte);
            if buffer.is_full() {
                let result = self.seal_block(&mut output, &mut buffer).await;
                if result.is_err() {
                    return result;
                }
            }
        }
        if !buffer.is_empty() {
            let result = self.seal_block(&mut output, &mut buffer).await;
            if result.is_err() {
                return result;
            }
        }
        let code = self.hmac.result_reset().code();
        let code_stream = stream::iter(code);
        let result = code_stream.map(|byte| Ok(byte)).forward(&mut output).await;
        if result.is_err() {
            // TODO: Check error messages
            return Err(Error::UpstreamWritableError);
        }
        let result = output.close().await;
        if result.is_err() {
            // TODO: Check error messages
            return Err(Error::UpstreamWritableError);
        }
        Ok(())
    }

    async fn seal_block(
        &mut self,
        mut output: impl Sink<u8> + Unpin,
        buffer: &mut ArrayVec<[u8; BLOCKSIZE]>
    ) -> Result<(), Error> {
        let block = buffer.as_mut_slice();
        self.aes.encrypt(block).await;
        self.hmac.input(block);
        let block_stream = stream::iter(block);
        let result = block_stream.map(|byte| Ok(*byte)).forward(&mut output).await;
        if result.is_err() {
            // TODO: Check error messages
            return Err(Error::UpstreamWritableError);
        }
        buffer.clear();
        Ok(())
    }
}

impl Writable for Verifier {
    fn write(&mut self, buf: &[u8]) -> Result<(), Error> {
        self.input(buf);
        Ok(())
    }
}
