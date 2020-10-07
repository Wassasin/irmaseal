use crate::stream::*;
use crate::*;

use crate::util::SliceReader;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, TryFutureExt};
use hmac::Mac;

/// First stage opener of an IRMAseal encrypted bytestream.
/// It reads the IRMAseal header, and yields the recipient Identity for which the content is intended.
///
/// Enables the library user to lookup the UserSecretKey corresponding to this Identity before continuing.
pub struct OpenerSealed<R: AsyncRead + Unpin> {
    input_reader: R,
    metadata: Vec<u8>,
}

impl<R: AsyncRead + Unpin> OpenerSealed<R> {
    /// Starts interpreting a bytestream as an IRMAseal stream.
    /// Will immediately detect whether the bytestream actually is such a stream, and will yield
    /// the identity for which the stream is intended, as well as the stream continuation.
    pub async fn new(mut r: R) -> Result<(Identity, OpenerSealed<R>), Error> {
        let mut buffer = [0u8; 14];
        r.read_exact(&mut buffer)
            // TODO: Check error messages
            .map_err(|_| Error::UpstreamWritableError)
            .await?;
        if buffer[..4] != PRELUDE {
            return Err(Error::NotIRMASEAL);
        }

        if buffer[4] != FORMAT_VERSION {
            return Err(Error::IncorrectVersion);
        }

        // TODO: Temporary read all bytes first. Can be changed when Rowan's metadata is merged.
        let identity_length = usize::from(u8::from_be(buffer[13]));
        let mut metadata = vec![0u8; 15 + identity_length];
        let metadata_slice = metadata.as_mut_slice();
        metadata_slice[..14].copy_from_slice(&buffer);
        r.read_exact(&mut metadata_slice[14..])
            // TODO: Check error messages
            .map_err(|_| Error::UpstreamWritableError)
            .await?;
        let attribute_length = usize::from(u8::from_be(*metadata.last().unwrap()));
        let mut attribute = vec![0u8; attribute_length];
        r.read_exact(attribute.as_mut_slice())
            // TODO: Check error messages
            .map_err(|_| Error::UpstreamWritableError)
            .await?;
        metadata.extend(attribute);
        let i = Identity::read_from(&mut SliceReader::new(&metadata.as_slice()[5..]))?;

        Ok((
            i,
            OpenerSealed {
                input_reader: r,
                metadata,
            },
        ))
    }

    /// Will unseal the stream continuation and write the plaintext in the given writer.
    pub async fn unseal<W: AsyncWrite + Unpin>(
        mut self,
        usk: &UserSecretKey,
        mut output: W,
    ) -> Result<bool, Error> {
        let mut ciphertext_buffer = [0u8; 144];
        self.input_reader
            .read_exact(&mut ciphertext_buffer)
            // TODO: Check error messages
            .map_err(|_| Error::UpstreamWritableError)
            .await?;
        let c = crate::util::open_ct(ibe::kiltz_vahlis_one::CipherText::from_bytes(
            &ciphertext_buffer,
        ))
        .ok_or(Error::FormatViolation)?;

        let m = ibe::kiltz_vahlis_one::decrypt(&usk.0, &c);
        let (skey, mackey) = crate::stream::util::derive_keys(&m);

        let mut hmac = Verifier::new_varkey(&mackey).unwrap();

        hmac.input(self.metadata.as_slice());
        hmac.input(&ciphertext_buffer);

        let mut iv = [0u8; IVSIZE];
        self.input_reader
            .read_exact(&mut iv)
            // TODO: Check error messages
            .map_err(|_| Error::UpstreamWritableError)
            .await?;
        hmac.input(&iv);

        let mut aes = SymCrypt::new(&skey.into(), &iv).await;
        let mut buffer = [0u8; MACSIZE + 2 * BLOCKSIZE];

        // The input buffer must at least contain enough bytes for a MAC to be included.
        self.input_reader
            .read_exact(&mut buffer[..MACSIZE])
            // TODO: Check error messages
            .map_err(|_| Error::UpstreamWritableError)
            .await?;

        let mut buffer_tail = MACSIZE;
        loop {
            let input_length = self
                .input_reader
                .read(&mut buffer[buffer_tail..buffer_tail + BLOCKSIZE])
                // TODO: Check error messages
                .map_err(|_| Error::UpstreamWritableError)
                .await?;
            buffer_tail += input_length;

            // TODO: Consider size of buffer for efficiency
            if buffer_tail > BLOCKSIZE + MACSIZE || input_length == 0 && buffer_tail > MACSIZE {
                let mut block = &mut buffer[0..buffer_tail - MACSIZE];
                hmac.input(&mut block);
                aes.encrypt(&mut block).await;
                output
                    .write_all(&mut block)
                    // TODO: Check error messages
                    .map_err(|_| Error::UpstreamWritableError)
                    .await?;

                // Make sure potential MAC is shifted to the front of the array.
                let mut tmp = [0u8; MACSIZE];
                tmp.copy_from_slice(&buffer[buffer_tail - MACSIZE..buffer_tail]);
                buffer[..MACSIZE].copy_from_slice(&tmp);

                buffer_tail = MACSIZE;
            }

            if input_length == 0 {
                break;
            }
        }

        output
            .flush()
            // TODO: Check error messages
            .map_err(|_| Error::UpstreamWritableError)
            .await?;
        Ok(hmac.verify(&buffer[..MACSIZE]).is_ok())
    }
}
