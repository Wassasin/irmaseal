pub fn set_panic_hook() {
    // When the `console_error_panic_hook` feature is enabled, we can call the
    // `set_panic_hook` function at least once during initialization, and then
    // we will get better error messages if our code ever panics.
    //
    // For more details see
    // https://github.com/rustwasm/console_error_panic_hook#readme
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

pub struct OwnedSliceReader<T> {
    buf: Box<[T]>,
    i: usize,
}

impl<T> OwnedSliceReader<T> {
    pub fn new(buf: Box<[T]>) -> OwnedSliceReader<T> {
        OwnedSliceReader { buf, i: 0 }
    }
}

impl<'a> irmaseal_core::Readable for OwnedSliceReader<u8> {
    fn read_byte(&mut self) -> Result<u8, irmaseal_core::Error> {
        if self.buf.len() < self.i {
            return Err(irmaseal_core::Error::EndOfStream);
        }

        unsafe {
            let res = *self.buf.get_unchecked(self.i);
            self.i += 1;

            Ok(res)
        }
    }

    fn read_bytes(&mut self, n: usize) -> Result<&[u8], irmaseal_core::Error> {
        if self.i >= self.buf.len() {
            return Err(irmaseal_core::Error::EndOfStream);
        }

        let mut end = self.i + n; // Non-inclusive
        if self.buf.len() < end {
            end = self.buf.len();
        }

        let res = &self.buf[self.i..end];
        self.i += n;

        Ok(res)
    }
}
