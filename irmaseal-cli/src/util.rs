use irmaseal_core::{Error, Readable, Writable};
use futures::Sink;
use futures::task::{Context, Poll};
use tokio::macros::support::Pin;
use arrayvec::ArrayVec;
use std::io::Write;

pub struct FileWriter {
    buffer: ArrayVec<[u8; 65536]>,
    os: std::fs::File,
}

impl FileWriter {
    pub fn new(os: std::fs::File) -> FileWriter {
        let buffer = ArrayVec::new();
        FileWriter { buffer, os }
    }
}

impl Writable for FileWriter {
    fn write(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.os.write_all(bytes).unwrap();
        Ok(())
    }
}

impl Sink<u8> for FileWriter {
    type Error = Error;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.buffer.is_full() {
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn start_send(self: Pin<&mut Self>, item: u8) -> Result<(), Self::Error> {
        let mut_self = self.get_mut();
        mut_self.buffer.push(item);
        if mut_self.buffer.is_full() {
            let bytes = mut_self.buffer.as_slice();
            let result = mut_self.os.write(bytes);
            mut_self.buffer.clear();
            match result {
                Ok(_) => Ok(()),
                _ => Err(Error::PrematureEndError)
            }
        } else {
            Ok(())
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let mut_self = self.get_mut();
        let bytes = mut_self.buffer.as_slice();
        let result = mut_self.os.write(bytes);
        mut_self.buffer.clear();
        match result {
            Ok(_) => Poll::Ready(mut_self.os.flush().map_err(|_| Error::PrematureEndError)),
            _ => Poll::Ready(Err(Error::PrematureEndError))
        }
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.poll_flush(_cx)
    }
}

pub struct FileReader {
    is: std::fs::File,
    buf: Vec<u8>,
}

impl FileReader {
    pub fn new(is: std::fs::File) -> FileReader {
        FileReader { is, buf: vec![] }
    }
}

impl Readable for FileReader {
    fn read_byte(&mut self) -> Result<u8, Error> {
        Ok(self.read_bytes(1)?[0])
    }

    fn read_bytes(&mut self, n: usize) -> Result<&[u8], Error> {
        use std::io::Read;

        if self.buf.len() < n {
            self.buf.resize(n, 0u8);
        }

        let dst = &mut self.buf.as_mut_slice()[0..n];
        let len = self.is.read(dst).unwrap();

        Ok(&dst[0..len])
    }
}
