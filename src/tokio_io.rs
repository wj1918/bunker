//! TokioIo adapter between tokio and hyper IO traits.
//!
//! This replaces hyper_util::rt::TokioIo with a minimal implementation.
//!
//! It provides bidirectional adaptation:
//! 1. Tokio AsyncRead/AsyncWrite -> Hyper Read/Write (for TcpStream, TLS streams)
//! 2. Hyper Read/Write -> Tokio AsyncRead/AsyncWrite (for Upgraded connections)

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use hyper::rt::{Read, ReadBufCursor, Write};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Adapter that bridges tokio and hyper IO traits.
///
/// For types that implement tokio's AsyncRead/AsyncWrite (like TcpStream),
/// this implements hyper's Read/Write.
///
/// For types that implement hyper's Read/Write (like Upgraded),
/// this implements tokio's AsyncRead/AsyncWrite.
#[derive(Debug)]
pub struct TokioIo<T> {
    inner: T,
}

impl<T> TokioIo<T> {
    /// Create a new TokioIo wrapping an inner type.
    pub fn new(inner: T) -> Self {
        TokioIo { inner }
    }

    /// Get a reference to the inner type.
    #[allow(dead_code)]
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// Get a mutable reference to the inner type.
    #[allow(dead_code)]
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Consume this adapter and return the inner type.
    #[allow(dead_code)]
    pub fn into_inner(self) -> T {
        self.inner
    }
}

// ============================================================================
// Direction 1: Tokio AsyncRead/AsyncWrite -> Hyper Read/Write
// Used for: TcpStream, TLS streams wrapped with TokioIo for use with hyper
// ============================================================================

impl<T: AsyncRead + Unpin> Read for TokioIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        // SAFETY: We guarantee that the bytes written to unfilled are initialized
        // before we call assume_init.
        let unfilled = unsafe { buf.as_mut() };
        let mut read_buf = ReadBuf::uninit(unfilled);

        match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                let filled = read_buf.filled().len();
                // SAFETY: We just filled these bytes via poll_read
                unsafe {
                    buf.advance(filled);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T: AsyncWrite + Unpin> Write for TokioIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ============================================================================
// Direction 2: Hyper Read/Write -> Tokio AsyncRead/AsyncWrite
// Used for: hyper::upgrade::Upgraded wrapped with TokioIo for tokio::io::copy
// ============================================================================

impl<T: Read + Unpin> AsyncRead for TokioIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        tbuf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let filled = tbuf.filled().len();
        let sub_filled = unsafe {
            // Create a hyper ReadBuf from the unfilled portion
            let mut buf = hyper::rt::ReadBuf::uninit(tbuf.unfilled_mut());

            match Read::poll_read(Pin::new(&mut self.inner), cx, buf.unfilled()) {
                Poll::Ready(Ok(())) => buf.filled().len(),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        };

        let n_filled = filled + sub_filled;
        let n_init = sub_filled;
        unsafe {
            tbuf.assume_init(n_init);
            tbuf.set_filled(n_filled);
        }

        Poll::Ready(Ok(()))
    }
}

impl<T: Write + Unpin> AsyncWrite for TokioIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Write::poll_write(Pin::new(&mut self.inner), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Write::poll_flush(Pin::new(&mut self.inner), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Write::poll_shutdown(Pin::new(&mut self.inner), cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tokio_io_new() {
        let data = std::io::Cursor::new(vec![1, 2, 3]);
        let io = TokioIo::new(data);
        assert_eq!(io.inner().get_ref(), &[1, 2, 3]);
    }

    #[test]
    fn test_tokio_io_inner_mut() {
        let data = std::io::Cursor::new(vec![1, 2, 3]);
        let mut io = TokioIo::new(data);
        io.inner_mut().set_position(2);
        assert_eq!(io.inner().position(), 2);
    }

    #[test]
    fn test_tokio_io_into_inner() {
        let data = std::io::Cursor::new(vec![1, 2, 3]);
        let io = TokioIo::new(data);
        let inner = io.into_inner();
        assert_eq!(inner.get_ref(), &[1, 2, 3]);
    }
}
