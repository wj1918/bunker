//! HTTP body utilities.
//!
//! This replaces http-body-util with minimal implementations of:
//! - BoxBody: Type-erased body
//! - Empty: Body with no data
//! - Full: Body from a single Bytes chunk
//! - BodyExt: Extension trait for Body

use bytes::Buf;
use hyper::body::{Body, Frame};
use std::pin::Pin;
use std::task::{Context, Poll};

/// A type-erased HTTP body.
pub struct BoxBody<D, E> {
    inner: Pin<Box<dyn Body<Data = D, Error = E> + Send + 'static>>,
}

impl<D, E> BoxBody<D, E> {
    /// Create a new BoxBody from a body.
    pub fn new<B>(body: B) -> Self
    where
        B: Body<Data = D, Error = E> + Send + 'static,
        D: Buf,
    {
        BoxBody {
            inner: Box::pin(body),
        }
    }
}

impl<D: Buf, E> Body for BoxBody<D, E> {
    type Data = D;
    type Error = E;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.inner.as_mut().poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

/// An empty HTTP body.
#[derive(Debug, Clone, Copy, Default)]
pub struct Empty<D> {
    _marker: std::marker::PhantomData<fn() -> D>,
}

impl<D> Empty<D> {
    /// Create a new empty body.
    pub fn new() -> Self {
        Empty {
            _marker: std::marker::PhantomData,
        }
    }
}

impl<D: Buf + Send + 'static> Body for Empty<D> {
    type Data = D;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(None)
    }

    fn is_end_stream(&self) -> bool {
        true
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        hyper::body::SizeHint::with_exact(0)
    }
}

/// A body that contains a single chunk of Bytes.
#[derive(Debug, Clone)]
pub struct Full<D> {
    data: Option<D>,
}

impl<D> Full<D> {
    /// Create a new Full body from data.
    pub fn new(data: D) -> Self {
        Full { data: Some(data) }
    }
}

impl<D> Unpin for Full<D> {}

impl<D: Buf + Send + 'static> Body for Full<D> {
    type Data = D;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.get_mut().data.take() {
            Some(data) => Poll::Ready(Some(Ok(Frame::data(data)))),
            None => Poll::Ready(None),
        }
    }

    fn is_end_stream(&self) -> bool {
        self.data.is_none()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        match &self.data {
            Some(data) => hyper::body::SizeHint::with_exact(data.remaining() as u64),
            None => hyper::body::SizeHint::with_exact(0),
        }
    }
}

/// Extension trait for Body types.
#[allow(dead_code)]
pub trait BodyExt: Body {
    /// Convert this body into a BoxBody.
    fn boxed(self) -> BoxBody<Self::Data, Self::Error>
    where
        Self: Sized + Send + 'static,
    {
        BoxBody::new(self)
    }

    /// Map the error type of this body.
    fn map_err<F, E>(self, f: F) -> MapErr<Self, F>
    where
        Self: Sized,
        F: FnMut(Self::Error) -> E,
    {
        MapErr { inner: self, f }
    }

    /// Limit the body to a maximum number of bytes.
    /// Returns LimitExceeded error if the limit is exceeded.
    fn limited(self, limit: u64) -> Limited<Self>
    where
        Self: Sized,
    {
        Limited::new(self, limit)
    }
}

impl<T: Body> BodyExt for T {}

/// Body adapter that maps the error type.
pub struct MapErr<B, F> {
    inner: B,
    f: F,
}

impl<B: Unpin, F> Unpin for MapErr<B, F> {}

impl<B, F, E> Body for MapErr<B, F>
where
    B: Body + Unpin,
    F: FnMut(B::Error) -> E,
{
    type Data = B::Data;
    type Error = E;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => Poll::Ready(Some(Ok(frame))),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err((self.f)(e)))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

/// Error returned when body size limit is exceeded.
#[derive(Debug)]
#[allow(dead_code)]
pub struct LimitExceeded {
    pub limit: u64,
}

impl std::fmt::Display for LimitExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "body size limit exceeded: {} bytes", self.limit)
    }
}

impl std::error::Error for LimitExceeded {}

/// Body adapter that limits the number of bytes read.
#[allow(dead_code)]
pub struct Limited<B> {
    inner: B,
    remaining: u64,
    limit: u64,
}

impl<B> Limited<B> {
    /// Create a new Limited body with the given byte limit.
    pub fn new(inner: B, limit: u64) -> Self {
        Limited {
            inner,
            remaining: limit,
            limit,
        }
    }
}

impl<B: Unpin> Unpin for Limited<B> {}

impl<B> Body for Limited<B>
where
    B: Body + Unpin,
    B::Data: Buf,
{
    type Data = B::Data;
    type Error = LimitedError<B::Error>;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    let len = data.remaining() as u64;
                    if len > self.remaining {
                        return Poll::Ready(Some(Err(LimitedError::LimitExceeded(
                            LimitExceeded { limit: self.limit },
                        ))));
                    }
                    self.remaining -= len;
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(LimitedError::Inner(e)))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        let inner = self.inner.size_hint();
        let lower = std::cmp::min(inner.lower(), self.remaining);
        let upper = inner.upper().map(|u| std::cmp::min(u, self.remaining));

        let mut hint = hyper::body::SizeHint::new();
        hint.set_lower(lower);
        if let Some(u) = upper {
            hint.set_upper(u);
        }
        hint
    }
}

/// Error type for Limited body - either limit exceeded or inner body error.
#[derive(Debug)]
#[allow(dead_code)]
pub enum LimitedError<E> {
    LimitExceeded(LimitExceeded),
    Inner(E),
}

impl<E: std::fmt::Display> std::fmt::Display for LimitedError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LimitedError::LimitExceeded(e) => write!(f, "{}", e),
            LimitedError::Inner(e) => write!(f, "{}", e),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for LimitedError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            LimitedError::LimitExceeded(e) => Some(e),
            LimitedError::Inner(e) => Some(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    #[allow(unused_imports)]
    use hyper::body::Frame;

    #[test]
    fn test_empty_is_end_stream() {
        let body: Empty<Bytes> = Empty::new();
        assert!(body.is_end_stream());
    }

    #[test]
    fn test_empty_size_hint() {
        let body: Empty<Bytes> = Empty::new();
        let hint = body.size_hint();
        assert_eq!(hint.lower(), 0);
        assert_eq!(hint.upper(), Some(0));
    }

    #[test]
    fn test_full_size_hint() {
        let data = Bytes::from("hello");
        let body = Full::new(data);
        let hint = body.size_hint();
        assert_eq!(hint.lower(), 5);
        assert_eq!(hint.upper(), Some(5));
    }

    #[test]
    fn test_full_is_end_stream() {
        let data = Bytes::from("hello");
        let body = Full::new(data);
        assert!(!body.is_end_stream());
    }

    #[test]
    fn test_full_after_consumed() {
        let data = Bytes::from("hello");
        let mut body = Full::new(data);
        body.data.take(); // Simulate consumption
        assert!(body.is_end_stream());
    }

    #[tokio::test]
    async fn test_empty_poll() {
        use std::future::poll_fn;

        let mut body: Empty<Bytes> = Empty::new();
        let result: Option<Result<Frame<Bytes>, std::convert::Infallible>> =
            poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_full_poll() {
        use std::future::poll_fn;

        let mut body = Full::new(Bytes::from("hello"));

        // First poll should return data
        let result: Option<Result<Frame<Bytes>, std::convert::Infallible>> =
            poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await;
        assert!(result.is_some());
        let frame = result.unwrap().unwrap();
        assert!(frame.is_data());

        // Second poll should return None
        let result: Option<Result<Frame<Bytes>, std::convert::Infallible>> =
            poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await;
        assert!(result.is_none());
    }

    #[test]
    fn test_boxed() {
        let body = Full::new(Bytes::from("hello"));
        let _boxed: BoxBody<Bytes, std::convert::Infallible> = body.boxed();
    }

    #[test]
    fn test_limited_within_limit() {
        let body = Full::new(Bytes::from("hello"));
        let limited = body.limited(10); // 10 bytes limit, body is 5 bytes
        assert!(!limited.is_end_stream());
    }

    #[test]
    fn test_limited_size_hint() {
        let body = Full::new(Bytes::from("hello world")); // 11 bytes
        let limited = body.limited(5); // 5 byte limit
        let hint = limited.size_hint();
        // Upper bound should be clamped to limit
        assert_eq!(hint.upper(), Some(5));
    }

    #[tokio::test]
    async fn test_limited_exceeds_limit() {
        use std::future::poll_fn;

        let body = Full::new(Bytes::from("hello world")); // 11 bytes
        let mut limited = body.limited(5); // 5 byte limit

        let result = poll_fn(|cx| Pin::new(&mut limited).poll_frame(cx)).await;
        assert!(result.is_some());
        let err = result.unwrap();
        assert!(err.is_err());
        match err.unwrap_err() {
            LimitedError::LimitExceeded(e) => assert_eq!(e.limit, 5),
            _ => panic!("Expected LimitExceeded error"),
        }
    }

    #[tokio::test]
    async fn test_limited_within_limit_poll() {
        use std::future::poll_fn;

        let body = Full::new(Bytes::from("hi")); // 2 bytes
        let mut limited = body.limited(10); // 10 byte limit

        // First poll should return data
        let result = poll_fn(|cx| Pin::new(&mut limited).poll_frame(cx)).await;
        assert!(result.is_some());
        let frame = result.unwrap().unwrap();
        assert!(frame.is_data());

        // Second poll should return None (end of stream)
        let result = poll_fn(|cx| Pin::new(&mut limited).poll_frame(cx)).await;
        assert!(result.is_none());
    }

    #[test]
    fn test_limit_exceeded_display() {
        let err = LimitExceeded { limit: 1024 };
        assert_eq!(format!("{}", err), "body size limit exceeded: 1024 bytes");
    }
}
