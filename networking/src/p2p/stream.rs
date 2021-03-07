// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

//! This module encapsulates p2p communication between peers.
//!
//! It provides message packaging from/to binary format, encryption, message nonce handling.

use std::{convert::TryInto, io, pin::Pin, task::Poll};

use bytes::Buf;
use failure::_core::time::Duration;
use failure::{Error, Fail};
use slog::{trace, FnValue, Logger};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf};
use tokio::net::TcpStream;

use crypto::crypto_box::PrecomputedKey;
use crypto::nonce::Nonce;
use crypto::CryptoError;
use tezos_encoding::{binary_reader::BinaryReaderError, binary_writer::BinaryWriterError};
use tezos_messages::p2p::binary_message::{
    BinaryChunk, BinaryChunkError, BinaryMessage, CONTENT_LENGTH_FIELD_BYTES,
};

/// Max allowed content length in bytes when taking into account extra data added by encryption
pub const CONTENT_LENGTH_MAX: usize =
    tezos_messages::p2p::binary_message::CONTENT_LENGTH_MAX - crypto::crypto_box::BOX_ZERO_BYTES;

/// This is common error that might happen when communicating with peer over the network.
#[derive(Debug, Fail)]
pub enum StreamError {
    #[fail(display = "Failed to encrypt message")]
    FailedToEncryptMessage { error: CryptoError },
    #[fail(display = "Failed to decrypt message")]
    FailedToDecryptMessage { error: CryptoError },
    #[fail(display = "Message serialization error: {}", error)]
    SerializationError { error: BinaryWriterError },
    #[fail(display = "Message de-serialization error: {}", error)]
    DeserializationError { error: BinaryReaderError },
    #[fail(display = "Network error: {}, cause: {}", message, error)]
    NetworkError { message: &'static str, error: Error },
}

impl From<BinaryWriterError> for StreamError {
    fn from(error: BinaryWriterError) -> Self {
        StreamError::SerializationError { error }
    }
}

impl From<std::io::Error> for StreamError {
    fn from(error: std::io::Error) -> Self {
        StreamError::NetworkError {
            error: error.into(),
            message: "Stream error",
        }
    }
}

impl From<BinaryChunkError> for StreamError {
    fn from(error: BinaryChunkError) -> Self {
        StreamError::NetworkError {
            error: error.into(),
            message: "Binary chunk error",
        }
    }
}

impl From<BinaryReaderError> for StreamError {
    fn from(error: BinaryReaderError) -> Self {
        StreamError::DeserializationError { error }
    }
}

impl slog::Value for StreamError {
    fn serialize(
        &self,
        _record: &slog::Record,
        key: slog::Key,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        serializer.emit_arguments(key, &format_args!("{}", self))
    }
}

/// Holds read and write parts of the message stream.
pub struct MessageStream {
    reader: ReadHalf<TcpStream>,
    writer: MessageWriter,
}

impl MessageStream {
    fn new(stream: TcpStream) -> MessageStream {
        let _ = stream.set_linger(Some(Duration::from_secs(2)));
        let _ = stream.set_nodelay(true);

        let (rx, tx) = tokio::io::split(stream);
        MessageStream {
            reader: rx,
            writer: MessageWriter { stream: tx },
        }
    }

    #[inline]
    pub fn split(self) -> (ReadHalf<TcpStream>, MessageWriter) {
        (self.reader, self.writer)
    }
}

impl From<TcpStream> for MessageStream {
    fn from(stream: TcpStream) -> Self {
        MessageStream::new(stream)
    }
}

/// Reader of the TCP/IP connection.
pub struct MessageReader {
    /// reader part or the TCP/IP network stream
    stream: ReadHalf<TcpStream>,
}

impl MessageReader {
    /// Read message from network and return message contents in a form of bytes.
    /// Each message is prefixed by a 2 bytes indicating total length of the message.
    pub async fn read_message(&mut self) -> Result<BinaryChunk, StreamError> {
        // read encoding length (2 bytes)
        let msg_len_bytes = self.read_message_length_bytes().await?;
        // copy bytes containing encoding length to`` raw encoding buffer
        let mut all_recv_bytes = vec![];
        all_recv_bytes.extend(&msg_len_bytes);

        // read the message contents
        let msg_len = (&msg_len_bytes[..]).get_u16() as usize;
        let mut msg_content_bytes = vec![0u8; msg_len];
        self.stream.read_exact(&mut msg_content_bytes).await?;
        all_recv_bytes.extend(&msg_content_bytes);

        Ok(all_recv_bytes.try_into()?)
    }

    /// Read 2 bytes containing total length of the message contents from the network stream.
    /// Total length is encoded as u big endian u16.
    async fn read_message_length_bytes(&mut self) -> io::Result<[u8; CONTENT_LENGTH_FIELD_BYTES]> {
        let mut msg_len_bytes: [u8; CONTENT_LENGTH_FIELD_BYTES] = [0; CONTENT_LENGTH_FIELD_BYTES];
        self.stream.read_exact(&mut msg_len_bytes).await?;
        Ok(msg_len_bytes)
    }
}

pub struct MessageWriter {
    stream: WriteHalf<TcpStream>,
}

impl MessageWriter {
    /// Construct and write message to network stream.
    ///
    /// # Arguments
    /// * `bytes` - A message contents represented ab bytes
    ///
    /// In case all bytes are successfully written to network stream a raw binary
    /// message is returned as a result.
    #[inline]
    pub async fn write_message(&mut self, bytes: &BinaryChunk) -> Result<(), StreamError> {
        Ok(self.stream.write_all(bytes.raw()).await?)
    }
}

/// The `EncryptedMessageWriter` encapsulates process of the encrypted outgoing message transmission.
/// This process involves (not only) nonce increment, encryption and network transmission.
pub struct EncryptedMessageWriter {
    /// Precomputed key is created from merge of peer public key and our secret key.
    /// It's used to speedup of crypto operations.
    precomputed_key: PrecomputedKey,
    /// Nonce used to encrypt outgoing messages
    nonce_local: Nonce,
    /// Outgoing message writer
    tx: MessageWriter,
    /// Logger
    log: Logger,
}

impl EncryptedMessageWriter {
    pub fn new(
        tx: MessageWriter,
        precomputed_key: PrecomputedKey,
        nonce_local: Nonce,
        log: Logger,
    ) -> Self {
        EncryptedMessageWriter {
            tx,
            precomputed_key,
            nonce_local,
            log,
        }
    }

    pub async fn write_message<'a>(
        &'a mut self,
        message: &'a impl BinaryMessage,
    ) -> Result<(), StreamError> {
        let message_bytes = message.as_bytes()?;
        trace!(self.log, "Writing message"; "message" => FnValue(|_| hex::encode(&message_bytes)));

        for chunk_content_bytes in message_bytes.chunks(CONTENT_LENGTH_MAX) {
            // encrypt
            let nonce = self.nonce_fetch_increment();
            let message_bytes_encrypted =
                match self.precomputed_key.encrypt(chunk_content_bytes, &nonce) {
                    Ok(msg) => msg,
                    Err(error) => return Err(StreamError::FailedToEncryptMessage { error }),
                };

            // send
            let chunk = BinaryChunk::from_content(&message_bytes_encrypted)?;
            self.tx.write_message(&chunk).await?;
        }

        Ok(())
    }

    #[inline]
    fn nonce_fetch_increment(&mut self) -> Nonce {
        let incremented = self.nonce_local.increment();
        std::mem::replace(&mut self.nonce_local, incremented)
    }
}

/// The `MessageReceiver` encapsulates process of the encrypted incoming message transmission.
/// This process involves (not only) nonce increment, encryption and network transmission.
pub struct EncryptedMessageReader {
    /// Precomputed key is created from merge of peer public key and our secret key.
    /// It's used to speedup of crypto operations.
    /// Nonce used to decrypt received messages
    crypt_data: Option<CryptData>,
    /// Incoming message reader
    read: ReadHalf<TcpStream>,
    /// Chunk size buffer
    size_buffer: [u8; 2],
    /// Chunk data buffer
    data_buffer: Vec<u8>,
    /// Async read state
    state: ReadState,
    /// Logger
    log: Logger,
}

impl EncryptedMessageReader {
    /// Create new encrypted message from async reader and peer data
    pub fn new(read: ReadHalf<TcpStream>, log: Logger) -> Self {
        EncryptedMessageReader {
            read,
            crypt_data: None,
            size_buffer: [0; 2],
            data_buffer: vec![0; u16::MAX as usize],
            state: ReadState::ReadSize { offset: 0 },
            log,
        }
    }

    pub async fn read_connection_message(&mut self) -> Result<BinaryChunk, StreamError> {
        let mut buf = vec![];
        self.read_to_end(&mut buf).await?;
        Ok(buf.try_into()?)
    }

    pub fn set_crypt_data(&mut self, precomputed_key: PrecomputedKey, nonce_remote: Nonce) {
        self.crypt_data = Some(CryptData {
            precomputed_key,
            nonce_remote,
        });
    }

    /// Consume content of inner message reader into specific message
    pub async fn read_message<M>(&mut self) -> Result<M, StreamError>
    where
        M: BinaryMessage,
    {
        let message = M::async_read(self).await?;
        Ok(message)
    }

    pub fn unsplit(self, tx: EncryptedMessageWriter) -> TcpStream {
        self.read.unsplit(tx.tx.stream)
    }
}

enum ReadState {
    ReadSize { offset: usize },
    ReadData { size: usize, offset: usize },
    DataAvail { size: usize, offset: usize },
}

struct CryptData {
    precomputed_key: PrecomputedKey,
    nonce_remote: Nonce,
}

impl CryptData {
    fn fetch_increment_nonce(&mut self) -> Nonce {
        let nonce = self.nonce_remote.increment();
        std::mem::replace(&mut self.nonce_remote, nonce)
    }
}

use tokio::io::AsyncRead;

impl AsyncRead for EncryptedMessageReader {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let me = &mut *self;
        loop {
            match me.state {
                ReadState::ReadSize { offset } => {
                    let mut buff = ReadBuf::new(&mut me.size_buffer[offset..]);
                    let rem = buff.remaining();
                    match Pin::new(&mut me.read).poll_read(cx, &mut buff) {
                        Poll::Ready(_) => (),
                        Poll::Pending => return Poll::Pending,
                    }
                    if rem == buff.remaining() {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "eof reading chunk size",
                        ))
                        .into();
                    }
                    me.state = if buff.remaining() == 0 {
                        ReadState::ReadData {
                            size: u16::from_be_bytes(me.size_buffer) as usize,
                            offset: 0,
                        }
                    } else {
                        ReadState::ReadSize {
                            offset: offset + buff.remaining() - rem,
                        }
                    };
                }
                ReadState::ReadData { size, offset } => {
                    let mut buff = ReadBuf::new(&mut me.data_buffer.as_mut_slice()[offset..size]);
                    let rem = buff.remaining();
                    match Pin::new(&mut me.read).poll_read(cx, &mut buff) {
                        Poll::Ready(_) => (),
                        Poll::Pending => return Poll::Pending,
                    }
                    if rem == buff.remaining() {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "eof reading chunk data",
                        ))
                        .into();
                    }
                    me.state = if buff.remaining() == 0 {
                        if let Some(ref mut crypt_data) = me.crypt_data {
                            let nonce = crypt_data.fetch_increment_nonce();
                            match crypt_data
                                .precomputed_key
                                .decrypt(me.data_buffer.as_slice(), &nonce)
                            {
                                Ok(message_decrypted) => {
                                    trace!(me.log, "Message received"; "message" => FnValue(|_| hex::encode(&message_decrypted)));
                                    me.data_buffer.copy_from_slice(&message_decrypted);
                                    ReadState::DataAvail { size, offset: 0 }
                                }
                                Err(error) => {
                                    return Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        format!("error decryping a chunk: {}", error),
                                    ))
                                    .into();
                                }
                            }
                        } else {
                            ReadState::DataAvail { size, offset: 0 }
                        }
                    } else {
                        ReadState::ReadData {
                            size,
                            offset: offset + buff.remaining() - rem,
                        }
                    };
                }
                ReadState::DataAvail { size, offset } => {
                    let amt = std::cmp::min(size - offset, buf.remaining());
                    let (a, _) = me.data_buffer.as_slice().split_at(amt);
                    buf.put_slice(a);
                    me.state = if amt < size - offset {
                        ReadState::DataAvail {
                            size,
                            offset: offset + amt,
                        }
                    } else if me.crypt_data.is_some() {
                        // we should continue to the next chunk
                        ReadState::ReadSize { offset: 0 }
                    } else {
                        ReadState::DataAvail { size, offset: size }
                    };
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}
