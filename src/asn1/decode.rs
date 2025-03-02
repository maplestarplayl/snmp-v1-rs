use crate::asn1::encode;
use anyhow::{Context, Result, anyhow};
use bytes::{Buf, Bytes, BytesMut};
use std::error::Error;
use std::fmt;
use std::io::Read;
use std::ops::Index;

#[derive(Debug)]
pub enum Asn1Error {
    InvalidTag(u8),
    InvalidLength,
    InvalidValue,
    UnexpectedEndOfData,
    UnsupportedEncoding,
}

impl fmt::Display for Asn1Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Asn1Error::InvalidTag(tag) => write!(f, "Invalid tag: {}", tag),
            Asn1Error::InvalidLength => write!(f, "Invalid length"),
            Asn1Error::InvalidValue => write!(f, "Invalid value"),
            Asn1Error::UnexpectedEndOfData => write!(f, "Unexpected end of data"),
            Asn1Error::UnsupportedEncoding => write!(f, "Unsupported encoding"),
        }
    }
}

impl Error for Asn1Error {}

pub fn peek_tag(buf: &Bytes) -> Result<u8> {
    if buf.remaining() < 1 {
        return Err(anyhow!("Buffer underflow when peeking tag"));
    }
    Ok(buf[0])
}

pub fn decode_tag(buf: &mut Bytes) -> Result<u8> {
    if buf.remaining() < 1 {
        return Err(anyhow!("Buffer underflow when decoding tag"));
    }
    Ok(buf.get_u8())
}

pub fn decode_length(buf: &mut Bytes) -> Result<usize> {
    if buf.remaining() < 1 {
        return Err(anyhow!("Buffer underflow when decoding length"));
    }

    let first_byte = buf.get_u8();

    if first_byte < 0x80 {
        // Short form
        return Ok(first_byte as usize);
    }

    // Long form
    let num_bytes = first_byte & 0x7F;
    if num_bytes > 4 {
        return Err(anyhow!("Length encoding too large: {} bytes", num_bytes));
    }

    if buf.remaining() < num_bytes as usize {
        return Err(anyhow!("Buffer underflow when decoding long form length"));
    }

    let mut length: usize = 0;
    for _ in 0..num_bytes {
        length = (length << 8) | (buf.get_u8() as usize);
    }

    Ok(length)
}

pub fn decode_sequence(buf: &mut Bytes) -> Result<Bytes> {
    let tag = decode_tag(buf)?;
    if tag != encode::SEQUENCE_TAG
        && tag != encode::GET_REQUEST_TAG
        && tag != encode::GET_NEXT_REQUEST_TAG
        && tag != encode::GET_RESPONSE_TAG
        && tag != encode::SET_REQUEST_TAG
    {
        return Err(anyhow!("Expected SEQUENCE tag, got {}", tag));
    }

    let length = decode_length(buf)?;

    if buf.remaining() < length {
        return Err(anyhow!("Buffer underflow when decoding SEQUENCE content"));
    }

    Ok(buf.split_to(length))
}

pub fn decode_integer(buf: &mut Bytes) -> Result<i32> {
    let tag = decode_tag(buf)?;
    if tag != encode::INTEGER_TAG {
        return Err(anyhow!("Expected INTEGER tag, got {}", tag));
    }

    let length = decode_length(buf)?;

    if length > 4 {
        return Err(anyhow!("INTEGER too large: {} bytes", length));
    }

    if buf.remaining() < length {
        return Err(anyhow!("Buffer underflow when decoding INTEGER content"));
    }

    let mut value: i32 = 0;
    let first_byte = buf.get_u8();

    // Handle sign bit
    if (first_byte & 0x80) != 0 {
        value = -1; // Start with all bits set
    }

    value = (value << 8) | (first_byte as i32);

    // Process remaining bytes
    for _ in 1..length {
        value = (value << 8) | (buf.get_u8() as i32);
    }

    Ok(value)
}

pub fn decode_octet_string(buf: &mut Bytes) -> Result<Vec<u8>> {
    let tag = decode_tag(buf)?;
    if tag != encode::OCTET_STRING_TAG {
        return Err(anyhow!("Expected OCTET STRING tag, got {}", tag));
    }

    let length = decode_length(buf)?;

    if buf.remaining() < length {
        return Err(anyhow!(
            "Buffer underflow when decoding OCTET STRING content"
        ));
    }

    let mut result = vec![0; length];
    buf.copy_to_slice(&mut result);

    Ok(result)
}

pub fn decode_null(buf: &mut Bytes) -> Result<()> {
    let tag = decode_tag(buf)?;
    if tag != encode::NULL_TAG {
        return Err(anyhow!("Expected NULL tag, got {}", tag));
    }

    let length = decode_length(buf)?;
    if length != 0 {
        return Err(anyhow!("NULL should have zero length, got {}", length));
    }

    Ok(())
}

// Decode an OBJECT IDENTIFIER
pub fn decode_oid(buf: &mut Bytes) -> Result<Vec<u32>> {
    let tag = decode_tag(buf)?;
    if tag != encode::OBJECT_IDENTIFIER_TAG {
        return Err(anyhow!("Expected OBJECT IDENTIFIER tag, got {}", tag));
    }
    
    let length = decode_length(buf)?;
    println!("length: {}", length);
    println!("after decode length, buf remaining: {:02x?}", &buf[..]);
    if buf.remaining() < length {
        return Err(anyhow!("Buffer underflow when decoding OBJECT IDENTIFIER content"));
    }
    
    let mut oid_bytes = buf.split_to(length);
    let mut result = Vec::new();
    
    // First byte encodes the first two components
    if oid_bytes.remaining() > 0 {
        let first_byte = oid_bytes.get_u8(); // Properly consume the first byte
        let first = (first_byte / 40) as u32;
        let second = (first_byte % 40) as u32;
        
        result.push(first);
        result.push(second);
    } else {
        return Err(anyhow!("Empty OBJECT IDENTIFIER"));
    }
    
    // Decode remaining components
    while oid_bytes.remaining() > 0 {
        let mut value: u32 = 0;
        let mut byte: u8;
        
        // Each component can span multiple bytes
        loop {
            byte = oid_bytes.get_u8();
            value = (value << 7) | ((byte & 0x7F) as u32);
            
            // If high bit is not set, this is the last byte of this component
            if (byte & 0x80) == 0 {
                break;
            }
        }
        
        result.push(value);
    }
    
    Ok(result)
}
