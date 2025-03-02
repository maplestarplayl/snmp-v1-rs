use bytes::{BufMut, BytesMut};

// ASN.1 BER tag constants
pub const INTEGER_TAG: u8 = 0x02;
pub const OCTET_STRING_TAG: u8 = 0x04;
pub const NULL_TAG: u8 = 0x05;
pub const OBJECT_IDENTIFIER_TAG: u8 = 0x06;
pub const SEQUENCE_TAG: u8 = 0x33;
pub const GET_REQUEST_TAG: u8 = 0xA0;
pub const GET_RESPONSE_TAG: u8 = 0xA2;
pub const GET_NEXT_REQUEST_TAG: u8 = 0xA1;
pub const SET_REQUEST_TAG: u8 = 0xA3;
// use Definite Form
fn encode_length(len: usize, buf: &mut BytesMut) {
    if len <= 128 {
        //short form - one byte
        buf.put_u8(len as u8);
    } else {
        //long form - mutiple bytes
        let mut bytes = Vec::new();
        let mut temp_len = len;

        while temp_len > 0 {
            bytes.push((temp_len & 0xFF) as u8);
            temp_len >>= 8;
        }

        buf.put_u8(0x80 | bytes.len() as u8);

        for i in bytes.iter().rev() {
            buf.put_u8(*i);
        }
    }
}
/// Encodes an ASN.1 INTEGER into the buffer
pub fn encode_integer(value: i32, buf: &mut BytesMut) {
    buf.put_u8(INTEGER_TAG);

    let mut temp = value;
    let mut len = 1;

    while (temp > 127) || (temp < -128) {
        temp >>= 8;
        len += 1;
    }

    encode_length(len, buf);

    for i in (0..len).rev() {
        let shift = i * 8;
        buf.put_u8(((value >> shift) & 0xFF) as u8);
    }
}

pub fn encode_octet_string(data: &[u8], buf: &mut BytesMut) {
    buf.put_u8(OCTET_STRING_TAG);
    encode_length(data.len(), buf);
    buf.put_slice(data);
}

pub fn encode_null(buf: &mut BytesMut) {
    buf.put_u8(NULL_TAG);
    buf.put_u8(0x00);
}

/// Encodes content as an ASN.1 sequence with the given tag.
/// 
/// This function writes a tag byte, encodes the length of the content,
/// and then appends the content itself to the buffer. It is designed to
/// handle ASN.1 encoding for sequences, which are commonly used in protocols
/// like SNMP.
/// 
/// # Arguments
/// 
/// * `content` - A slice of bytes representing the content to be encoded.
/// * `tag` - The ASN.1 tag to be used for the sequence.
/// * `buf` - A mutable reference to a `BytesMut` buffer where the encoded
///   sequence will be written.
pub fn encode_sequence(content: &[u8], tag: u8, buf: &mut BytesMut) {
    buf.put_u8(tag);
    println!("{:02x?}",&buf[..]);

    encode_length(content.len(), buf);
    println!("{:02x?}",&buf[..]);

    buf.put_slice(content);
    println!("{:02x?}",&buf[..]);
}

pub fn encode_oid(oid: &[u32], buf: &mut BytesMut) {
    println!("oid: {:?}", oid);
    buf.put_u8(OBJECT_IDENTIFIER_TAG);

    let mut oid_buf = BytesMut::new();

    if oid.len() >= 2 {
        oid_buf.put_u8((40 * oid[0] + oid[1]) as u8);
    }

    for &num in oid.iter().skip(2) {
        if num < 128 {
            oid_buf.put_u8(num as u8);
        } else {
            let mut bytes = Vec::new();
            let mut temp = num;
            bytes.push((temp & 0x7F) as u8);
            temp >>= 7;

            while temp > 0 {
                bytes.push(((temp & 0x7F) | 0x80) as u8);
                temp >>= 7;
            }

            for b in bytes.iter().rev() {
                oid_buf.put_u8(*b);
            }
        }
    }
    //TODO:check if always correct
    encode_length(oid.len() - 1, buf);
    buf.put_slice(&oid_buf);
}
