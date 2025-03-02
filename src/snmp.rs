use crate::asn1::{decode, encode};
use anyhow::{Context, Result, anyhow};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;

pub const SNMP_VERSION_1: u8 = 0x00;

#[derive(Debug)]
pub enum PduType {
    GET_REQUEST,
    GET_RESPONSE,
    GET_NEXT_REQUEST,
    SET_REQUEST,
}

#[derive(Debug)]
pub enum SnmpError {
    InvalidVersion,
    InvalidPdu,
    InvalidVarbind,
    UnsupportedOperation,
    NoSuchObject,
    GenError,
}

impl fmt::Display for SnmpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SnmpError::InvalidVersion => write!(f, "Invalid SNMP version"),
            SnmpError::InvalidPdu => write!(f, "Invalid PDU"),
            SnmpError::InvalidVarbind => write!(f, "Invalid varbind"),
            SnmpError::UnsupportedOperation => write!(f, "Unsupported operation"),
            SnmpError::NoSuchObject => write!(f, "No such object"),
            SnmpError::GenError => write!(f, "General error"),
        }
    }
}

impl std::error::Error for SnmpError {}

impl PduType {
    pub fn to_tag(&self) -> u8 {
        match self {
            PduType::GET_REQUEST => encode::GET_REQUEST_TAG,
            PduType::GET_RESPONSE => encode::GET_RESPONSE_TAG,
            PduType::GET_NEXT_REQUEST => encode::GET_NEXT_REQUEST_TAG,
            PduType::SET_REQUEST => encode::SET_REQUEST_TAG,
        }
    }
}

pub fn build_varbind(oid: &[u32], buf: &mut BytesMut) {
    let mut varbind_buf = BytesMut::new();

    encode::encode_oid(oid, &mut varbind_buf);
    println!("OID: {:?}", oid);
    println!("OID encoded: {:02x?}", &varbind_buf[..]);

    encode::encode_null(&mut varbind_buf);
    println!("NULL encoded: {:02x?}", &varbind_buf[..]);

    encode::encode_sequence(&varbind_buf, encode::SEQUENCE_TAG, buf);
    println!("Varbind encoded: {:02x?}", &buf[..]);
}

pub fn build_varbind_list(oids: &[&[u32]], buf: &mut BytesMut) {
    let mut varbind_list_buf = BytesMut::new();
    for oid in oids {
        build_varbind(oid, &mut varbind_list_buf);
    }

    encode::encode_sequence(&varbind_list_buf, encode::SEQUENCE_TAG, buf);
}

pub fn build_pdu(
    request_id: i32,
    error_status: i32,
    error_index: i32,
    varbind_list: &[u8],
    pdu_type: PduType,
    buf: &mut BytesMut,
) {
    let mut pdu_buf = BytesMut::new();

    encode::encode_integer(request_id, &mut pdu_buf);

    encode::encode_integer(error_status, &mut pdu_buf);

    encode::encode_integer(error_index, &mut pdu_buf);

    pdu_buf.put_slice(varbind_list);

    encode::encode_sequence(&pdu_buf, pdu_type.to_tag(), buf);
}

pub fn build_snmp_msg(community: &str, pdu: &[u8], buf: &mut BytesMut) {
    let mut msg_buf = BytesMut::new();

    encode::encode_integer(SNMP_VERSION_1 as i32, &mut msg_buf);

    encode::encode_octet_string(community.as_bytes(), &mut msg_buf);

    msg_buf.put_slice(pdu);

    encode::encode_sequence(&msg_buf, encode::SEQUENCE_TAG, buf);
}

#[derive(Debug, Clone)]
pub enum SnmpValue {
    Integer(i32),
    OctetString(Vec<u8>),
    Null,
    ObjectIdentifier(Vec<u32>),
}

#[derive(Debug, Clone)]
pub struct Varbind {
    pub oid: Vec<u32>,
    pub value: SnmpValue,
}

#[derive(Debug)]
pub struct SnmpPdu {
    pub pdu_type: PduType,
    pub request_id: i32,
    pub error_status: i32,
    pub error_index: i32,
    pub varbinds: Vec<Varbind>,
}

#[derive(Debug)]
pub struct SnmpMessage {
    pub version: i32,
    pub community: Vec<u8>,
    pub pdu: SnmpPdu,
}

pub fn decode_varbind(buf: &mut Bytes) -> Result<Varbind> {
    let mut seq_data = decode::decode_sequence(buf)
        .map_err(|e| anyhow!("Failed to decode varbind sequence: {}", e))?;
    println!("Remaining varbind data: {:02x?}", &seq_data[..]);
    let oid =
        decode::decode_oid(&mut seq_data).map_err(|e| anyhow!("Failed to decode OID: {}", e))?;
    println!("remaining bytes after OID: {:02x?}", &seq_data[..]);
    let tag = decode::peek_tag(&mut seq_data).map_err(|e| anyhow!("Failed to peek tag: {}", e))?;
    println!("tag: {:?}", tag);
    let value = match tag {
        encode::INTEGER_TAG => {
            let val = decode::decode_integer(&mut seq_data)
                .map_err(|e| anyhow!("Failed to decode integer: {}", e))?;
            SnmpValue::Integer(val)
        }
        encode::OCTET_STRING_TAG => {
            let val = decode::decode_octet_string(&mut seq_data)
                .map_err(|e| anyhow!("Failed to decode octet string: {}", e))?;
            SnmpValue::OctetString(val)
        }
        encode::NULL_TAG => {
            decode::decode_null(&mut seq_data)
                .map_err(|e| anyhow!("Failed to decode null: {}", e))?;
            SnmpValue::Null
        }
        encode::OBJECT_IDENTIFIER_TAG => {
            let val = decode::decode_oid(&mut seq_data)
                .map_err(|e| anyhow!("Failed to decode OID value: {}", e))?;
            SnmpValue::ObjectIdentifier(val)
        }
        _ => return Err(anyhow!("Invalid varbind value tag: {}", tag)),
    };

    Ok(Varbind { oid, value })
}

pub fn decode_varbind_list(buf: &mut Bytes) -> Result<Vec<Varbind>> {
    let mut seq_data = decode::decode_sequence(buf)
        .map_err(|e| anyhow!("Failed to decode varbind list sequence: {}", e))?;

    let mut varbinds = Vec::new();
    println!("Remaining varbind list data: {:02x?}", &seq_data[..]);
    while seq_data.remaining() > 0 {
        varbinds.push(decode_varbind(&mut seq_data)?);
    }

    Ok(varbinds)
}

pub fn decode_pdu(buf: &mut Bytes) -> Result<SnmpPdu> {
    println!("Decoding PDU...");
    let tag = decode::peek_tag(buf).map_err(|e| anyhow!("Failed to peek PDU tag: {}", e))?;

    let pdu_type = match tag {
        encode::GET_REQUEST_TAG => PduType::GET_REQUEST,
        encode::GET_NEXT_REQUEST_TAG => PduType::GET_NEXT_REQUEST,
        encode::GET_RESPONSE_TAG => PduType::GET_RESPONSE,
        encode::SET_REQUEST_TAG => PduType::SET_REQUEST,
        _ => return Err(anyhow!("Invalid PDU tag: {}", tag)),
    };

    let mut pdu_data = decode::decode_sequence(buf)
        .map_err(|e| anyhow!("Failed to decode PDU sequence: {}", e))?;

    let request_id = decode::decode_integer(&mut pdu_data)
        .map_err(|e| anyhow!("Failed to decode request ID: {}", e))?;

    let error_status = decode::decode_integer(&mut pdu_data)
        .map_err(|e| anyhow!("Failed to decode error status: {}", e))?;

    let error_index = decode::decode_integer(&mut pdu_data)
        .map_err(|e| anyhow!("Failed to decode error index: {}", e))?;

    println!("Remaining undecoded varbinds: {:02x?}", &pdu_data[..]);
    let varbinds = decode_varbind_list(&mut pdu_data)?;
    Ok(SnmpPdu {
        pdu_type,
        request_id,
        error_status,
        error_index,
        varbinds,
    })
}

pub fn decode_snmp_message(data: &[u8]) -> Result<SnmpMessage> {
    let mut buf = Bytes::copy_from_slice(data);
    let mut msg_data = decode::decode_sequence(&mut buf)
        .map_err(|e| anyhow!("Failed to decode message sequence: {}", e))?;

    let version = decode::decode_integer(&mut msg_data)
        .map_err(|e| anyhow!("Failed to decode version: {}", e))?;

    if version != SNMP_VERSION_1 as i32 {
        return Err(anyhow!("Invalid SNMP version: {}", version));
    }

    let community = decode::decode_octet_string(&mut msg_data)
        .map_err(|e| anyhow!("Failed to decode community string: {}", e))?;

    println!("Decoded community string: {:?}", community);

    println!("Remaining data: {:02x?}", &msg_data[..]);
    let pdu = decode_pdu(&mut msg_data)?;
    

    Ok(SnmpMessage {
        version,
        community,
        pdu,
    })
}

pub fn build_response_pdu(
    request: &SnmpPdu,
    response_varbinds: Vec<Varbind>,
    error_status: i32,
    error_index: i32,
    buf: &mut BytesMut,
) {
    let mut pdu_buf = BytesMut::new();

    encode::encode_integer(request.request_id, &mut pdu_buf);

    encode::encode_integer(error_status, &mut pdu_buf);

    encode::encode_integer(error_index, &mut pdu_buf);

    let mut varbind_list_buf = BytesMut::new();
    build_response_varbind_list(&response_varbinds, &mut varbind_list_buf);
    pdu_buf.put_slice(&varbind_list_buf);

    encode::encode_sequence(&pdu_buf, encode::GET_RESPONSE_TAG, buf);
}

fn build_response_varbind_list(varbinds: &[Varbind], buf: &mut BytesMut) {
    let mut varbind_list_buf = BytesMut::new();

    for varbind in varbinds {
        build_response_varbind(varbind, &mut varbind_list_buf);
    }

    encode::encode_sequence(&varbind_list_buf, encode::SEQUENCE_TAG, buf);
}

fn build_response_varbind(varbind: &Varbind, buf: &mut BytesMut) {
    let mut varbind_buf = BytesMut::new();

    encode::encode_oid(&varbind.oid, &mut varbind_buf);

    match &varbind.value {
        SnmpValue::Integer(val) => {
            encode::encode_integer(*val, &mut varbind_buf);
        }
        SnmpValue::OctetString(val) => {
            encode::encode_octet_string(val, &mut varbind_buf);
        }
        SnmpValue::Null => {
            encode::encode_null(&mut varbind_buf);
        }
        SnmpValue::ObjectIdentifier(val) => {
            encode::encode_oid(val, &mut varbind_buf);
        }
    }

    encode::encode_sequence(&varbind_buf, encode::SEQUENCE_TAG, buf);
}

pub fn build_response_message(
    request: &SnmpMessage,
    response_varbinds: Vec<Varbind>,
    error_status: i32,
    error_index: i32,
    buf: &mut BytesMut,
) {
    let mut msg_buf = BytesMut::new();

    encode::encode_integer(request.version, &mut msg_buf);

    encode::encode_octet_string(&request.community, &mut msg_buf);

    let mut pdu_buf = BytesMut::new();
    build_response_pdu(
        &request.pdu,
        response_varbinds,
        error_status,
        error_index,
        &mut pdu_buf,
    );
    msg_buf.put_slice(&pdu_buf);

    encode::encode_sequence(&msg_buf, encode::SEQUENCE_TAG, buf);
}
