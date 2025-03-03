use crate::snmp::{self, SnmpMessage, SnmpValue, Varbind};
use anyhow::{Context, Result};
use bytes::BytesMut;
use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;
type MibDB = HashMap<Vec<u32>, SnmpValue>;

pub struct SnmpAgent {
    socket: UdpSocket,
    communities: Vec<String>,
    mib: Arc<RwLock<MibDB>>,
}

impl SnmpAgent {
    pub fn new(addr: &str, communities: Vec<String>) -> Result<Self> {
        let socket = UdpSocket::bind(addr).context("Failed to bind UDP socket")?;
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .context("Failed to set socket timeout")?;

        Ok(Self {
            socket,
            communities,
            mib: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub fn register_oid(&self, oid: Vec<u32>, value: SnmpValue) -> Result<()> {
        self.mib.write().unwrap().insert(oid, value);
        Ok(())
    }

    // Process an SNMP message
    fn process_message(&self, data: &[u8], src_addr: SocketAddr) -> Result<()> {
        // Decode the message
        let message = match snmp::decode_snmp_message(data) {
            Ok(msg) => msg,
            Err(e) => {
                println!("Error decoding message: {}", e);
                return Ok(());
            }
        };

        // Check community string
        let community_str = String::from_utf8_lossy(&message.community);
        if !self.communities.iter().any(|c| c == community_str.as_ref()) {
            println!("Invalid community string: {}", community_str);
            return Ok(());
        }
        // Process PDU based on type
        match message.pdu.pdu_type {
            crate::snmp::PduType::GET_REQUEST => {
                self.handle_get_request(&message, src_addr)?;
            }
            crate::snmp::PduType::GET_NEXT_REQUEST => {
                self.handle_get_next_request(&message, src_addr)?;
            }
            crate::snmp::PduType::SET_REQUEST => {
                self.handle_set_request(&message, src_addr)?;
            }
            _ => {
                println!("Unsupported PDU type");
            }
        }

        Ok(())
    }

    // Handle a GetRequest
    fn handle_get_request(&self, request: &SnmpMessage, src_addr: SocketAddr) -> Result<()> {
        let mib = self.mib.read().unwrap();
        let mut response_varbinds = Vec::new();
        let mut error_status = 0;
        let mut error_index = 0;

        // Process each varbind in the request
        for (i, varbind) in request.pdu.varbinds.iter().enumerate() {
            if let Some(value) = mib.get(&varbind.oid) {
                // OID found, add to response
                response_varbinds.push(Varbind {
                    oid: varbind.oid.clone(),
                    value: value.clone(),
                });
            } else {
                // OID not found, set error
                error_status = 2; // noSuchName
                error_index = (i + 1) as i32;

                // Add the original varbind with NULL value
                response_varbinds.push(Varbind {
                    oid: varbind.oid.clone(),
                    value: SnmpValue::Null,
                });
            }
        }

        // Build and send response
        let mut response_buf = BytesMut::new();
        snmp::build_response_message(
            request,
            response_varbinds,
            error_status,
            error_index,
            &mut response_buf,
        );

        self.socket
            .send_to(&response_buf, src_addr)
            .context("Failed to send SNMP response")?;

        Ok(())
    }

    // Handle a GetNextRequest
    fn handle_get_next_request(&self, request: &SnmpMessage, src_addr: SocketAddr) -> Result<()> {
        let mib = self.mib.read().unwrap();
        let mut response_varbinds = Vec::new();
        let mut error_status = 0;
        let mut error_index = 0;

        // Process each varbind in the request
        for (i, varbind) in request.pdu.varbinds.iter().enumerate() {
            // Find the next OID in lexicographical order
            let next_oid = mib
                .keys()
                .filter(|k| k > &&varbind.oid)
                .min_by(|a, b| a.cmp(b));

            if let Some(next_oid) = next_oid {
                // Next OID found, add to response
                if let Some(value) = mib.get(next_oid) {
                    response_varbinds.push(Varbind {
                        oid: next_oid.clone(),
                        value: value.clone(),
                    });
                }
            } else {
                // No next OID, set error
                error_status = 2; // noSuchName
                error_index = (i + 1) as i32;

                // Add the original varbind with NULL value
                response_varbinds.push(Varbind {
                    oid: varbind.oid.clone(),
                    value: SnmpValue::Null,
                });
            }
        }

        // Build and send response
        let mut response_buf = BytesMut::new();
        snmp::build_response_message(
            request,
            response_varbinds,
            error_status,
            error_index,
            &mut response_buf,
        );

        self.socket
            .send_to(&response_buf, src_addr)
            .context("Failed to send SNMP response")?;

        Ok(())
    }

    // Handle a SetRequest
    fn handle_set_request(&self, request: &SnmpMessage, src_addr: SocketAddr) -> Result<()> {
        let mut mib = self.mib.write().unwrap();
        let mut response_varbinds = Vec::new();
        let mut error_status = 0;
        let mut error_index = 0;

        // Process each varbind in the request
        for (i, varbind) in request.pdu.varbinds.iter().enumerate() {
            // Update the MIB
            mib.insert(varbind.oid.clone(), varbind.value.clone());

            // Add to response
            response_varbinds.push(varbind.clone());
        }

        // Build and send response
        let mut response_buf = BytesMut::new();
        snmp::build_response_message(
            request,
            response_varbinds,
            error_status,
            error_index,
            &mut response_buf,
        );

        self.socket
            .send_to(&response_buf, src_addr)
            .context("Failed to send SNMP response")?;

        Ok(())
    }

    // Run the SNMP agent
    pub fn run(&self) -> Result<()> {
        println!(
            "SNMP agent running on {}",
            self.socket
                .local_addr()
                .context("Failed to get local address")?
        );

        let mut buf = [0u8; 4096];

        loop {
            match self.socket.recv_from(&mut buf) {
                Ok((size, src_addr)) => {
                    if let Err(e) = self.process_message(&buf[..size], src_addr) {
                        println!("Error processing message: {}", e);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // Timeout, continue
                    continue;
                }
                Err(e) => {
                    println!("Error receiving data: {}", e);
                    break;
                }
            }
        }

        Ok(())
    }

    // Run the agent in a separate thread
    pub fn run_in_thread(self) -> thread::JoinHandle<Result<()>> {
        thread::spawn(move || self.run())
    }
}
