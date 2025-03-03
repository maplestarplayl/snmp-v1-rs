use std::error::Error;
use std::fmt::format;
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::time::Duration;

use bytes::BytesMut;

use crate::snmp;
pub struct SnmpClient {
    socket: UdpSocket,
    timeout: Duration,
    request_id: i32,
}

impl SnmpClient {
    pub fn new() -> Self {
        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        let timeout = Duration::from_secs(5);

        Self {
            socket,
            timeout,
            request_id: 1,
        }
    }
    pub fn get(
        &mut self,
        target: &str,
        community: &str,
        oids: &[&[u32]],
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut buf = BytesMut::new();
        let mut varbind_list_buf = BytesMut::new();
        let mut pdu_buf = BytesMut::new();

        snmp::build_varbind_list(oids, &mut varbind_list_buf);
        snmp::build_pdu(
            self.request_id,
            0,
            0,
            &varbind_list_buf,
            snmp::PduType::GET_REQUEST,
            &mut pdu_buf,
        );
        snmp::build_snmp_msg(community, &pdu_buf, &mut buf);

        self.request_id += 1;

        let target_addr: SocketAddr = format!("{}:16100", target).parse()?;
        self.socket.send_to(&buf, target_addr)?;

        let mut response = vec![0u8; 1024];

        let (len, _) = self.socket.recv_from(&mut response)?;

        Ok(response[..len].to_vec())
    }

    // pub fn set
}
