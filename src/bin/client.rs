use bytes::{BufMut, BytesMut};
use snmp_t::{client::SnmpClient, snmp::{self, SnmpValue}};
use anyhow::Result;
fn main() -> Result<()>{
    let mut client = SnmpClient::new();

    // Example: Get system description (1.3.6.1.2.1.1.1.0)
    let system_description_oid = &[1, 3, 6, 1, 2, 1, 1, 1, 0];

    // Target device (replace with your SNMP agent's IP)
    let target = "127.0.0.1";

    // Community string (replace with your community string)
    let community = "public";

    println!(
        "Sending SNMP GET request to {} for system description...",
        target
    );
    let mut bytes = BytesMut::new();

    match client.get(target, community, &[system_description_oid]) {
        Ok(response) => {
            println!("Received response: {:?}", response);
            let decoded_response = snmp::decode_snmp_message(&response)?;
            decoded_response.pdu.varbinds.iter().for_each(|varbind| {
                println!("OID: {:?}, Value: {:?}", varbind.oid, format_snmp_value(&varbind.value));
            });
            println!("Decoded response: {:?}", decoded_response);
            Ok(())
            // Note: In a real implementation, you would decode the response here
        }
        Err(e) => {
            println!("Error: {}", e);
            Ok(())
        }
    }
}

// Function to get a human-readable string representation of SnmpValue
fn format_snmp_value(value: &SnmpValue) -> String {
    match value {
        SnmpValue::Integer(val) => format!("{} (Integer)", val),
        SnmpValue::OctetString(val) => {
            // Try to display as string if it's printable ASCII
            if val.iter().all(|&b| b >= 32 && b <= 126) {
                format!("\"{}\" (OctetString)", String::from_utf8_lossy(val))
            } else {
                format!("0x{} (OctetString)", 
                    val.iter().map(|b| format!("{:02x}", b)).collect::<String>())
            }
        },
        SnmpValue::Null => "NULL".to_string(),
        SnmpValue::ObjectIdentifier(val) => "TODO".to_string(),
    }
}