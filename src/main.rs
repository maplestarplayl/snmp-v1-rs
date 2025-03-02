mod agent;
mod asn1;
mod client;
mod snmp;
fn main() {
    let mut client = client::SnmpClient::new();

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

    match client.get(target, community, &[system_description_oid]) {
        Ok(response) => {
            println!("Received response: {:?}", response);
            // Note: In a real implementation, you would decode the response here
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    }
}
