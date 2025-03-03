use std::thread;
use std::time::Duration;
use anyhow::Result;
use snmp_t::snmp::SnmpValue;
use snmp_t::agent::SnmpAgent;
fn main() -> Result<()> {
    println!("Starting SNMP v1 Agent");
    
    // Create an SNMP agent on port 161 (requires root/admin privileges)
    // Use a higher port like 16100 if you don't have privileges
    let agent = SnmpAgent::new("0.0.0.0:16100", vec!["public".to_string()])?;
    
    // Register some OIDs
    
    // System description (1.3.6.1.2.1.1.1.0)
    agent.register_oid(
        vec![1, 3, 6, 1, 2, 1, 1, 1, 0],
        SnmpValue::OctetString("Rust SNMP Agent v1.0".as_bytes().to_vec())
    )?;
    
    // System uptime (1.3.6.1.2.1.1.3.0)
    agent.register_oid(
        vec![1, 3, 6, 1, 2, 1, 1, 3, 0],
        SnmpValue::Integer(0) // Will be updated
    )?;
    
    // System contact (1.3.6.1.2.1.1.4.0)
    agent.register_oid(
        vec![1, 3, 6, 1, 2, 1, 1, 4, 0],
        SnmpValue::OctetString("admin@example.com".as_bytes().to_vec())
    )?;
    
    // Start the agent in a separate thread
    let agent_thread = agent.run_in_thread();
    
    println!("SNMP agent started. Press Ctrl+C to stop.");
    
    // Wait for Ctrl+C or other termination signal
    // In a real application, you would use a proper signal handler
    thread::sleep(Duration::from_secs(3600)); // Run for 1 hour
    
    println!("SNMP agent stopped");
    
    Ok(())
}
