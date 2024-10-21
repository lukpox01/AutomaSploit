use anyhow::Result;
use rustscan::scanner::Scanner;
use std::net::IpAddr;
use std::process::Command;
use std::str::FromStr;

#[tokio::main]
async fn main() -> Result<()> {
    // Get the target IP address from command line arguments
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <target_ip>", args[0]);
        std::process::exit(1);
    }
    let target_ip = IpAddr::from_str(&args[1])?;

    // Perform RustScan
    println!("Starting RustScan...");
    let scanner = Scanner::new(
        "127.0.0.1".parse().unwrap(),           // target IP
        1,                                      // start port
        65535,                                  // end port
        100,                                    // rate
        std::time::Duration::from_millis(1000), // timeout
        4,                                      // retries
        std::time::Duration::from_millis(100),  // delay
        rustscan::PortStrategy::Serial,         // port strategy
        false,                                  // verbose
        vec![]                                  // ports to scan (empty for all)
    );
    let rustscan_results = scanner.scan(&[target_ip]).await?;

    // Extract open ports from RustScan results
    let open_ports: Vec<u16> = rustscan_results
        .iter()
        .flat_map(|result| result.open_ports.iter().map(|port| port.port))
        .collect();

    if open_ports.is_empty() {
        println!("No open ports found.");
        return Ok(());
    }

    println!("Open ports found: {:?}", open_ports);

    // Perform Nmap scan on open ports
    println!("Starting Nmap vulnerability scan...");
    let ports = open_ports.iter().map(|p| p.to_string()).collect::<Vec<String>>().join(",");
    let nmap_command = format!("nmap -p {} --script vuln {}", ports, target_ip);

    let output = Command::new("sh")
        .arg("-c")
        .arg(&nmap_command)
        .output()?;

    // Print Nmap results
    println!("Nmap vulnerability scan results:");
    println!("{}", String::from_utf8_lossy(&output.stdout));

    Ok(())
}
