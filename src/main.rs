use anyhow::Result;
use rustscan::Scanner;
use nmap::Nmap;
use std::net::IpAddr;
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
    let scanner = Scanner::new();
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
    let mut nmap = Nmap::new();
    nmap.add_target(&target_ip.to_string());
    for port in open_ports {
        nmap.add_port(port);
    }
    nmap.script("vuln");

    let nmap_results = nmap.run()?;

    // Print Nmap results
    println!("Nmap vulnerability scan results:");
    println!("{}", nmap_results);

    Ok(())
}
