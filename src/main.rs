use anyhow::Result;
use std::net::IpAddr;
use std::process::Command;
use std::str::FromStr;

fn main() -> Result<()> {
    // Get the target IP address from command line arguments
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <target_ip>", args[0]);
        std::process::exit(1);
    }
    let target_ip = IpAddr::from_str(&args[1])?;

    // Perform RustScan
    println!("Starting RustScan...");
    let rustscan_command = format!("rustscan -a {} -b 500 -t 4000 --ulimit 5000", target_ip);
    let rustscan_output = Command::new("sh")
        .arg("-c")
        .arg(&rustscan_command)
        .output()?;

    let rustscan_result = String::from_utf8_lossy(&rustscan_output.stdout);
    println!("RustScan results:\n{}", rustscan_result);

    // Extract open ports from RustScan results
    let open_ports: Vec<u16> = rustscan_result
        .lines()
        .filter(|line| line.contains("Open"))
        .filter_map(|line| {
            line.split_whitespace()
                .next()
                .and_then(|s| s.parse().ok())
        })
        .collect();

    if open_ports.is_empty() {
        println!("No open ports found.");
        return Ok(());
    }

    println!("Open ports found: {:?}", open_ports);

    // Perform Nmap scan on open ports
    println!("Starting Nmap vulnerability scan...");
    let ports = open_ports.iter().map(|p| p.to_string()).collect::<Vec<String>>().join(",");
    let nmap_command = format!("nmap -sV -sC -p {} {}", ports, target_ip);

    let nmap_output = Command::new("sh")
        .arg("-c")
        .arg(&nmap_command)
        .output()?;

    // Print Nmap results
    println!("Nmap vulnerability scan results:");
    println!("{}", String::from_utf8_lossy(&nmap_output.stdout));

    Ok(())
}
