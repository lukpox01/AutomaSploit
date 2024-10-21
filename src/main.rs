use anyhow::{Result, anyhow};
use std::net::IpAddr;
use std::process::Command;
use std::str::FromStr;

#[derive(Debug, Clone)]
struct Port {
    number: u16,
    service: String,
    version: String,
}

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
    // println!("RustScan raw results:\n{}", rustscan_result);

    // Extract open ports from RustScan results
    let open_ports: Vec<u16> = rustscan_result
        .lines()
        .filter(|line| line.contains("Open"))
        .inspect(|line| println!("Filtered line: {}", line))
        .map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            let s:Vec<&str> = parts[1].split(':').collect();
            s[1].parse::<u16>().unwrap()
        })
        .collect();

    println!("Parsed open ports: {:?}", open_ports);

    if open_ports.is_empty() {
        println!("No open ports found.");
        return Ok(());
    }

    // Perform Nmap scan on open ports
    println!("Starting Nmap vulnerability scan...");
    let ports = open_ports.iter().map(|p| p.to_string()).collect::<Vec<String>>().join(",");
    let nmap_command = format!("nmap -sV -sC -p {} {}", ports, target_ip);
    println!("Executing Nmap command: {}", nmap_command);

    let nmap_output = Command::new("sh")
        .arg("-c")
        .arg(&nmap_command)
        .output()?;

    // Output Nmap results
    println!("Nmap scan results:");
    let nmap_result = String::from_utf8_lossy(&nmap_output.stdout);
    for line in nmap_result.lines() {
        if line.contains("/tcp") && line.contains("open") {
            println!("{}", line);
        }
    }

    if !nmap_output.status.success() {
        println!("Nmap command failed with exit code: {:?}", nmap_output.status.code());
    }

    Ok(())
}
