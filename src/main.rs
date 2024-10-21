use anyhow::{Result, anyhow};
use colored::*;
use std::net::IpAddr;
use std::process::Command;
use std::str::FromStr;
use std::time::{Duration, Instant};
use std::thread;
use indicatif::{ProgressBar, ProgressStyle};
use dialoguer::{theme::ColorfulTheme, Input, MultiSelect};

#[derive(Debug, Clone)]
struct Port {
    number: u16,
    service: String,
    version: String,
    protocol: String,
}

#[derive(Debug, Clone)]
struct Machine {
    ip_address: IpAddr,
    ports: Vec<Port>,
}

fn main() -> Result<()> {
    println!("{}", "Starting AutomaSploit...".green().bold());

    let machines = get_target_machines()?;

    for machine in machines {
        println!("\n{} {}", "Scanning machine:".cyan().bold(), machine.ip_address);
        
        // Perform RustScan
        let open_ports = perform_rustscan(&machine.ip_address)?;

        if open_ports.is_empty() {
            println!("{}", "No open ports found.".yellow());
            continue;
        }

        // Perform Nmap scan on open ports
        let ports = perform_nmap_scan(&machine.ip_address, &open_ports)?;

        // Print results
        println!("\n{}", "Scan results:".cyan().bold());
        for port in ports {
            print_port(&port);
        }
    }

    Ok(())
}

fn perform_rustscan(target_ip: &IpAddr) -> Result<Vec<u16>> {
    println!("{}", "Starting RustScan...".blue());
    let rustscan_command = format!("rustscan -a {} -b 500 -t 4000 --ulimit 5000", target_ip);
    
    let estimated_duration = Duration::from_secs(30); // Adjust this based on typical RustScan duration
    let loading_thread = show_loading_animation("Performing RustScan", estimated_duration);
    
    let start_time = Instant::now();
    let rustscan_output = Command::new("sh")
        .arg("-c")
        .arg(&rustscan_command)
        .output()?;
    let elapsed_time = start_time.elapsed();

    loading_thread.join().unwrap();

    println!("{} {:.2?}", "RustScan completed in".blue(), elapsed_time);

    let rustscan_result = String::from_utf8_lossy(&rustscan_output.stdout);

    // Extract open ports from RustScan results
    let open_ports: Vec<u16> = rustscan_result
        .lines()
        .filter(|line| line.contains("Open"))
        .map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            let s:Vec<&str> = parts[1].split(':').collect();
            s[1].parse::<u16>().unwrap()
        })
        .collect();

    println!("{} {:?}", "Parsed open ports:".blue(), open_ports);
    Ok(open_ports)
}

fn perform_nmap_scan(target_ip: &IpAddr, open_ports: &[u16]) -> Result<Vec<Port>> {
    println!("{}", "Starting Nmap vulnerability scan...".blue());
    let ports = if open_ports.is_empty() {
        "1-65535".to_string()
    } else {
        open_ports.iter().map(|p| p.to_string()).collect::<Vec<String>>().join(",")
    };
    let nmap_command = format!("nmap -sV -sC -p {} {}", ports, target_ip);
    println!("{} {}", "Executing Nmap command:".blue(), nmap_command);

    let estimated_duration = Duration::from_secs(60 * open_ports.len().max(1) as u64); // Rough estimate: 1 minute per port, minimum 1 minute
    let loading_thread = show_loading_animation("Performing Nmap scan", estimated_duration);

    let start_time = Instant::now();
    let nmap_output = Command::new("sh")
        .arg("-c")
        .arg(&nmap_command)
        .output()?;
    let elapsed_time = start_time.elapsed();

    loading_thread.join().unwrap();

    println!("{} {:.2?}", "Nmap scan completed in".blue(), elapsed_time);

    let mut ports: Vec<Port> = Vec::new();
    let nmap_result = String::from_utf8_lossy(&nmap_output.stdout);
    for line in nmap_result.lines() {
        if (line.contains("/tcp") || line.contains("/udp")) && line.contains("open") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            ports.push(Port {
                number: parts[0].split('/').next().unwrap().parse::<u16>()?,
                protocol: parts[0].split('/').last().unwrap().to_string(),
                service: parts[2].to_string(),
                version: parts[3..].join(" "),
            });
        }
    }

    if !nmap_output.status.success() {
        println!("{} {:?}", "Nmap command failed with exit code:".red(), nmap_output.status.code());
    }

    Ok(ports)
}

fn print_port(port: &Port) {
    println!("{}", "━".repeat(50).cyan());
    println!("{}: {}", "Port".cyan().bold(), port.number.to_string().yellow());
    println!("{}: {}", "Protocol".cyan().bold(), port.protocol.yellow());
    println!("{}: {}", "Service".cyan().bold(), port.service.yellow());
    println!("{}: {}", "Version".cyan().bold(), port.version.yellow());
}

fn show_loading_animation(message: &str, duration: Duration) -> thread::JoinHandle<()> {
    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner()
        .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ")
        .template("{spinner:.blue} {msg}")
        .unwrap());
    pb.set_message(message.to_string());

    thread::spawn(move || {
        let start = Instant::now();
        while start.elapsed() < duration {
            pb.tick();
            thread::sleep(Duration::from_millis(100));
        }
        pb.finish_with_message("Done");
    })
}

fn get_target_machines() -> Result<Vec<Machine>> {
    let mut machines = Vec::new();

    loop {
        let ip_address: IpAddr = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter a target IP address (or leave empty to finish)")
            .allow_empty(true)
            .validate_with(|input: &String| -> Result<(), String> {
                if input.is_empty() {
                    return Ok(());
                }
                match IpAddr::from_str(input) {
                    Ok(_) => Ok(()),
                    Err(_) => Err("Invalid IP address format. Please try again.".to_string()),
                }
            })
            .interact_text()?;

        if ip_address.to_string().is_empty() {
            break;
        }

        let ports = get_port_specification()?;
        machines.push(Machine { ip_address, ports: Vec::new() });
    }

    if machines.is_empty() {
        return Err(anyhow!("No target machines specified"));
    }

    Ok(machines)
}

fn get_port_specification() -> Result<Vec<u16>> {
    let port_spec: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter port specification (e.g., '80,443,8000-8100' or leave empty for all ports)")
        .allow_empty(true)
        .interact_text()?;

    if port_spec.is_empty() {
        return Ok(Vec::new());
    }

    let mut ports = Vec::new();
    for part in port_spec.split(',') {
        if part.contains('-') {
            let range: Vec<&str> = part.split('-').collect();
            if range.len() != 2 {
                return Err(anyhow!("Invalid port range specification"));
            }
            let start: u16 = range[0].parse()?;
            let end: u16 = range[1].parse()?;
            ports.extend(start..=end);
        } else {
            ports.push(part.parse()?);
        }
    }

    Ok(ports)
}
