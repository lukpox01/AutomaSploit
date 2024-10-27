use anyhow::{anyhow, Result};
use colored::*;
use dialoguer::{theme::ColorfulTheme, Input, MultiSelect};
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::Client;
use serde_json::json;
use termimad::crossterm::style::Color::{Green, Red, Yellow};
use termimad::{MadSkin, StyledChar};
use std::net::IpAddr;
use std::process::Command;
use std::str::FromStr;
use std::thread;
use std::time::{Duration, Instant};


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

#[tokio::main]
async fn main() -> Result<()> {
    println!("{}", "Starting AutomaSploit...".green().bold());

    let targets = get_target_machines()?;

    for (ip_address, specified_ports) in targets {
        println!("\n{} {}", "Scanning machine:".cyan().bold(), ip_address);

        // Perform RustScan
        let open_ports = perform_rustscan(&ip_address, &specified_ports)?;

        if open_ports.is_empty() {
            println!("{}", "No open ports found.".yellow());
            continue;
        }

        // Perform Nmap scan on open ports
        let ports = perform_nmap_scan(&ip_address, &open_ports)?;

        // Print results
        println!("\n{}", "Scan results:".cyan().bold());
        for port in &ports {
            print_port(port);
        }

        // Analyze ports with OpenAI
        // println!("\n{}", "Analyzing ports with OpenAI...".cyan().bold());
        // match analyze_ports_with_openai(&ports).await {
        //     Ok(analysis) => print_openai_analysis(&analysis),
        //     Err(e) => println!("{} {}", "Failed to analyze ports with OpenAI:".red().bold(), e),
        // }

        // Analyze ports with Ollama
        println!("\n{}", "Analyzing ports with Ollama...".cyan().bold());
        match analyze_ports_with_ollama(&ports).await {
            Ok(analysis) => print_ollama_analysis(&analysis),
            Err(e) => println!("{} {}", "Failed to analyze ports with Ollama:".red().bold(), e),
        }
    }

    Ok(())
}

use std::process::Stdio;

fn perform_rustscan(target_ip: &IpAddr, specified_ports: &[u16]) -> Result<Vec<u16>> {
    println!("{}", "Starting RustScan...".blue());

    let ports_arg = if specified_ports.is_empty() {
        "".to_string()
    } else {
        format!(
            "-p {}",
            specified_ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<String>>()
                .join(",")
        )
    };

    let rustscan_command = format!("rustscan -a {} {} -g", target_ip, ports_arg);

    println!(
        "{} {}",
        "Executing RustScan command:".blue(),
        rustscan_command
    );

    let start_time = Instant::now();

    let stop_signal = Arc::new(AtomicBool::new(false));
    let animation_handle = show_loading_animation("RustScan in progress...", stop_signal.clone());

    let rustscan_output = Command::new("sh")
        .arg("-c")
        .arg(&rustscan_command)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow!("Failed to execute RustScan: {}", e))?;

    let output = rustscan_output
        .wait_with_output()
        .map_err(|e| anyhow!("Failed to wait for RustScan: {}", e))?;

    stop_signal.store(true, Ordering::Relaxed);
    animation_handle.join().unwrap();

    let elapsed_time = start_time.elapsed();
    println!("{} {:.2?}", "RustScan completed in".blue(), elapsed_time);

    if !output.status.success() {
        let error_message = String::from_utf8_lossy(&output.stderr);
        println!("RustScan stderr: {}", error_message);
        return Err(anyhow!("RustScan failed: {}", error_message));
    }

    let rustscan_result = String::from_utf8_lossy(&output.stdout);
    // println!("RustScan stdout: {}", rustscan_result);

    // Extract open ports from RustScan results
    let open_ports: Vec<u16> = rustscan_result.split(" -> ").collect::<Vec<&str>>()[1]
        .replace(']', "")
        .replace('[', "")
        .split(',')
        .map(|p| p.trim().parse::<u16>().unwrap())
        .collect();

    if open_ports.is_empty() {
        println!("{}", "No open ports found by RustScan.".yellow());
    } else {
        println!(
            "{} {:?}",
            "Open ports found by RustScan:".cyan(),
            open_ports
        );
    }

    Ok(open_ports)
}

fn perform_nmap_scan(target_ip: &IpAddr, open_ports: &[u16]) -> Result<Vec<Port>> {
    println!("{}", "Starting Nmap vulnerability scan...".blue());
    let ports = if open_ports.is_empty() {
        "1-65535".to_string()
    } else {
        open_ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<String>>()
            .join(",")
    };
    let nmap_command = format!("nmap -T4 -sV -sC -p {} {}", ports, target_ip);
    println!("{} {}", "Executing Nmap command:".blue(), nmap_command);

    let start_time = Instant::now();

    let stop_signal = Arc::new(AtomicBool::new(false));
    let animation_handle = show_loading_animation("Nmap scan in progress...", stop_signal.clone());

    let nmap_output = Command::new("sh")
        .arg("-c")
        .arg(&nmap_command)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow!("Failed to execute Nmap: {}", e))?;

    let output = nmap_output
        .wait_with_output()
        .map_err(|e| anyhow!("Failed to wait for Nmap: {}", e))?;

    stop_signal.store(true, Ordering::Relaxed);
    animation_handle.join().unwrap();

    let elapsed_time = start_time.elapsed();
    println!("{} {:.2?}", "Nmap scan completed in".blue(), elapsed_time);

    if !output.status.success() {
        let error_message = String::from_utf8_lossy(&output.stderr);
        println!("Nmap stderr: {}", error_message);
        return Err(anyhow!("Nmap failed: {}", error_message));
    }

    let nmap_result = String::from_utf8_lossy(&output.stdout);
    // println!("Nmap stdout: {}", nmap_result);

    let mut ports: Vec<Port> = Vec::new();
    for line in nmap_result.lines() {
        if (line.contains("/tcp") || line.contains("/udp")) && line.contains("open") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                ports.push(Port {
                    number: parts[0].split('/').next().unwrap().parse::<u16>()?,
                    protocol: parts[0].split('/').last().unwrap().to_string(),
                    service: parts[2].to_string(),
                    version: parts.get(3..).unwrap_or(&[]).join(" "),
                });
            }
        }
    }

    if ports.is_empty() {
        println!("{}", "No open ports found by Nmap.".yellow());
    } 
    // else {
    //     println!("{} {:?}", "Open ports found by Nmap:".blue(), ports);
    // }

    Ok(ports)
}

fn print_port(port: &Port) {
    println!("{}", "━".repeat(50).cyan());
    println!(
        "{}: {}",
        "Port".cyan().bold(),
        port.number.to_string().yellow()
    );
    println!("{}: {}", "Protocol".cyan().bold(), port.protocol.yellow());
    println!("{}: {}", "Service".cyan().bold(), port.service.yellow());
    println!("{}: {}", "Version".cyan().bold(), port.version.yellow());
}

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn show_loading_animation(message: &str, stop_signal: Arc<AtomicBool>) -> thread::JoinHandle<()> {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ")
            .template("{spinner:.blue} {msg}")
            .unwrap(),
    );

    let message = message.to_string(); // Clone the message

    thread::spawn(move || {
        while !stop_signal.load(Ordering::Relaxed) {
            pb.set_message(message.clone());
            pb.tick();
            thread::sleep(Duration::from_millis(100));
        }
        pb.finish_with_message("Done");
    })
}

fn get_target_machines() -> Result<Vec<(IpAddr, Vec<u16>)>> {
    let mut targets = Vec::new();

    loop {
        let ip_input: String = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter a target IP address (or leave empty to finish)")
            .allow_empty(true)
            .interact_text()?;

        if ip_input.is_empty() {
            break;
        }

        let ip_address = match IpAddr::from_str(&ip_input) {
            Ok(ip) => ip,
            Err(_) => {
                println!("{}", "Invalid IP address format. Please try again.".red());
                continue;
            }
        };

        let ports = get_port_specification()?;
        targets.push((ip_address, ports));
    }

    if targets.is_empty() {
        return Err(anyhow!("No target machines specified"));
    }

    Ok(targets)
}

fn get_port_specification() -> Result<Vec<u16>> {
    let port_spec: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt(
            "Enter port specification (e.g., '80,443,8000-8100' or leave empty for all ports)",
        )
        .allow_empty(true)
        .interact_text()?;

    if port_spec.trim().is_empty() {
        println!("No specific ports entered. Scanning all ports.");
        return Ok(Vec::new());
    }

    let mut ports = Vec::new();
    for part in port_spec.split(',') {
        if part.contains('-') {
            let range: Vec<&str> = part.split('-').collect();
            if range.len() != 2 {
                return Err(anyhow!("Invalid port range specification"));
            }
            let start: u16 = range[0].trim().parse()?;
            let end: u16 = range[1].trim().parse()?;
            ports.extend(start..=end);
        } else {
            ports.push(part.trim().parse()?);
        }
    }

    Ok(ports)
}
async fn analyze_ports_with_openai(ports: &[Port]) -> Result<Vec<String>> {
    let api_key = std::env::var("OPENAI_API_KEY").expect("OPENAI_API_KEY not set");
    let client = Client::new();

    let ports_info = ports
        .iter()
        .map(|p| format!("Port {}: {} {} ({})", p.number, p.service, p.protocol, p.version))
        .collect::<Vec<String>>()
        .join("\n");

    let prompt = format!(
        "Analyze the following ports for potential vulnerabilities and outdated versions:\n\n{}\n\nProvide a detailed analysis of potential security risks and recommendations. Format your response in these sections: 'Vulnerabilities', 'Outdated Versions', and 'Recommendations'. Use '-' for bullet points.",
        ports_info
    );

    let response = client
        .post("https://api.openai.com/v1/chat/completions")
        .header("Authorization", format!("Bearer {}", api_key))
        .json(&json!({
            "model": "gpt-3.5-turbo",
            "messages": [
                {"role": "system", "content": "You are a cybersecurity expert analyzing port scan results."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.7,
            "max_tokens": 1000
        }))
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    let analysis = response["choices"][0]["message"]["content"]
        .as_str()
        .ok_or_else(|| anyhow!("Failed to get response content"))?
        .to_string();

    Ok(analysis.lines().map(|s| s.to_string()).collect())
}

async fn analyze_ports_with_ollama(ports: &[Port]) -> Result<Vec<String>> {
    use ollama_rs::generation::completion::request::GenerationRequest;
    use ollama_rs::Ollama;

    let ollama = Ollama::default();
    
    let ports_info = ports
        .iter()
        .map(|p| format!("Port {}: {} {} ({})", p.number, p.service, p.protocol, p.version))
        .collect::<Vec<String>>()
        .join("\n");

    let prompt = format!(
        "As a cybersecurity expert, analyze these ports for vulnerabilities:\n\n{}\n\n\
        For each port, provide analysis in this exact format:\n\n\
        # Port [number]\n\
        ## Service Details\n\
        - Service: [service name]\n\
        - Version: [version info]\n\
        - Protocol: [protocol]\n\n\
        ## Known Vulnerabilities\n\
        - [list specific CVEs or known vulnerabilities]\n\n\
        ## Version Analysis\n\
        - [analysis of version-specific issues]\n\n\
        ## Security Recommendations\n\
        - [specific hardening steps]\n\n\
        Keep responses concise and focus on actionable security findings.\
        Use markdown formatting consistently.",
        ports_info
    );

    let request = GenerationRequest::new(
        "hf.co/bartowski/Llama-3.1-WhiteRabbitNeo-2-8B-GGUF:IQ4_XS".to_string(),
        prompt,
    )
    .system("You are an expert cybersecurity analyst specializing in network security and penetration testing. Your task is to analyze port scan results and identify potential security vulnerabilities, outdated services, and provide detailed recommendations for hardening. Format your response in clear markdown with headers and bullet points. Focus on practical, actionable security advice and current best practices for securing network services.".to_string());

    let response = ollama.generate(request).await?;
    let analysis = response.response;

    Ok(analysis.lines().map(|s| s.to_string()).collect())
}
    

fn print_ollama_analysis(analysis: &[String]) {
    let mut skin = MadSkin::default();
    skin.set_headers_fg(Yellow);
    skin.bold.set_fg(Yellow);
    skin.italic.set_fg(Green);
    skin.bullet = StyledChar::from_fg_char(Yellow, '•');

    let mut markdown = String::new();
    markdown.push_str("# Ollama Analysis\n\n");
    markdown.push_str(&analysis.join("\n"));

    skin.print_text(&markdown);
}

fn print_openai_analysis(analysis: &[String]) {
    let mut skin = MadSkin::default();
    skin.set_headers_fg(Yellow);
    skin.bold.set_fg(Yellow);
    skin.italic.set_fg(Green);
    skin.bullet = StyledChar::from_fg_char(Yellow, '•');

    let mut markdown = String::new();
    markdown.push_str("# OpenAI Analysis\n\n");

    for line in analysis {
        if line.ends_with(':') {
            markdown.push_str(&format!("## {}\n", line));
        } else if line.starts_with('-') {
            markdown.push_str(&format!("{}\n", line));
        } else {
            markdown.push_str(&format!("{}\n", line));
        }
    }

    // Replace "Vulnerabilities:" with red text
    markdown = markdown.replace("## Vulnerabilities:", "## <red>Vulnerabilities:</red>");
    // Replace "Outdated Versions:" with yellow text
    markdown = markdown.replace("## Outdated Versions:", "## <yellow>Outdated Versions:</yellow>");
    // Replace "Recommendations:" with green text
    markdown = markdown.replace("## Recommendations:", "## <green>Recommendations:</green>");

    skin.print_text(&markdown);
}
