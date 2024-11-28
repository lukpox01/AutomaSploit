mod vulnerabilities;

use vulnerabilities::{Vulnerability, VulnerabilityCheck};

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

use std::fs::File;
use std::io::Write;
use std::path::Path;
use chrono::Local;

impl Machine {
    pub fn generate_text_report(&self) -> Result<String> {
        let mut report = String::new();
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
        
        report.push_str(&format!("Security Analysis Report for {}\n", self.ip_address));
        report.push_str(&format!("Generated at: {}\n", timestamp));
        report.push_str(&"=".repeat(50));
        report.push_str("\n\n");

        for port in &self.ports {
            report.push_str(&format!("Port {}: {} ({})\n", port.number, port.service, port.protocol));
            report.push_str(&format!("Version: {}\n", port.version));
            
            let vulns = port.check_vulnerabilities();
            if !vulns.is_empty() {
                report.push_str("\nVulnerabilities Found:\n");
                for vuln in vulns {
                    report.push_str(&format!("\n- {}\n", vuln.name));
                    report.push_str(&format!("  Severity: {}\n", vuln.severity));
                    if let Some(cve) = vuln.cve {
                        report.push_str(&format!("  CVE: {}\n", cve));
                    }
                    report.push_str(&format!("  Description: {}\n", vuln.description));
                }
            }
            report.push_str("\n");
            report.push_str(&"-".repeat(50));
            report.push_str("\n\n");
        }

        Ok(report)
    }

    pub fn generate_html_report(&self) -> Result<String> {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
        let mut html = String::new();

        // Updated HTML header and styling
        html.push_str(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Analysis Report</title>
    <style>
        :root {
            --primary-color: #2c3e50;
            --danger-color: #e74c3c;
            --warning-color: #f39c12;
            --success-color: #27ae60;
            --info-color: #3498db;
            --background-color: #ecf0f1;
            --card-background: #ffffff;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: var(--background-color);
            color: var(--primary-color);
        }
        
        .container {
            background-color: var(--card-background);
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .header {
            border-bottom: 3px solid var(--primary-color);
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        
        .header h1 {
            color: var(--primary-color);
            margin: 0;
            font-size: 2.2em;
        }
        
        .header p {
            color: #666;
            margin: 10px 0 0 0;
            font-size: 1.1em;
        }
        
        .port-section {
            margin-bottom: 30px;
            padding: 20px;
            border: 1px solid #ddd;
            border-radius: 8px;
            background-color: #fafafa;
            transition: all 0.3s ease;
        }
        
        .port-section:hover {
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            transform: translateY(-2px);
        }
        
        .port-section h2 {
            color: var(--info-color);
            border-bottom: 2px solid var(--info-color);
            padding-bottom: 8px;
            margin-top: 0;
        }
        
        .vulnerability {
            margin: 15px 0;
            padding: 15px;
            background-color: #fff;
            border-radius: 6px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }
        
        .vulnerability h4 {
            margin: 0 0 10px 0;
            color: var(--danger-color);
        }
        
        .severity-critical {
            border-left: 5px solid #dc3545;
            background-color: #fff5f5;
        }
        
        .severity-high {
            border-left: 5px solid #fd7e14;
            background-color: #fff9f0;
        }
        
        .severity-medium {
            border-left: 5px solid #ffc107;
            background-color: #fffbeb;
        }
        
        .severity-low {
            border-left: 5px solid #28a745;
            background-color: #f0fff4;
        }
        
        .service-details {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 15px 0;
            padding: 15px;
            background-color: #f8f9fa;
            border-radius: 6px;
        }
        
        .service-detail {
            padding: 10px;
        }
        
        .service-detail strong {
            color: var(--primary-color);
            display: block;
            margin-bottom: 5px;
        }
        
        .vulnerability-list {
            margin-top: 20px;
        }
        
        .vulnerability-badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.9em;
            font-weight: bold;
            margin-right: 8px;
        }
        
        .badge-critical { background-color: #dc3545; color: white; }
        .badge-high { background-color: #fd7e14; color: white; }
        .badge-medium { background-color: #ffc107; color: black; }
        .badge-low { background-color: #28a745; color: white; }
    </style>
</head>
<body>
<div class="container">"#);

        // Report header
        html.push_str(&format!(r#"
    <div class="header">
        <h1>Security Analysis Report for {}</h1>
        <p>Generated at: {}</p>
    </div>"#, self.ip_address, timestamp));

        // Port sections
        for port in &self.ports {
            html.push_str(&format!(r#"
    <div class="port-section">
        <h2>Port {}: {} ({})</h2>
        <div class="service-details">
            <div class="service-detail">
                <strong>Port Number:</strong>
                <span>{}</span>
            </div>
            <div class="service-detail">
                <strong>Service:</strong>
                <span>{}</span>
            </div>
            <div class="service-detail">
                <strong>Protocol:</strong>
                <span>{}</span>
            </div>
            <div class="service-detail">
                <strong>Version:</strong>
                <span>{}</span>
            </div>
        </div>"#,
                port.number, port.service, port.protocol,
                port.number, port.service, port.protocol, port.version));

            let vulns = port.check_vulnerabilities();
            if !vulns.is_empty() {
                html.push_str("\n        <div class=\"vulnerability-list\">\n");
                html.push_str("            <h3>Vulnerabilities Found:</h3>");
                for vuln in vulns {
                    let severity_class = match vuln.severity.to_lowercase().as_str() {
                        "critical" => "severity-critical",
                        "high" => "severity-high",
                        "medium" => "severity-medium",
                        _ => "severity-low",
                    };
                    
                    let badge_class = match vuln.severity.to_lowercase().as_str() {
                        "critical" => "badge-critical",
                        "high" => "badge-high",
                        "medium" => "badge-medium",
                        _ => "badge-low",
                    };

                    html.push_str(&format!(r#"
            <div class="vulnerability {}">
                <h4>{}</h4>
                <span class="vulnerability-badge {}">{}</span>
                {}"#,
                        severity_class, 
                        vuln.name,
                        badge_class,
                        vuln.severity,
                        if let Some(cve) = vuln.cve {
                            format!("<span class=\"vulnerability-badge badge-high\">{}</span>", cve)
                        } else {
                            String::new()
                        }
                    ));
                    
                    html.push_str(&format!(r#"
                <p>{}</p>
            </div>"#, vuln.description));
                }
                html.push_str("\n        </div>");
            }
            
            html.push_str("\n    </div>");
        }

        // HTML footer
        html.push_str(r#"
</div>
</body>
</html>"#);

        Ok(html)
    }

    pub fn save_report(&self, format: ReportFormat, output_path: &str) -> Result<()> {
        let content = match format {
            ReportFormat::Text => self.generate_text_report()?,
            ReportFormat::HTML => self.generate_html_report()?,
        };

        let path = Path::new(output_path);
        let mut file = File::create(path)?;
        file.write_all(content.as_bytes())?;

        println!("{} Report saved to: {}", "✔".green(), output_path);
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ReportFormat {
    Text,
    HTML,
}

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

        // Create Machine instance
        let machine = Machine {
            ip_address,
            ports,
        };

        // Print results
        println!("\n{}", "Scan results:".cyan().bold());
        for port in &machine.ports {
            print_port(port);
        }

        // Save reports
        if let Err(e) = machine.save_report(ReportFormat::Text, &format!("report_{}.txt", ip_address)) {
            println!("{} {}", "Failed to save text report:".red().bold(), e);
        }
        if let Err(e) = machine.save_report(ReportFormat::HTML, &format!("report_{}.html", ip_address)) {
            println!("{} {}", "Failed to save HTML report:".red().bold(), e);
        }

        // ...existing OpenAI and Ollama analysis code...
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
    
    let vulns = port.check_vulnerabilities();
    if !vulns.is_empty() {
        println!("\n{}", "Known Vulnerabilities:".red().bold());
        for vuln in vulns {
            println!("  {} ({})", vuln.name.red(), vuln.severity.yellow());
            if let Some(cve) = vuln.cve {
                println!("  CVE: {}", cve.red());
            }
            println!("  Description: {}", vuln.description);
        }
    }
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
