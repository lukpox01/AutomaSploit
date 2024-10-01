use core::str;
use std::net::{Ipv4Addr, SocketAddr};
use std::process::Command;
use std::{net::IpAddr, time::Duration};
use tokio;

use regex::Regex;
use rustscan::input::{PortRange, ScanOrder};
use rustscan::port_strategy::PortStrategy;
use rustscan::scanner::Scanner;

use openai_api_rust::*;
use openai_api_rust::chat::*;
use openai_api_rust::completions::*;

#[derive(Debug)]
enum Error {
    NmapError(String),
    NmapXmlParserError(String),
    IoError(std::io::Error),
}
#[derive(Debug)]
struct Port {
    port: u16,
    protocol: String,
    state: String,
    service: String,
    version: Option<String>,
}

impl Port {
    fn new() -> Port {
        Port {
            port: 0,
            protocol: String::new(),
            state: String::new(),
            service: String::new(),
            version: None,
        }
    }
}
#[derive(Debug)]
struct MachineInfo {
    ip: String,
    ports: Vec<Port>,
    os_info: String,
    cpe_info: String,
}

impl MachineInfo {
    fn new() -> MachineInfo {
        MachineInfo {
            ip: String::new(),
            ports: Vec::new(),
            os_info: String::new(),
            cpe_info: String::new(),
        }
    }
}

#[tokio::main]
async fn main() {
    let IP = IpAddr::V4(Ipv4Addr::new(45, 33, 32, 156));
    let result = scan(vec![IP], PortRange { start: 1, end: 100 }).await;
    let mut ports: Vec<u16> = Vec::new();
    for socket_addr in result {
        ports.push(socket_addr.port());
    }
    println!("Open ports: {:?}", ports);
    let (scan_output, machine) = nmap(IP, ports).unwrap();
    analyze(scan_output);
}

async fn scan(ip_addrs: Vec<IpAddr>, range: PortRange) -> Vec<SocketAddr> {
    let strategy = PortStrategy::pick(&Some(range), None, ScanOrder::Serial);
    let scanner = Scanner::new(
        &ip_addrs,
        10,
        Duration::from_millis(1000),
        2,
        true,
        strategy,
        true,
        vec![],
        false,
    );
    scanner.run().await
}

fn parse_service_info_regex(line: &str) -> (String, String) {
    let os_regex = Regex::new(r"OS:\s+([^;]+)").unwrap();
    let cpe_regex = Regex::new(r"CPE:\s+(.+)").unwrap();

    let os_info = if let Some(cap) = os_regex.captures(line) {
        cap[1].to_string()
    } else {
        String::new()
    };

    let cpe_info = if let Some(cap) = cpe_regex.captures(line) {
        cap[1].to_string()
    } else {
        String::new()
    };

    (os_info, cpe_info)
}

fn nmap(ip_addr: IpAddr, ports: Vec<u16>) -> Result<(String, MachineInfo), Error> {
    let mut command = Command::new("nmap");
    command.arg("-p");
    let mut ports_str = String::new();
    for (idx, port) in ports.iter().enumerate() {
        ports_str.push_str(port.to_string().as_str());
        if idx != ports.len() - 1 {
            ports_str.push_str(",");
        }
    }
    command.arg(ports_str);
    command.arg(ip_addr.to_string());
    command.arg("-sV").arg("-sC").arg("-T4");
    command.arg("-oN").arg("scan_result");

    let output = match command.output() {
        Ok(output) => output,
        Err(err) => return Err(Error::IoError(err)),
    };

    if !output.status.success() {
        return Err(Error::NmapError("Nmap failed to execute".to_string()));
    }

    let output = str::from_utf8(&output.stdout).unwrap();
    let mut scan_content = output.lines();
    let mut start_scan_idx = usize::MAX;

    let mut machine = MachineInfo::new();
    machine.ip = ip_addr.to_string();
    for (idx, line) in scan_content.enumerate() {

        if line.starts_with("PORT") || idx > start_scan_idx {
            if start_scan_idx == usize::MAX {
                start_scan_idx = idx;
                continue;
            } else if line.is_empty() {
                break;
            } else if line.starts_with("Service Info:") {
                let (os_info, cpe_info) = parse_service_info_regex(line);
                machine.os_info = os_info;
                machine.cpe_info = cpe_info;
                continue;
            } else if line.starts_with("|") {
                continue;
            }

            let port_line: Vec<&str> = line.split_whitespace().collect();
            let mut port_field = port_line.get(0).unwrap().split('/');
            let port: u16 = port_field.next().unwrap().parse().unwrap();
            let protocol: String = port_field.next().unwrap().to_string();
            let state = port_line.get(1).unwrap().to_string();
            let service = port_line.get(2).unwrap().to_string();
            let mut version: String = String::new();
            // Fourth section (version and additional info)
            if port_line.len() > 3 {
                let version_info: String = port_line[3..].join(" ");
                version.push_str(&version_info);
            }

            machine.ports.push(Port {
                port,
                protocol,
                state,
                service,
                version: Some(version.to_string()),
            })
        }
    }

    println!("{:#?}", machine);

    Ok((output.to_string(),machine))  
}


fn analyze( nmap_scan: String) {
    // Load API key from environment OPENAI_API_KEY.
    // You can also hadcode through `Auth::new(<your_api_key>)`, but it is not recommended.
    let auth = Auth::from_env().unwrap();
    let openai = OpenAI::new(auth, "https://api.openai.com/v1/");
    let body = ChatBody {
        model: "gpt-3.5-turbo".to_string(),
        max_tokens: None,
        temperature: Some(0.5_f32),
        top_p: Some(0_f32),
        n: Some(1),
        stream: Some(false),
        stop: None,
        presence_penalty: None,
        frequency_penalty: None,
        logit_bias: None,
        user: None,
        messages: vec![Message { role: Role::System, content: "Purpose: This AI is designed to analyze Nmap scan results and identify potential vulnerabilities and exploits associated with the scanned systems.

Functionality:

    Input Analysis: The AI will process Nmap scan output in various formats (XML, grepable, etc.) to identify open ports, running services, and operating system details.

    Vulnerability Identification: Using an updated database of known vulnerabilities (e.g., CVE listings), the AI will correlate the services and versions detected in the scan to highlight potential security risks.

    Exploit Insights: The AI will provide a summary of known exploits associated with identified vulnerabilities, including links to public exploit databases and resources for mitigation.

    Recommendations: The AI will suggest remediation steps for each identified vulnerability, prioritizing them based on severity (e.g., critical, high, medium, low) and potential impact.

    Reporting: The AI will generate a structured report summarizing findings, including:
        Detected services and versions
        Associated vulnerabilities
        Recommended mitigations
        References to external resources

Operational Guidelines:

    The AI will respect user privacy and data confidentiality.
    Outputs should be clear and actionable, suitable for IT security professionals.
    The AI will continuously update its vulnerability database to ensure the relevance of its analyses.".to_string() },
    Message{ content: format!("{} - analyze this scan", nmap_scan), role: Role::User }],
    };
    let rs = openai.chat_completion_create(&body);
    let choice = rs.unwrap().choices;
    let message = &choice[0].message.as_ref().unwrap();
    println!("Bot: {}", message.content);
}