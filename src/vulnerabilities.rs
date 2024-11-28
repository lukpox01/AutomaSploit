use crate::Port;

#[derive(Debug, Clone)]
pub struct Vulnerability {
    pub name: String,
    pub cve: Option<String>,
    pub description: String,
    pub severity: String,
}

pub fn check_service_vulnerabilities(service: &str, version: &str) -> Vec<Vulnerability> {
    let mut vulns = Vec::new();
    
    match service.to_lowercase().as_str() {
        "http" | "https" => check_web_vulnerabilities(version, &mut vulns),
        "ssh" => check_ssh_vulnerabilities(version, &mut vulns),
        "smb" | "microsoft-ds" => check_smb_vulnerabilities(version, &mut vulns),
        "mysql" => check_mysql_vulnerabilities(version, &mut vulns),
        "ftp" => check_ftp_vulnerabilities(version, &mut vulns),
        "rdp" | "ms-wbt-server" => check_rdp_vulnerabilities(version, &mut vulns),
        "postgresql" => check_postgres_vulnerabilities(version, &mut vulns),
        "telnet" => check_telnet_vulnerabilities(version, &mut vulns),
        "dns" | "domain" => check_dns_vulnerabilities(version, &mut vulns),
        "smtp" | "mail" => check_smtp_vulnerabilities(version, &mut vulns),
        _ => (),
    }
    
    vulns
}

fn check_web_vulnerabilities(version: &str, vulns: &mut Vec<Vulnerability>) {
    if version.to_lowercase().contains("apache/2.4.49") {
        vulns.push(Vulnerability {
            name: "Apache Path Traversal".to_string(),
            cve: Some("CVE-2021-41773".to_string()),
            description: "Critical path traversal vulnerability in Apache 2.4.49".to_string(),
            severity: "Critical".to_string(),
        });
    }
    
    if version.to_lowercase().contains("nginx/1.16") {
        vulns.push(Vulnerability {
            name: "Nginx HTTP Request Smuggling".to_string(),
            cve: Some("CVE-2019-20372".to_string()),
            description: "HTTP request smuggling vulnerability in Nginx 1.16.x".to_string(),
            severity: "High".to_string(),
        });
    }
}

fn check_ssh_vulnerabilities(version: &str, vulns: &mut Vec<Vulnerability>) {
    if version.to_lowercase().contains("openssh 7.") {
        vulns.push(Vulnerability {
            name: "OpenSSH User Enumeration".to_string(),
            cve: Some("CVE-2018-15473".to_string()),
            description: "Username enumeration via timing attack".to_string(),
            severity: "Medium".to_string(),
        });
    }
}

fn check_smb_vulnerabilities(version: &str, vulns: &mut Vec<Vulnerability>) {
    if version.to_lowercase().contains("samba 3.") {
        vulns.push(Vulnerability {
            name: "Samba Remote Code Execution".to_string(),
            cve: Some("CVE-2017-7494".to_string()),
            description: "Remote code execution vulnerability in Samba".to_string(),
            severity: "Critical".to_string(),
        });
    }
    if version.to_lowercase().contains("windows nt") {
        vulns.push(Vulnerability {
            name: "EternalBlue SMB".to_string(),
            cve: Some("CVE-2017-0144".to_string()),
            description: "Remote code execution vulnerability in SMBv1".to_string(),
            severity: "Critical".to_string(),
        });
    }
}

fn check_mysql_vulnerabilities(version: &str, vulns: &mut Vec<Vulnerability>) {
    if version.to_lowercase().contains("5.5.") {
        vulns.push(Vulnerability {
            name: "MySQL Password Hash Disclosure".to_string(),
            cve: Some("CVE-2012-2122".to_string()),
            description: "Authentication bypass vulnerability".to_string(),
            severity: "High".to_string(),
        });
    }
    if version.to_lowercase().contains("5.7.") {
        vulns.push(Vulnerability {
            name: "MySQL Remote Root Code Execution".to_string(),
            cve: Some("CVE-2016-6662".to_string()),
            description: "Remote code execution via malicious configuration file".to_string(),
            severity: "Critical".to_string(),
        });
    }
}

fn check_ftp_vulnerabilities(version: &str, vulns: &mut Vec<Vulnerability>) {
    if version.to_lowercase().contains("vsftpd 2.3.4") {
        vulns.push(Vulnerability {
            name: "vsFTPd Backdoor".to_string(),
            cve: Some("CVE-2011-2523".to_string()),
            description: "Malicious backdoor in vsFTPd 2.3.4".to_string(),
            severity: "Critical".to_string(),
        });
    }
    if version.to_lowercase().contains("proftpd 1.3.3") {
        vulns.push(Vulnerability {
            name: "ProFTPD Remote Code Execution".to_string(),
            cve: Some("CVE-2010-4221".to_string()),
            description: "Remote code execution via telnet IAC buffer overflow".to_string(),
            severity: "Critical".to_string(),
        });
    }
}

fn check_rdp_vulnerabilities(version: &str, vulns: &mut Vec<Vulnerability>) {
    if version.to_lowercase().contains("windows") {
        vulns.push(Vulnerability {
            name: "BlueKeep RDP".to_string(),
            cve: Some("CVE-2019-0708".to_string()),
            description: "Remote code execution vulnerability in RDP".to_string(),
            severity: "Critical".to_string(),
        });
    }
    if version.to_lowercase().contains("xrdp") {
        vulns.push(Vulnerability {
            name: "XRDP Authentication Bypass".to_string(),
            cve: Some("CVE-2022-23468".to_string()),
            description: "Authentication bypass in XRDP".to_string(),
            severity: "High".to_string(),
        });
    }
}

fn check_postgres_vulnerabilities(version: &str, vulns: &mut Vec<Vulnerability>) {
    if version.to_lowercase().contains("9.") {
        vulns.push(Vulnerability {
            name: "PostgreSQL Authentication Bypass".to_string(),
            cve: Some("CVE-2019-10164".to_string()),
            description: "Authentication bypass via string truncation".to_string(),
            severity: "High".to_string(),
        });
    }
    if version.to_lowercase().contains("10.") {
        vulns.push(Vulnerability {
            name: "PostgreSQL Privilege Escalation".to_string(),
            cve: Some("CVE-2020-25695".to_string()),
            description: "Privilege escalation via partition manipulation".to_string(),
            severity: "High".to_string(),
        });
    }
}

fn check_telnet_vulnerabilities(version: &str, vulns: &mut Vec<Vulnerability>) {
    vulns.push(Vulnerability {
        name: "Telnet Cleartext Protocol".to_string(),
        cve: None,
        description: "Telnet transmits data in cleartext, exposing sensitive information".to_string(),
        severity: "High".to_string(),
    });
    if version.to_lowercase().contains("linux") {
        vulns.push(Vulnerability {
            name: "Remote Code Execution in Telnet".to_string(),
            cve: Some("CVE-2011-4862".to_string()),
            description: "Buffer overflow in telnet server".to_string(),
            severity: "Critical".to_string(),
        });
    }
}

fn check_dns_vulnerabilities(version: &str, vulns: &mut Vec<Vulnerability>) {
    if version.to_lowercase().contains("bind 9") {
        vulns.push(Vulnerability {
            name: "BIND9 Cache Poisoning".to_string(),
            cve: Some("CVE-2020-8617".to_string()),
            description: "DNS cache poisoning via buffer overflow".to_string(),
            severity: "High".to_string(),
        });
    }
    if version.to_lowercase().contains("windows dns") {
        vulns.push(Vulnerability {
            name: "Windows DNS Server RCE".to_string(),
            cve: Some("CVE-2020-1350".to_string()),
            description: "Critical RCE vulnerability (SIGRed)".to_string(),
            severity: "Critical".to_string(),
        });
    }
}

fn check_smtp_vulnerabilities(version: &str, vulns: &mut Vec<Vulnerability>) {
    if version.to_lowercase().contains("exim 4") {
        vulns.push(Vulnerability {
            name: "Exim RCE".to_string(),
            cve: Some("CVE-2019-10149".to_string()),
            description: "Remote command execution in Exim".to_string(),
            severity: "Critical".to_string(),
        });
    }
    if version.to_lowercase().contains("postfix") {
        vulns.push(Vulnerability {
            name: "Postfix SMTP Injection".to_string(),
            cve: Some("CVE-2019-10511".to_string()),
            description: "SMTP header injection vulnerability".to_string(),
            severity: "Medium".to_string(),
        });
    }
}

pub trait VulnerabilityCheck {
    fn check_vulnerabilities(&self) -> Vec<Vulnerability>;
}

impl VulnerabilityCheck for Port {
    fn check_vulnerabilities(&self) -> Vec<Vulnerability> {
        check_service_vulnerabilities(&self.service, &self.version)
    }
}

