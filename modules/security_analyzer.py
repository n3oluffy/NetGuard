
def analyze_ports(scan_results):

    findings = []

    security_rules = {
        21: (
            "FTP",
            "HIGH",
            "FTP may transmit data without encryption.",
            "Use secure file transfer such as SFTP."
        ),
        22: (
            "SSH",
            "INFO",
            "SSH remote access is available.",
            "Allow access only from trusted systems."
        ),
        23: (
            "Telnet",
            "HIGH",
            "Telnet does not encrypt login traffic.",
            "Disable Telnet and use SSH."
        ),
        25: (
            "SMTP",
            "MEDIUM",
            "SMTP service is accessible.",
            "Review mail server security and authentication."
        ),
        53: (
            "DNS",
            "INFO",
            "DNS service is accessible.",
            "Restrict zone transfers and review DNS configuration."
        ),
        80: (
            "HTTP",
            "MEDIUM",
            "HTTP traffic is not encrypted.",
            "Use HTTPS where appropriate."
        ),
        443: (
            "HTTPS",
            "INFO",
            "HTTPS service is accessible.",
            "Keep TLS configuration and certificates updated."
        ),
        3306: (
            "MySQL",
            "HIGH",
            "MySQL database port is accessible.",
            "Restrict database access to trusted hosts."
        ),
        3389: (
            "RDP",
            "MEDIUM",
            "Remote Desktop access is available.",
            "Restrict access to authorized users and networks."
        ),
        8000: (
            "HTTP (Development Port)",
            "INFO",
            "A service is accessible on a commonly used development port.",
            "Verify the service and avoid exposing development servers to untrusted networks."
        )
    }

    for port, status in scan_results.items():

        if status == "OPEN":

            rule = security_rules.get(port)

            if rule:
                service, severity, issue, recommendation = rule
            else:
                service = "Unknown"
                severity = "INFO"
                issue = "An unclassified port is accessible."
                recommendation = "Identify the service and review its access."

            finding = {
                "port": port,
                "service": service,
                "severity": severity,
                "issue": issue,
                "recommendation": recommendation
            }

            findings.append(finding)

    return findings

