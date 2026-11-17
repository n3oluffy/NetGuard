

import csv
from datetime import datetime
from pathlib import Path


def get_scan_summary(scan_results, findings):

    total_ports = len(scan_results)

    open_ports = sum(
        1 for status in scan_results.values()
        if status == "OPEN"
    )

    closed_ports = sum(
        1 for status in scan_results.values()
        if status == "CLOSED"
    )

    error_ports = sum(
        1 for status in scan_results.values()
        if status == "ERROR"
    )

    high = sum(
        1 for item in findings
        if item.get("severity", "").upper() == "HIGH"
    )

    medium = sum(
        1 for item in findings
        if item.get("severity", "").upper() == "MEDIUM"
    )

    info = sum(
        1 for item in findings
        if item.get("severity", "").upper() == "INFO"
    )

    return {
        "total": total_ports,
        "open": open_ports,
        "closed": closed_ports,
        "errors": error_ports,
        "high": high,
        "medium": medium,
        "info": info
    }


def generate_report(target_ip, scan_results, findings):

    reports_dir = Path("reports")
    reports_dir.mkdir(parents=True, exist_ok=True)

    current_time = datetime.now()
    timestamp = current_time.strftime("%Y%m%d_%H%M%S")

    filename = f"security_report_{timestamp}.txt"
    filepath = reports_dir / filename

    summary = get_scan_summary(scan_results, findings)

    with open(filepath, "w", encoding="utf-8") as report:

        report.write("=" * 60 + "\n")
        report.write("              NETGUARD SECURITY REPORT\n")
        report.write("=" * 60 + "\n\n")

        report.write("--- SCAN INFORMATION ---\n\n")
        report.write(f"Target IP       : {target_ip}\n")
        report.write(
            f"Scan Date       : {current_time.strftime('%Y-%m-%d')}\n"
        )
        report.write(
            f"Scan Time       : {current_time.strftime('%I:%M:%S %p')}\n"
        )

        report.write("\n" + "-" * 60 + "\n")
        report.write("                 SECURITY SUMMARY\n")
        report.write("-" * 60 + "\n\n")

        report.write(f"Total Ports Scanned : {summary['total']}\n")
        report.write(f"Open Ports          : {summary['open']}\n")
        report.write(f"Closed Ports        : {summary['closed']}\n")
        report.write(f"Scan Errors         : {summary['errors']}\n")

        report.write("\n--- RISK SUMMARY ---\n\n")
        report.write(f"HIGH Findings       : {summary['high']}\n")
        report.write(f"MEDIUM Findings     : {summary['medium']}\n")
        report.write(f"INFO Findings       : {summary['info']}\n")

        report.write("\n" + "-" * 60 + "\n")
        report.write("                 PORT SCAN RESULTS\n")
        report.write("-" * 60 + "\n\n")

        for port, status in scan_results.items():
            report.write(f"Port {port:<8}: {status}\n")

        report.write("\n" + "-" * 60 + "\n")
        report.write("                 SECURITY FINDINGS\n")
        report.write("-" * 60 + "\n")

        if findings:

            for finding in findings:

                report.write("\n")
                report.write(f"Port           : {finding['port']}\n")
                report.write(f"Service        : {finding['service']}\n")
                report.write(f"Severity       : {finding['severity']}\n")
                report.write(f"Issue          : {finding['issue']}\n")
                report.write(
                    f"Recommendation : {finding['recommendation']}\n"
                )

        else:
            report.write(
                "\nNo findings from configured security rules.\n"
            )

        report.write("\n" + "=" * 60 + "\n")
        report.write("              END OF NETGUARD REPORT\n")
        report.write("=" * 60 + "\n")

    print(f"[+] TXT report generated: {filepath}")

    return str(filepath)


def generate_csv_report(target_ip, scan_results, findings):

    reports_dir = Path("reports")
    reports_dir.mkdir(parents=True, exist_ok=True)

    current_time = datetime.now()
    timestamp = current_time.strftime("%Y%m%d_%H%M%S")

    filename = f"NetGuard_{target_ip}_{timestamp}.csv"
    filepath = reports_dir / filename

    summary = get_scan_summary(scan_results, findings)

    findings_lookup = {
        finding.get("port"): finding
        for finding in findings
    }

    fieldnames = [
        "Target IP",
        "Scan Date",
        "Scan Time",
        "Total Ports Scanned",
        "Open Ports",
        "Closed Ports",
        "Scan Errors",
        "HIGH Findings",
        "MEDIUM Findings",
        "INFO Findings",
        "Port",
        "Status",
        "Service",
        "Severity",
        "Issue",
        "Recommendation"
    ]

    with open(
        filepath,
        "w",
        newline="",
        encoding="utf-8-sig"
    ) as csvfile:

        writer = csv.DictWriter(
            csvfile,
            fieldnames=fieldnames
        )

        writer.writeheader()

        for port, status in scan_results.items():

            finding = findings_lookup.get(port, {})

            writer.writerow({
                "Target IP": target_ip,
                "Scan Date": current_time.strftime("%Y-%m-%d"),
                "Scan Time": current_time.strftime("%I:%M:%S %p"),
                "Total Ports Scanned": summary["total"],
                "Open Ports": summary["open"],
                "Closed Ports": summary["closed"],
                "Scan Errors": summary["errors"],
                "HIGH Findings": summary["high"],
                "MEDIUM Findings": summary["medium"],
                "INFO Findings": summary["info"],
                "Port": port,
                "Status": status,
                "Service": finding.get("service", "Unknown"),
                "Severity": finding.get("severity", "N/A"),
                "Issue": finding.get("issue", "No issue detected"),
                "Recommendation": finding.get(
                    "recommendation",
                    "No recommendation available"
                )
            })

    print(f"[+] CSV report generated: {filepath}")

    return str(filepath)

