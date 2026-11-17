import csv
import os
from pathlib import Path

from modules.ip_validator import validate_ip
from modules.network_info import get_network_info
from modules.host_checker import check_host
from modules.port_scanner import scan_port
from modules.service_detector import detect_service
from modules.security_analyzer import analyze_ports
from modules.logger import setup_logger
from modules.report_generator import (
    generate_report,
    generate_csv_report
)

# Create folders
os.makedirs("logs", exist_ok=True)
os.makedirs("reports", exist_ok=True)

logger = setup_logger()




def display_banner():
    import os
    os.system("clear")

    CYAN = "\033[96m"
    GREEN = "\033[92m"
    WHITE = "\033[97m"
    RESET = "\033[0m"
    BOLD = "\033[1m"

    print()
    print(CYAN + BOLD + "  ==================================================" + RESET)
    print()

    print("       " + CYAN + BOLD + "███╗   ██╗" + GREEN + " ██████╗ " + RESET)
    print("       " + CYAN + BOLD + "████╗  ██║" + GREEN + "██╔════╝ " + RESET)
    print("       " + CYAN + BOLD + "██╔██╗ ██║" + GREEN + "██║  ███╗" + RESET)
    print("       " + CYAN + BOLD + "██║╚██╗██║" + GREEN + "██║   ██║" + RESET)
    print("       " + CYAN + BOLD + "██║ ╚████║" + GREEN + "╚██████╔╝" + RESET)
    print("       " + CYAN + BOLD + "╚═╝  ╚═══╝" + GREEN + " ╚═════╝ " + RESET)

    print()
    print("                    " + WHITE + BOLD + "NG - NetGuard" + RESET)
    print(CYAN + "  ==================================================" + RESET)
    print(WHITE + BOLD + "             NETWORK SECURITY MONITOR" + RESET)
    print(GREEN + "                    VERSION 1.0" + RESET)
    print(CYAN + "  --------------------------------------------------" + RESET)

    print(GREEN + "  [+] Developed by : n3oluffy" + RESET)
    print(CYAN + "  [*] Python Cybersecurity Tool" + RESET)
    print(CYAN + "  [*] TCP/IP | PORT SCANNING" + RESET)
    print(CYAN + "  [*] SECURITY ANALYSIS | REPORTS" + RESET)

    print(CYAN + "  --------------------------------------------------" + RESET)
    print(GREEN + BOLD + "  [✓] NetGuard initialized successfully!" + RESET)
    print(CYAN + "  ==================================================" + RESET)
    print()






def display_menu():
    print("\n--------------- MAIN MENU ---------------")
    print("1. Network Information")
    print("2. Host Availability Check")
    print("3. Port Scanning & Security Analysis")
    print("4. View Security Reports")
    print("5. View Application Logs")
    print("6. Exit")
    print("-----------------------------------------")


def network_information():
    print("\n--- NETWORK INFORMATION ---")

    try:
        hostname, ip_address = get_network_info()
        print("Hostname:", hostname)
        print("IP Address:", ip_address)
        logger.info("Network information collected")

    except Exception as error:
        print("Network information error:", error)
        logger.exception("Network information error")


def get_valid_target():
    target_ip = input(
        "\nEnter authorized target IP: "
    ).strip()

    if validate_ip(target_ip):
        return target_ip

    print("Invalid IP address!")
    logger.warning("Invalid IP address entered")
    return None


def host_availability():
    print("\n--- HOST AVAILABILITY CHECK ---")

    target_ip = get_valid_target()

    if not target_ip:
        return

    try:
        if check_host(target_ip):
            print("Host Status: Reachable")
        else:
            print("Host Status: No ping response")
            print("ICMP may be blocked.")

        logger.info(f"Host check completed: {target_ip}")

    except Exception as error:
        print("Host check error:", error)
        logger.exception("Host availability error")


def security_scan():
    print("\n--- SECURITY SCAN ---")

    target_ip = get_valid_target()

    if not target_ip:
        return

    logger.info(f"Security scan started: {target_ip}")

    ports = [
        21, 22, 23, 25, 53,
        80, 443, 3306, 3389, 8000
    ]

    scan_results = {}
    print("\n--- PORT SCANNING ---")

    for port in ports:
        try:
            status = scan_port(target_ip, port)

        except Exception:
            status = "ERROR"
            logger.exception(f"Port {port} scan error")

        scan_results[port] = status
        print(f"Port {port}: {status}")
        logger.info(f"Port {port}: {status}")

        if status == "OPEN":
            try:
                service, banner = detect_service(
                    target_ip, port
                )
                print("Service:", service)
                print("Banner:", banner)

            except Exception as error:
                print("Service detection error:", error)
                logger.exception(
                    f"Service detection error on port {port}"
                )

    print("\n--- SECURITY ANALYSIS ---")

    try:
        findings = analyze_ports(scan_results)

        if findings:
            for finding in findings:
                print("\nPort:", finding["port"])
                print("Service:", finding["service"])
                print("Severity:", finding["severity"])
                print("Issue:", finding["issue"])
                print(
                    "Recommendation:",
                    finding["recommendation"]
                )
        else:
            print("No findings from configured security rules.")

    except Exception as error:
        print("Security analysis error:", error)
        logger.exception("Security analysis failed")
        return

    print("\n--- REPORT GENERATION ---")

    # TXT report
    try:
        report_path = generate_report(
            target_ip, scan_results, findings
        )
        print("TXT report generated:", report_path)
        logger.info(f"TXT report generated: {report_path}")

    except Exception as error:
        print("TXT report generation error:", error)
        logger.exception("TXT report generation failed")

    # CSV report
    try:
        csv_report_path = generate_csv_report(
            target_ip, scan_results, findings
        )
        print("CSV report generated:", csv_report_path)
        logger.info(
            f"CSV report generated: {csv_report_path}"
        )

    except Exception as error:
        print("CSV report generation error:", error)
        logger.exception("CSV report generation failed")

    logger.info(f"Security scan completed: {target_ip}")



def view_reports():
    print("\n--- SECURITY REPORTS ---")

    reports_dir = Path("reports")

    if not reports_dir.is_dir():
        print("Reports directory not found.")
        return

    files = sorted(
        file for file in reports_dir.iterdir()
        if file.is_file()
        and not file.is_symlink()
        and file.suffix.lower() in (".txt", ".csv")
    )

    if not files:
        print("No reports available.")
        return

    for index, filepath in enumerate(files, start=1):
        print(f"{index}. {filepath.name}")

    choice = input(
        "\nEnter report number (0 to cancel): "
    ).strip()

    if choice == "0":
        return

    if not choice.isdigit():
        print("Invalid selection.")
        return

    index = int(choice)

    if index < 1 or index > len(files):
        print("Invalid report selection.")
        return

    filepath = files[index - 1]

    try:
        print("\n" + "=" * 60)
        print("REPORT:", filepath.name)
        print("=" * 60)

        if filepath.suffix.lower() == ".csv":
            with open(
                filepath, "r",
                encoding="utf-8-sig",
                newline=""
            ) as file:
                reader = csv.reader(file)

                for row in reader:
                    print(" | ".join(row))

        else:
            with open(
                filepath, "r", encoding="utf-8"
            ) as file:
                print(file.read())

        print("=" * 60)

        logger.info(f"Report viewed: {filepath.name}")

    except Exception as error:
        print("Report viewing error:", error)
        logger.exception("Report viewing failed")


def view_logs():
    print("\n--- APPLICATION LOGS ---")

    log_file = Path("logs/netguard.log")

    if not log_file.exists():
        print("No log file available.")
        return

    try:
        content = log_file.read_text(encoding="utf-8")

        if content:
            print(content)
        else:
            print("Log file is empty.")

    except Exception as error:
        print("Log viewing error:", error)
        logger.exception("Log viewing failed")


def main():
    display_banner()
    logger.info("NetGuard application started")

    while True:
        display_menu()

        choice = input(
            "\nEnter your choice (1-6): "
        ).strip()

        if choice == "1":
            network_information()

        elif choice == "2":
            host_availability()

        elif choice == "3":
            security_scan()

        elif choice == "4":
            view_reports()

        elif choice == "5":
            view_logs()

        elif choice == "6":
            print("\nThank you for using NetGuard!")
            print("Application closed.")
            logger.info("NetGuard application closed")
            break

        else:
            print("\nInvalid choice! Please select 1-6.")


if __name__ == "__main__":
    try:
        main()

    except KeyboardInterrupt:
        print("\nNetGuard stopped by user.")
        logger.warning("Application interrupted")

    except Exception as error:
        print("\nUnexpected application error:", error)
        logger.exception("Unexpected application error")

