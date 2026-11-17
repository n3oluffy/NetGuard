
import socket

def detect_service(ip, port):

    services = {
        21: "FTP",
        22: "SSH",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        443: "HTTPS",
        3306: "MySQL",
        8000: "HTTP (Development Server)"
    }

    service_name = services.get(port, "Unknown")

    try:
        with socket.create_connection((ip, port), timeout=2) as sock:

            if port == 443:
                return service_name, "TLS service; banner not inspected"

            if port in (80, 8000):
                sock.sendall(
                    b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n"
                )

            banner = sock.recv(1024).decode(
                "utf-8", errors="replace"
            )

            return service_name, banner.strip()

    except (OSError, TimeoutError):
        return service_name, "Banner unavailable"

