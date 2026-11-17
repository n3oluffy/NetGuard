import socket

def get_network_info():
    hostname = socket.gethostname()

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 80))
            ip_address = s.getsockname()[0]
    except OSError:
        ip_address = "Unable to detect LAN IP"

    return hostname, ip_address
