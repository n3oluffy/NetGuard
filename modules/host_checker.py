import subprocess

def check_host(ip):

    result = subprocess.run(
        ["ping", "-c", "1", "-W", "2", ip],
        capture_output=True,
        text=True
    )

    if result.returncode == 0:
        return True
    else:
        return False
