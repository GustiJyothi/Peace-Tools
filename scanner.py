import subprocess

def scan_subnet(subnet, ports="1-65535", script="vuln"):
    try:
        command = f'nmap -p {ports} -sV --script {script} {subnet}'
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout
    except Exception as error:
        print(f"Error occurred: {error}")
        return None
