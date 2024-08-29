import socket #menentukan IP lokal & buat koneksi IP eksternal
import ipaddress #menghitung dan mengelola rentang subnet dari IP local
import platform #menentukan sistem operasi untuk penggunaan malware
from scanner import scan_subnet  # Import fungsi dari scanner.py
from Traffic import start_ids  # Import Traffic scan function
from malware import scan_malware  # Import fungsi dari malware.py

def generate_banner(tool_name):
    banner = f"""
               **************************************************
               *                                                *
               *            WELCOME TUGAS LAS WEEK-4            *
               *                                                *
               *       This tools for Network Scanning          *
               *                                                *
               *           GUSTI AYU ADINDHA JYOTHI             *
               *                                                *
               *                       ID : 2419                *    
               **************************************************
"""
    print(banner)

# find local IP
def find_local_ip():
    try: 
        temp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        temp_socket.connect(("8.8.8.8", 80))
        local_ip = temp_socket.getsockname()[0]
        temp_socket.close()
        return local_ip #mengembalikan ip lokal
    except Exception as error:
        print("Error:", error)
        return None

#calculate IP subnet range based on the local IP
def find_subnet_range(ip):
    network_obj = ipaddress.ip_network(f"{ip}/24", strict=False)
    return network_obj

# print results the scanned subnets
def ip_range(subnet):
    print(f"The IP range is {subnet.network_address} - {subnet.broadcast_address} ({len(list(subnet.hosts()))} hosts)")

if __name__ == "__main__":  
    tool_name = ""
    
    while True:
        generate_banner(tool_name)

        local_ip = find_local_ip()

        if local_ip:
            print(f"Your local IP Address is: {local_ip}")
            subnet = find_subnet_range(local_ip)
            print(f"The calculated CIDR notation is: {subnet}")
            ip_range(subnet)
            
            # Asks users for their choice of scan
            print()
            print("Choose a scan option:")
            print()
            print("1. Scan all active hosts for open ports and identify any services with vulnerabilities")
            print("2. Packet Detecting & Anomali Detections")
            print("3. Scan for Malware")

            print()
            choice = input("Enter your choice (1/2/3): ")
            
            # Based on choice, run the appropriate scan
            if choice == "1":
                print()
                print("Scanning all active hosts for open ports and identifying services with vulnerabilities.....")
                scan_result = scan_subnet(subnet)
                
            elif choice == "2":
                print()
                print("Starting Detect.....")
                start_ids()
                scan_result = None 

            elif choice == "3":
                print()
                print("Starting Malware Scan.....")
                directories = {
                    'Windows': ["C:\\", "D:\\", "E:\\"],
                    'Linux': ["/usr", "/home", "/"]
                }.get(platform.system(), [])

                if directories:
                    scan_malware(directories)
                else:
                    print("Unsupported operating system.")
                scan_result = None  

            else:
                print("Invalid choice.")  # Error handling for invalid choice
                scan_result = None

            if scan_result:
                print()
                print("Scan Results:")
                print()
                print(scan_result)
            else:
                print("No results to display.")  # Message for when there's no result to display
        else:
            print("Unable to retrieve local IP address.")  # Error handling for IP retrieval
        print()
        run_again = input("Do you want to run the program again? (yes/no): ")  # Ask user to run the program again or exit
        if run_again.lower() != 'yes':
            break
