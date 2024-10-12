"""
Command-line interface for SWAVS
"""

from swavs.scanner import WebAppScanner
from swavs.utils.banner import print_banner
from swavs.utils.formatting import print_table, print_report_footer

def main():
    """Main entry point for the scanner"""
    try:
        print_banner()
        
        target_host = input("\nEnter the target host (IP or domain): ")
        
        scanner = WebAppScanner(target_host)
        
        if not scanner.check_host_availability():
            print(f"\nError: Unable to reach host {target_host}")
            return 1
            
        print("\nInitiating scan... This may take a few minutes.\n")
        scanner.start_scan()
        
        # Run all checks
        os_info = scanner.detect_os()
        print_table("Operating System Detection", 
                    ["Detection Result"], 
                    [[os_info]])
        
        open_ports = scanner.scan_ports()
        if open_ports:
            print_table("Open Ports and Services",
                        ["Port", "Service"],
                        open_ports)
        
        vulnerabilities = scanner.check_web_vulnerabilities()
        print_table("Web Vulnerability Assessment",
                    ["Vulnerability", "Status"],
                    [[k, v] for k, v in vulnerabilities.items()])
        
        scanner.end_scan()
        print(f"\nScan completed in: {scanner.get_scan_duration()}")
        
        print_report_footer()
        return 0
        
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user. Exiting...")
        return 130
    except Exception as e:
        print(f"\n\nAn error occurred: {str(e)}")
        print("Please report this issue on our GitHub page.")
        return 1

if __name__ == "__main__":
    exit(main())
