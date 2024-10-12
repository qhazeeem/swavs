import socket
import sys
from datetime import datetime
import subprocess
import platform
import ssl
import http.client
from concurrent.futures import ThreadPoolExecutor
import time

class WebAppScanner:
    def __init__(self, target_host):
        self.target_host = target_host
        self.scan_start_time = None
        self.scan_end_time = None
        
    def start_scan(self):
        self.scan_start_time = datetime.now()
        
    def end_scan(self):
        self.scan_end_time = datetime.now()
        
    def get_scan_duration(self):
        if self.scan_start_time and self.scan_end_time:
            duration = self.scan_end_time - self.scan_start_time
            return str(duration).split('.')[0]
        return "Unknown"
        
    def check_host_availability(self):
        try:
            socket.gethostbyname(self.target_host)
            return True
        except socket.gaierror:
            return False

    # Add all the scanning methods from our previous implementation here
    def detect_os(self):
        try:
            if platform.system().lower() == 'windows':
                ping_cmd = ['ping', '-n', '1', self.target_host]
            else:
                ping_cmd = ['ping', '-c', '1', self.target_host]
                
            result = subprocess.run(ping_cmd, capture_output=True, text=True)
            
            if "ttl=64" in result.stdout.lower():
                return "Likely Linux/Unix system"
            elif "ttl=128" in result.stdout.lower():
                return "Likely Windows system"
            else:
                return "OS detection inconclusive"
        except Exception as e:
            return f"OS detection error: {str(e)}"

    # Add all other methods from our previous implementation
