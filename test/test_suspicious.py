# Подозрительный Python скрипт
import subprocess
import socket
import base64

def run_command(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True)
    return result.stdout

def connect_back(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    return s

if __name__ == "__main__":
    data = base64.b64decode("SGVsbG8gV29ybGQ=")
    print(data)
