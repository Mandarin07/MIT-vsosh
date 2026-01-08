
import os
import socket
import subprocess

print("Starting suspicious operations...")

# subprocess call
proc = subprocess.Popen(["ls", "-la"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
out, err = proc.communicate()
print(f"Listed {len(out.decode().split(chr(10)))} files")

# socket creation (но без реального подключения)
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.1)
    # Не подключаемся никуда
    s.close()
    print("Socket created and closed")
except Exception as e:
    print(f"Socket error: {e}")

print("Finished!")
