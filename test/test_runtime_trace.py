
import subprocess
import socket

print("=== Выполнение подозрительных операций ===")

# subprocess.run
result = subprocess.run(["echo", "hello from subprocess"], capture_output=True, text=True)
print(f"subprocess.run: {result.stdout.strip()}")

# subprocess.Popen  
proc = subprocess.Popen(["ls", "-la"], stdout=subprocess.PIPE)
out, _ = proc.communicate()
print(f"subprocess.Popen: listed {len(out.decode().split(chr(10)))} lines")

# socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.close()
print("socket: created and closed")

print("=== Завершено ===")
