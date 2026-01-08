
import subprocess
import socket

print("Starting traced script...")

# subprocess call
result = subprocess.run(["echo", "hello from subprocess"], capture_output=True, text=True)
print(f"Result: {result.stdout.strip()}")

# Ещё один вызов
proc = subprocess.Popen(["ls", "-la"], stdout=subprocess.PIPE)
out, _ = proc.communicate()
print(f"Listed files")

# Socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.close()

print("Script done!")
