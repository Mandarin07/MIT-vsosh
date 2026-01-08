
import subprocess
import os

# Это должно быть перехвачено hunter
print("Calling subprocess.run...")
result = subprocess.run(["echo", "traced!"], capture_output=True, text=True)
print(f"Result: {result.stdout.strip()}")

print("Calling subprocess.Popen...")
proc = subprocess.Popen(["ls", "-la"], stdout=subprocess.PIPE)
out, _ = proc.communicate()
print(f"Listed {len(out.decode().split(chr(10)))} lines")

print("Done!")
