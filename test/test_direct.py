
import os
import subprocess
print("Hello from direct run!")
result = subprocess.run(["whoami"], capture_output=True, text=True)
print(f"User: {result.stdout.strip()}")
print("Done!")
