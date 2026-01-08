
import os
import subprocess

# Эти вызовы должны быть перехвачены
result = subprocess.run(["echo", "Hello from subprocess"], capture_output=True, text=True)
print(f"Subprocess result: {result.stdout.strip()}")

# os.system тоже должен перехватиться
# os.system("echo 'Hello from os.system'")

print("Script completed!")
