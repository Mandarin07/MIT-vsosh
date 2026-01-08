
import os
import sys

print("=== TEST SCRIPT OUTPUT ===")
print(f"Python version: {sys.version}")
print(f"Working dir: {os.getcwd()}")
print(f"User: {os.getenv('USER', 'unknown')}")

# Простая арифметика
result = sum(range(100))
print(f"Sum 0-99: {result}")

# Тест импортов
try:
    import subprocess
    print("subprocess: imported")
except ImportError as e:
    print(f"subprocess: {e}")

print("=== END TEST ===")
