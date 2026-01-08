
import os
import sys
import socket
import json
import subprocess

socket_path = os.environ.get('SANDBOX_SOCKET')
print(f"Socket path: {socket_path}")

if socket_path:
    try:
        # Подключаемся к серверу
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(socket_path)
        print("Connected to LogServer!")
        
        # Отправляем тестовое событие
        event = {"type": "exec", "module": "subprocess", "function": "run", "cmd": "test command"}
        s.send((json.dumps(event) + "\n").encode())
        print(f"Sent event: {event}")
        
        s.close()
    except Exception as e:
        print(f"Socket error: {e}")
else:
    print("SANDBOX_SOCKET not set!")

# Делаем реальный вызов
result = subprocess.run(["echo", "subprocess test"], capture_output=True, text=True)
print(f"Subprocess result: {result.stdout.strip()}")
