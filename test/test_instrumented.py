
import os
import sys
import socket
import json

socket_path = os.environ.get('SANDBOX_SOCKET')
print(f"SANDBOX_SOCKET: {socket_path}")

# Подключаемся к сокету если есть
_sock = None
if socket_path:
    try:
        _sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        _sock.connect(socket_path)
        _sock.setblocking(False)
        print("Socket connected!")
    except Exception as e:
        print(f"Socket connect error: {e}")

# Функция отправки события
def send_event(event_type, module, function, cmd=""):
    if _sock:
        try:
            msg = json.dumps({"type": event_type, "module": module, "function": function, "cmd": cmd}) + "\n"
            _sock.send(msg.encode())
        except:
            pass

# Теперь делаем подозрительные вызовы
import subprocess

print("Calling subprocess.run...")
send_event("call", "subprocess", "run", "echo hello")
result = subprocess.run(["echo", "hello"], capture_output=True, text=True)
print(f"Result: {result.stdout.strip()}")

print("Calling subprocess.Popen...")
send_event("call", "subprocess", "Popen", "ls -la")
proc = subprocess.Popen(["ls"], stdout=subprocess.PIPE)
out, _ = proc.communicate()

print("Script completed!")

if _sock:
    _sock.close()
