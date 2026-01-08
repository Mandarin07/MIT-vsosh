
import os
import sys
import socket
import json

# Настраиваем hunter
try:
    import hunter
    
    socket_path = os.environ.get('SANDBOX_SOCKET')
    print(f"Socket path: {socket_path}")
    
    if socket_path:
        # Создаём сокет
        _sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        _sock.connect(socket_path)
        _sock.setblocking(False)
        print("Socket connected!")
        
        def send_event(event):
            try:
                msg = json.dumps({
                    "type": event.kind,
                    "module": str(event.module or ""),
                    "function": str(event.function or ""),
                    "cmd": ""
                }) + "\n"
                _sock.send(msg.encode())
                print(f"Sent: {msg.strip()}")
            except Exception as e:
                print(f"Send error: {e}")
        
        # Устанавливаем трассировку
        hunter.trace(
            hunter.Q(module_startswith=("os", "subprocess", "socket"), kind="call"),
            action=send_event
        )
        print("Hunter trace installed!")
except Exception as e:
    print(f"Hunter setup error: {e}")
    import traceback
    traceback.print_exc()

# Теперь делаем вызовы
import subprocess
print("\n=== Making calls ===")
result = subprocess.run(["echo", "test"], capture_output=True, text=True)
print(f"subprocess.run result: {result.stdout.strip()}")

print("\nDone!")
