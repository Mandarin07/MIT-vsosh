
import os
import sys
import socket
import json

print(f"Python: {sys.executable}")
print(f"SANDBOX_SOCKET: {os.environ.get('SANDBOX_SOCKET', 'NOT SET')}")

socket_path = os.environ.get('SANDBOX_SOCKET')
_sock = None

if socket_path:
    print(f"Connecting to socket: {socket_path}")
    try:
        _sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        _sock.connect(socket_path)
        _sock.setblocking(False)
        print("Socket connected!")
        
        # Отправляем тестовое событие
        msg = json.dumps({"type": "test", "module": "debug", "function": "init"}) + "\n"
        _sock.send(msg.encode())
        print(f"Sent test event: {msg.strip()}")
    except Exception as e:
        print(f"Socket error: {e}")
        import traceback
        traceback.print_exc()

# Пробуем hunter
try:
    import hunter
    print(f"Hunter imported: {hunter}")
    
    def trace_callback(event):
        print(f"TRACE: {event.kind} - {event.module}.{event.function}")
        if _sock:
            try:
                msg = json.dumps({
                    "type": event.kind,
                    "module": str(event.module or ""),
                    "function": str(event.function or "")
                }) + "\n"
                _sock.send(msg.encode())
            except Exception as e:
                print(f"Send error: {e}")
    
    # Устанавливаем трассировку
    hunter.trace(
        hunter.Q(module_startswith=("subprocess",), kind="call"),
        action=trace_callback
    )
    print("Hunter trace installed!")
    
except Exception as e:
    print(f"Hunter error: {e}")
    import traceback
    traceback.print_exc()

# Теперь делаем вызов
print("\n--- Making subprocess call ---")
import subprocess
result = subprocess.run(["echo", "hello"], capture_output=True, text=True)
print(f"Result: {result.stdout.strip()}")

if _sock:
    _sock.close()
print("\nDone!")
