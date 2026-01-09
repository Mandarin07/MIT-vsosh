#!/usr/bin/env python3
"""
Sandbox Analysis Agent
Runs inside the VM to execute and monitor suspicious files
"""

import os
import sys
import json
import time
import socket
import signal
import hashlib
import logging
import tempfile
import threading
import subprocess
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('/tmp/agent.log')
    ]
)
logger = logging.getLogger(__name__)


@dataclass
class SyscallEvent:
    """Syscall trace event"""
    timestamp: float
    syscall: str
    args: List[str]
    result: str
    pid: int


@dataclass
class FileEvent:
    """File system event"""
    timestamp: float
    event_type: str  # create, modify, delete, open, read, write
    path: str
    pid: int


@dataclass
class NetworkEvent:
    """Network activity event"""
    timestamp: float
    event_type: str  # connect, bind, dns, http
    src_addr: str
    dst_addr: str
    dst_port: int
    protocol: str
    data: str = ""


@dataclass
class ProcessEvent:
    """Process activity event"""
    timestamp: float
    event_type: str  # spawn, exit
    pid: int
    ppid: int
    cmdline: str
    exit_code: Optional[int] = None


@dataclass
class AnalysisResult:
    """Complete analysis result"""
    success: bool
    file_hash: str
    start_time: float
    end_time: float
    duration: float
    exit_code: Optional[int]
    stdout: str
    stderr: str
    syscalls: List[Dict] = field(default_factory=list)
    files: List[Dict] = field(default_factory=list)
    network: List[Dict] = field(default_factory=list)
    processes: List[Dict] = field(default_factory=list)
    events: List[Dict] = field(default_factory=list)
    error: Optional[str] = None


class SyscallTracer:
    """Trace syscalls using strace"""
    
    def __init__(self):
        self.events: List[SyscallEvent] = []
        self._process: Optional[subprocess.Popen] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
    
    def start(self, pid: int):
        """Start tracing a process"""
        self._running = True
        self._thread = threading.Thread(target=self._trace, args=(pid,), daemon=True)
        self._thread.start()
    
    def _trace(self, pid: int):
        """Run strace in background"""
        try:
            self._process = subprocess.Popen(
                ['strace', '-f', '-tt', '-T', '-p', str(pid),
                 '-e', 'trace=file,process,network,desc'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            for line in self._process.stderr:
                if not self._running:
                    break
                self._parse_strace_line(line.strip())
                
        except Exception as e:
            logger.error(f"Strace error: {e}")
    
    def _parse_strace_line(self, line: str):
        """Parse strace output line"""
        try:
            # Format: [pid 123] 12:34:56.789 syscall(args) = result <time>
            if not line or line.startswith('---') or line.startswith('+++'):
                return
            
            parts = line.split()
            if len(parts) < 3:
                return
            
            # Extract timestamp
            timestamp = time.time()
            
            # Find syscall
            syscall_start = line.find('(')
            if syscall_start == -1:
                return
            
            syscall_end = line.rfind(')')
            if syscall_end == -1:
                return
            
            # Get syscall name
            for i, c in enumerate(line):
                if c == '(':
                    syscall_name = line[:i].split()[-1]
                    break
            else:
                return
            
            args_str = line[syscall_start+1:syscall_end]
            args = [a.strip() for a in args_str.split(',')]
            
            # Get result
            result_part = line[syscall_end+1:].strip()
            result = result_part.split('=')[1].strip() if '=' in result_part else ""
            
            event = SyscallEvent(
                timestamp=timestamp,
                syscall=syscall_name,
                args=args,
                result=result,
                pid=0
            )
            self.events.append(event)
            
        except Exception:
            pass
    
    def stop(self):
        """Stop tracing"""
        self._running = False
        if self._process:
            self._process.terminate()
            try:
                self._process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self._process.kill()
    
    def get_events(self) -> List[Dict]:
        return [asdict(e) for e in self.events]


class FileMonitor:
    """Monitor file system changes using inotify"""
    
    def __init__(self, watch_paths: List[str] = None):
        self.events: List[FileEvent] = []
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self.watch_paths = watch_paths or ['/tmp', '/home', '/etc', '/var']
    
    def start(self):
        """Start monitoring"""
        self._running = True
        self._thread = threading.Thread(target=self._monitor, daemon=True)
        self._thread.start()
    
    def _monitor(self):
        """Run inotifywait"""
        try:
            cmd = ['inotifywait', '-m', '-r', '--format', '%T %w%f %e', '--timefmt', '%s']
            cmd.extend(self.watch_paths)
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True
            )
            
            for line in process.stdout:
                if not self._running:
                    break
                self._parse_inotify_line(line.strip())
            
            process.terminate()
            
        except Exception as e:
            logger.error(f"File monitor error: {e}")
    
    def _parse_inotify_line(self, line: str):
        """Parse inotifywait output"""
        try:
            parts = line.split()
            if len(parts) < 3:
                return
            
            timestamp = float(parts[0])
            path = parts[1]
            event_type = parts[2].lower()
            
            # Map inotify events
            type_map = {
                'create': 'create',
                'delete': 'delete',
                'modify': 'modify',
                'open': 'open',
                'access': 'read',
                'close_write': 'write'
            }
            
            mapped_type = type_map.get(event_type, event_type)
            
            event = FileEvent(
                timestamp=timestamp,
                event_type=mapped_type,
                path=path,
                pid=0
            )
            self.events.append(event)
            
        except Exception:
            pass
    
    def stop(self):
        """Stop monitoring"""
        self._running = False
    
    def get_events(self) -> List[Dict]:
        return [asdict(e) for e in self.events]


class NetworkMonitor:
    """Monitor network activity"""
    
    def __init__(self):
        self.events: List[NetworkEvent] = []
        self._process: Optional[subprocess.Popen] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
    
    def start(self):
        """Start network monitoring"""
        self._running = True
        self._thread = threading.Thread(target=self._monitor, daemon=True)
        self._thread.start()
    
    def _monitor(self):
        """Run tcpdump"""
        try:
            self._process = subprocess.Popen(
                ['tcpdump', '-l', '-n', '-q', '-i', 'any',
                 'port 53 or port 80 or port 443 or port 8080'],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True
            )
            
            for line in self._process.stdout:
                if not self._running:
                    break
                self._parse_tcpdump_line(line.strip())
                
        except Exception as e:
            logger.error(f"Network monitor error: {e}")
    
    def _parse_tcpdump_line(self, line: str):
        """Parse tcpdump output"""
        try:
            # Example: 12:34:56.123456 IP 192.168.1.1.12345 > 8.8.8.8.53: UDP, length 64
            parts = line.split()
            if len(parts) < 5:
                return
            
            timestamp = time.time()
            
            # Find IP addresses
            src = ""
            dst = ""
            port = 0
            protocol = "tcp"
            
            for i, part in enumerate(parts):
                if '>' in part and i > 0:
                    src = parts[i-1].rsplit('.', 1)[0]
                    dst_parts = parts[i+1].rstrip(':').rsplit('.', 1)
                    dst = dst_parts[0]
                    if len(dst_parts) > 1 and dst_parts[1].isdigit():
                        port = int(dst_parts[1])
            
            if 'UDP' in line:
                protocol = "udp"
            
            event = NetworkEvent(
                timestamp=timestamp,
                event_type='connect',
                src_addr=src,
                dst_addr=dst,
                dst_port=port,
                protocol=protocol
            )
            self.events.append(event)
            
        except Exception:
            pass
    
    def stop(self):
        """Stop monitoring"""
        self._running = False
        if self._process:
            self._process.terminate()
    
    def get_events(self) -> List[Dict]:
        return [asdict(e) for e in self.events]


class SandboxAgent:
    """Main sandbox agent"""
    
    def __init__(self):
        self.virtio_path = "/dev/virtio-ports/org.sandbox.agent"
        self._running = False
        self._sock: Optional[socket.socket] = None
    
    def _get_file_hash(self, path: str) -> str:
        """Calculate SHA256 hash of file"""
        h = hashlib.sha256()
        try:
            with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ""
    
    def _detect_file_type(self, path: str) -> str:
        """Detect file type"""
        try:
            result = subprocess.run(['file', '-b', path], capture_output=True, text=True, timeout=5)
            return result.stdout.strip().lower()
        except Exception:
            return "unknown"
    
    def _make_executable(self, path: str):
        """Make file executable"""
        try:
            os.chmod(path, 0o755)
        except Exception:
            pass
    
    def analyze(self, file_path: str, timeout: int = 60) -> AnalysisResult:
        """Run analysis on a file"""
        logger.info(f"Analyzing: {file_path}")
        
        start_time = time.time()
        file_hash = self._get_file_hash(file_path)
        file_type = self._detect_file_type(file_path)
        
        # Initialize monitors
        file_monitor = FileMonitor()
        network_monitor = NetworkMonitor()
        syscall_tracer = SyscallTracer()
        
        # Determine how to execute
        if 'python' in file_type or file_path.endswith('.py'):
            cmd = ['python3', file_path]
        elif 'node' in file_type or file_path.endswith('.js'):
            cmd = ['node', file_path]
        elif 'shell' in file_type or file_path.endswith('.sh'):
            cmd = ['/bin/bash', file_path]
        elif 'elf' in file_type or 'executable' in file_type:
            self._make_executable(file_path)
            cmd = [file_path]
        else:
            # Try to execute directly
            self._make_executable(file_path)
            cmd = [file_path]
        
        logger.info(f"Executing: {' '.join(cmd)}")
        
        # Start monitors
        file_monitor.start()
        network_monitor.start()
        
        stdout = ""
        stderr = ""
        exit_code = None
        error = None
        
        try:
            # Run the file
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                cwd=os.path.dirname(file_path) or '/tmp',
                env={**os.environ, 'HOME': '/tmp', 'TERM': 'xterm'}
            )
            
            # Start syscall tracing
            syscall_tracer.start(process.pid)
            
            # Wait for completion or timeout
            try:
                stdout, stderr = process.communicate(timeout=timeout)
                stdout = stdout.decode('utf-8', errors='ignore')
                stderr = stderr.decode('utf-8', errors='ignore')
                exit_code = process.returncode
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                stdout = stdout.decode('utf-8', errors='ignore')
                stderr = stderr.decode('utf-8', errors='ignore')
                error = "Timeout"
                exit_code = -1
                
        except Exception as e:
            error = str(e)
            logger.error(f"Execution error: {e}")
        
        # Stop monitors
        file_monitor.stop()
        network_monitor.stop()
        syscall_tracer.stop()
        
        # Wait a bit for events to be collected
        time.sleep(0.5)
        
        end_time = time.time()
        
        result = AnalysisResult(
            success=error is None,
            file_hash=file_hash,
            start_time=start_time,
            end_time=end_time,
            duration=end_time - start_time,
            exit_code=exit_code,
            stdout=stdout[:10000],  # Limit size
            stderr=stderr[:10000],
            syscalls=syscall_tracer.get_events(),
            files=file_monitor.get_events(),
            network=network_monitor.get_events(),
            processes=[],
            events=[],
            error=error
        )
        
        logger.info(f"Analysis complete: {result.duration:.2f}s, exit={exit_code}")
        return result
    
    def handle_command(self, command: Dict[str, Any]) -> Dict[str, Any]:
        """Handle a command from the host"""
        cmd = command.get('command', '')
        
        if cmd == 'ping':
            return {'success': True, 'message': 'pong', 'time': time.time()}
        
        elif cmd == 'analyze':
            file_path = command.get('file_path')
            timeout = command.get('timeout', 60)
            
            if not file_path or not os.path.exists(file_path):
                return {'success': False, 'error': 'File not found'}
            
            result = self.analyze(file_path, timeout)
            return asdict(result)
        
        elif cmd == 'execute':
            cmd_line = command.get('cmd')
            timeout = command.get('timeout', 30)
            
            try:
                result = subprocess.run(
                    cmd_line,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )
                return {
                    'success': True,
                    'stdout': result.stdout,
                    'stderr': result.stderr,
                    'exit_code': result.returncode
                }
            except subprocess.TimeoutExpired:
                return {'success': False, 'error': 'Timeout'}
            except Exception as e:
                return {'success': False, 'error': str(e)}
        
        elif cmd == 'write_file':
            path = command.get('path')
            data = command.get('data', '')
            mode = command.get('mode', 0o644)
            
            try:
                file_data = bytes.fromhex(data)
                with open(path, 'wb') as f:
                    f.write(file_data)
                os.chmod(path, mode)
                return {'success': True}
            except Exception as e:
                return {'success': False, 'error': str(e)}
        
        elif cmd == 'read_file':
            path = command.get('path')
            
            try:
                with open(path, 'rb') as f:
                    data = f.read()
                return {'success': True, 'data': data.hex()}
            except Exception as e:
                return {'success': False, 'error': str(e)}
        
        elif cmd == 'status':
            return {
                'success': True,
                'hostname': socket.gethostname(),
                'time': time.time(),
                'uptime': self._get_uptime()
            }
        
        else:
            return {'success': False, 'error': f'Unknown command: {cmd}'}
    
    def _get_uptime(self) -> float:
        """Get system uptime"""
        try:
            with open('/proc/uptime', 'r') as f:
                return float(f.read().split()[0])
        except Exception:
            return 0
    
    def run_virtio(self):
        """Run agent listening on virtio-serial port"""
        logger.info(f"Starting agent on virtio port: {self.virtio_path}")
        
        while not os.path.exists(self.virtio_path):
            logger.info("Waiting for virtio port...")
            time.sleep(1)
        
        self._running = True
        
        while self._running:
            try:
                with open(self.virtio_path, 'r+b', buffering=0) as port:
                    logger.info("Connected to virtio port")
                    buffer = b''
                    
                    while self._running:
                        data = port.read(4096)
                        if data:
                            buffer += data
                            
                            while b'\n' in buffer:
                                line, buffer = buffer.split(b'\n', 1)
                                try:
                                    command = json.loads(line.decode())
                                    response = self.handle_command(command)
                                    port.write((json.dumps(response) + '\n').encode())
                                except json.JSONDecodeError:
                                    pass
                        else:
                            time.sleep(0.1)
                            
            except Exception as e:
                logger.error(f"Virtio error: {e}")
                time.sleep(1)
    
    def run_socket(self, socket_path: str = "/tmp/agent.sock"):
        """Run agent listening on Unix socket (for testing)"""
        logger.info(f"Starting agent on socket: {socket_path}")
        
        if os.path.exists(socket_path):
            os.unlink(socket_path)
        
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.bind(socket_path)
        self._sock.listen(5)
        os.chmod(socket_path, 0o777)
        
        self._running = True
        
        while self._running:
            try:
                client, _ = self._sock.accept()
                threading.Thread(target=self._handle_client, args=(client,), daemon=True).start()
            except Exception as e:
                if self._running:
                    logger.error(f"Socket error: {e}")
    
    def _handle_client(self, client: socket.socket):
        """Handle a client connection"""
        buffer = b''
        try:
            while self._running:
                data = client.recv(4096)
                if not data:
                    break
                buffer += data
                
                while b'\n' in buffer:
                    line, buffer = buffer.split(b'\n', 1)
                    try:
                        command = json.loads(line.decode())
                        response = self.handle_command(command)
                        client.send((json.dumps(response) + '\n').encode())
                    except json.JSONDecodeError:
                        pass
        except Exception as e:
            logger.error(f"Client error: {e}")
        finally:
            client.close()
    
    def stop(self):
        """Stop the agent"""
        self._running = False
        if self._sock:
            self._sock.close()


def main():
    agent = SandboxAgent()
    
    # Handle signals
    def signal_handler(sig, frame):
        logger.info("Shutting down...")
        agent.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Check for virtio port
    if os.path.exists("/dev/virtio-ports/org.sandbox.agent"):
        agent.run_virtio()
    else:
        # Fallback to socket mode
        agent.run_socket()


if __name__ == "__main__":
    main()
