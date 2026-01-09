"""
Dynamic Analysis Module - VM-based Malware Sandbox

This module provides dynamic analysis capabilities using full VM virtualization
with anti-VM detection countermeasures. All analysis runs in isolated QEMU/KVM
virtual machines with realistic hardware emulation.
"""

import os
import re
import json
import yaml
import time
import math
import socket
import sqlite3
import hashlib
import subprocess
from datetime import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

# Scoring constants
SCORE_MODULES = {
    'subprocess': 15, 'os': 10, 'socket': 15, 'ctypes': 20,
    'requests': 10, 'urllib': 10, 'paramiko': 20,
    'child_process': 15, 'fs': 5, 'net': 15, 'libc': 10
}

SCORE_FUNCTIONS = {
    'system': 20, 'popen': 20, 'exec': 25, 'execSync': 25,
    'eval': 25, 'connect': 15, 'bind': 15, 'spawn': 15
}

# MITRE ATT&CK mapping
MITRE_MAP = {
    ('subprocess', 'Popen'): 'T1059', ('subprocess', 'call'): 'T1059',
    ('subprocess', 'run'): 'T1059', ('os', 'system'): 'T1059',
    ('os', 'popen'): 'T1059', ('socket', 'connect'): 'T1071',
    ('socket', 'bind'): 'T1071', ('child_process', 'exec'): 'T1059',
    ('child_process', 'spawn'): 'T1059', ('net', 'connect'): 'T1071',
    ('ctypes', 'CDLL'): 'T1055', ('requests', 'get'): 'T1071.001',
    ('requests', 'post'): 'T1071.001'
}

# Suspicious ELF imports
SUSPICIOUS_IMPORTS = {
    'setuid': ('T1548', 30, 'Privilege escalation'),
    'setreuid': ('T1548', 30, 'Privilege escalation'),
    'setgid': ('T1548', 25, 'Privilege escalation'),
    'ptrace': ('T1055.008', 20, 'Process injection'),
    'system': ('T1059', 15, 'Command execution'),
    'execve': ('T1059', 10, 'Program execution'),
    'popen': ('T1059', 15, 'Process pipe'),
    'socket': ('T1071', 10, 'Network socket'),
    'connect': ('T1071', 10, 'Network connect'),
    'bind': ('T1071', 10, 'Network bind'),
    'init_module': ('T1547.006', 25, 'Kernel module'),
    'mprotect': ('T1055', 10, 'Memory protection')
}

# Suspicious strings in binaries
SUSPICIOUS_STRINGS = [
    (r'api\.telegram\.org', 'T1102', 20, 'Telegram API'),
    (r'discord\.com', 'T1102', 15, 'Discord'),
    (r'/etc/shadow', 'T1003', 25, 'Shadow file'),
    (r'/etc/passwd', 'T1003', 15, 'Passwd file'),
    (r'\.ssh/', 'T1552.004', 20, 'SSH directory'),
    (r'LD_PRELOAD', 'T1574.006', 15, 'LD_PRELOAD'),
    (r'PTRACE_TRACEME', 'T1622', 15, 'Anti-debugging')
]

# Suspicious network indicators
SUSPICIOUS_TLDS = {
    '.shop', '.fun', '.xyz', '.top', '.club', '.online',
    '.site', '.work', '.click', '.link', '.gq', '.ml',
    '.cf', '.tk', '.ga', '.pw'
}

SUSPICIOUS_HOSTS = {
    'api.telegram.org': ('T1102', 20, 'Telegram Bot API (C2)'),
    'discord.com': ('T1102', 15, 'Discord (exfiltration)'),
    'pastebin.com': ('T1102', 15, 'Pastebin (payload)'),
    'raw.githubusercontent.com': ('T1105', 10, 'GitHub raw'),
    'ipinfo.io': ('T1016', 10, 'IP geolocation'),
    'ip-api.com': ('T1016', 10, 'IP geolocation')
}

# File type detection
FILE_TYPE_MAP = {
    '.py': 'python', '.pyw': 'python',
    '.js': 'javascript', '.mjs': 'javascript',
    '.sh': 'shell', '.bash': 'shell'
}


@dataclass
class ThreatEvent:
    """Represents a detected threat indicator"""
    source: str
    event_type: str
    details: str
    score: int
    mitre: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class YaraMatch:
    """YARA rule match result"""
    rule: str
    description: str
    score: int
    mitre: str = ""
    strings: List[str] = field(default_factory=list)


@dataclass
class AnalysisResult:
    """Complete analysis result"""
    verdict: str
    threat_score: int
    reasons: List[str]
    events: List[ThreatEvent]
    duration: float
    file_type: str
    file_hash: str
    yara_matches: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)


class YaraScanner:
    """YARA-based signature scanner"""
    
    def __init__(self, rules_dir: str = "yara_rules"):
        self.rules_dir = rules_dir
        self.rules = None
        self._available = False
        try:
            import yara
            if os.path.exists(rules_dir):
                rule_files = {
                    f: os.path.join(rules_dir, f)
                    for f in os.listdir(rules_dir)
                    if f.endswith(('.yar', '.yara'))
                }
                if rule_files:
                    self.rules = yara.compile(filepaths=rule_files)
            self._available = self.rules is not None
        except ImportError:
            pass
    
    @property
    def available(self) -> bool:
        return self._available
    
    def scan(self, file_path: str) -> List[YaraMatch]:
        if not self._available or not os.path.exists(file_path):
            return []
        try:
            matches = []
            for m in self.rules.match(file_path):
                meta = m.meta if hasattr(m, 'meta') else {}
                matches.append(YaraMatch(
                    rule=m.rule,
                    description=meta.get('description', m.rule),
                    score=int(meta.get('score', 10)),
                    mitre=meta.get('mitre', ''),
                    strings=[s.identifier for s in (m.strings[:5] if hasattr(m, 'strings') else [])]
                ))
            return matches
        except Exception:
            return []


class ELFAnalyzer:
    """ELF binary static analyzer"""
    
    def __init__(self):
        self._available = False
        try:
            from elftools.elf.elffile import ELFFile
            self._available = True
        except ImportError:
            pass
    
    @property
    def available(self) -> bool:
        return self._available
    
    def analyze(self, file_path: str) -> List[ThreatEvent]:
        if not self._available or not os.path.exists(file_path):
            return []
        events = []
        try:
            from elftools.elf.elffile import ELFFile
            with open(file_path, 'rb') as f:
                elf = ELFFile(f)
                events.extend(self._analyze_imports(elf))
                f.seek(0)
                events.extend(self._analyze_strings(f.read()))
                events.extend(self._analyze_entropy(elf))
        except Exception:
            pass
        return events
    
    def _analyze_imports(self, elf) -> List[ThreatEvent]:
        events, found = [], set()
        try:
            for section in elf.iter_sections():
                if section.name == '.dynstr':
                    for s in section.data().split(b'\x00'):
                        sym = s.decode('utf-8', errors='ignore')
                        if sym in SUSPICIOUS_IMPORTS and sym not in found:
                            found.add(sym)
                            mitre, score, desc = SUSPICIOUS_IMPORTS[sym]
                            events.append(ThreatEvent(
                                source='elf', event_type='import',
                                details=f"{sym}: {desc}", score=score, mitre=mitre
                            ))
        except Exception:
            pass
        return events
    
    def _analyze_strings(self, data: bytes) -> List[ThreatEvent]:
        events, strings, current = [], [], []
        for b in data:
            if 32 <= b <= 126:
                current.append(chr(b))
            else:
                if len(current) >= 4:
                    strings.append(''.join(current))
                current = []
        all_strings = '\n'.join(strings)
        for pattern, mitre, score, desc in SUSPICIOUS_STRINGS:
            if re.search(pattern, all_strings, re.IGNORECASE):
                events.append(ThreatEvent(
                    source='elf', event_type='string',
                    details=desc, score=score, mitre=mitre
                ))
        return events
    
    def _analyze_entropy(self, elf) -> List[ThreatEvent]:
        events = []
        for section in elf.iter_sections():
            if section.name in ['.text', '.data']:
                try:
                    data = section.data()
                    if len(data) > 100:
                        counts = [0] * 256
                        for b in data:
                            counts[b] += 1
                        entropy = -sum(
                            c/len(data) * math.log2(c/len(data))
                            for c in counts if c > 0
                        )
                        if entropy > 7.5:
                            events.append(ThreatEvent(
                                source='elf', event_type='entropy',
                                details=f"High entropy {section.name}: {entropy:.2f}",
                                score=15, mitre='T1027'
                            ))
                except Exception:
                    pass
        return events


class RuleEngine:
    """Pattern-based rule matching engine"""
    
    def __init__(self, patterns_file: str = "patterns.yaml"):
        self.patterns: Dict = {}
        if os.path.exists(patterns_file):
            try:
                with open(patterns_file, 'r', encoding='utf-8') as f:
                    self.patterns = yaml.safe_load(f) or {}
            except Exception:
                pass
    
    def match_script(self, language: str, code: str) -> List[ThreatEvent]:
        events = []
        for category, patterns in self.patterns.get('scripts', {}).get(language, {}).items():
            if isinstance(patterns, list):
                for p in patterns:
                    if isinstance(p, dict) and p.get('pattern'):
                        try:
                            if re.search(p['pattern'], code):
                                events.append(ThreatEvent(
                                    source='script', event_type=category,
                                    details=p.get('description', 'Suspicious pattern'),
                                    score=p.get('score', 10),
                                    mitre=p.get('mitre')
                                ))
                        except Exception:
                            pass
        return events
    
    def get_threshold(self, level: str) -> int:
        return self.patterns.get('verdict_thresholds', {}).get(level, 50)


class ThreatScorer:
    """Aggregates threat events and calculates verdict"""
    
    def __init__(self, rule_engine: Optional[RuleEngine] = None):
        self.events: List[ThreatEvent] = []
        self.total_score = 0
        self.rule_engine = rule_engine or RuleEngine()
    
    def add_event(self, event: ThreatEvent):
        self.events.append(event)
        self.total_score += event.score
    
    def add_events(self, events: List[ThreatEvent]):
        for e in events:
            self.add_event(e)
    
    def add_yara_matches(self, matches: List[YaraMatch]):
        for m in matches:
            self.add_event(ThreatEvent(
                source='yara', event_type='signature',
                details=f"{m.rule}: {m.description}",
                score=m.score, mitre=m.mitre or None
            ))
    
    def get_verdict(self) -> str:
        clean = self.rule_engine.get_threshold('clean')
        suspicious = self.rule_engine.get_threshold('suspicious')
        if self.total_score <= clean:
            return "CLEAN"
        if self.total_score <= suspicious:
            return "SUSPICIOUS"
        return "MALICIOUS"
    
    def get_reasons(self) -> List[str]:
        return [
            f"[{e.source.upper()}] {e.details}" + (f" ({e.mitre})" if e.mitre else "")
            for e in self.events
        ]
    
    def get_mitre_techniques(self) -> List[str]:
        return list({e.mitre for e in self.events if e.mitre})


class AnalysisDB:
    """SQLite database for caching analysis results"""
    
    def __init__(self, db_path: str = "logs/dynamic_analysis.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        with sqlite3.connect(db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS analyses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_hash TEXT NOT NULL,
                    file_name TEXT,
                    file_type TEXT,
                    verdict TEXT,
                    threat_score INTEGER,
                    duration REAL,
                    reasons TEXT,
                    yara_matches TEXT,
                    mitre_techniques TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
    
    def save(self, path: str, result: AnalysisResult) -> int:
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute(
                """INSERT INTO analyses 
                   (file_hash, file_name, file_type, verdict, threat_score, 
                    duration, reasons, yara_matches, mitre_techniques) 
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (result.file_hash, os.path.basename(path), result.file_type,
                 result.verdict, result.threat_score, result.duration,
                 json.dumps(result.reasons), json.dumps(result.yara_matches),
                 json.dumps(result.mitre_techniques))
            )
            return cur.lastrowid
    
    def get_by_hash(self, file_hash: str) -> Optional[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM analyses WHERE file_hash=? ORDER BY created_at DESC LIMIT 1",
                (file_hash,)
            ).fetchone()
        if row:
            return {
                k: json.loads(row[k]) if k in ('reasons', 'yara_matches', 'mitre_techniques') and row[k] else row[k]
                for k in row.keys()
            }
        return None


class DynamicAnalyzer:
    """
    VM-based Dynamic Analyzer with Anti-VM Detection.
    
    This analyzer uses QEMU/KVM virtual machines for executing and monitoring
    suspicious files in an isolated environment with anti-VM detection measures.
    """
    
    def __init__(self, timeout: int = 60, db_path: str = "logs/dynamic_analysis.db",
                 yara_dir: str = "yara_rules", patterns_file: str = "patterns.yaml",
                 vm_config_path: str = "vm_config.yaml"):
        self.timeout = timeout
        self.yara = YaraScanner(yara_dir)
        self.rules = RuleEngine(patterns_file)
        self.elf = ELFAnalyzer()
        self.db = AnalysisDB(db_path)
        self.vm_config_path = vm_config_path
        self._vm_manager = None
        self._vm_available = False
        self._init_vm_manager()
    
    def _init_vm_manager(self):
        """Initialize VM manager if available"""
        try:
            from vm_manager.vm_manager import VMManager
            if os.path.exists(self.vm_config_path):
                self._vm_manager = VMManager(config_path=self.vm_config_path)
                self._vm_available = True
        except ImportError:
            pass
        except Exception as e:
            print(f"[DynamicAnalyzer] VM manager init failed: {e}")
    
    @property
    def vm_available(self) -> bool:
        return self._vm_available and self._vm_manager is not None
    
    def _hash_file(self, path: str) -> str:
        h = hashlib.sha256()
        try:
            with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ''
    
    def _detect_type(self, path: str) -> str:
        ext = os.path.splitext(path)[1].lower()
        if ext in FILE_TYPE_MAP:
            return FILE_TYPE_MAP[ext]
        try:
            info = subprocess.run(
                ['file', '-b', path],
                capture_output=True, text=True, timeout=5
            ).stdout.lower()
            if 'elf' in info:
                if 'x86-64' in info or 'amd64' in info:
                    return 'elf_x64'
                if 'aarch64' in info or 'arm64' in info:
                    return 'elf_arm64'
                return 'elf'
            if 'python' in info:
                return 'python'
            if 'shell' in info:
                return 'shell'
        except Exception:
            pass
        return 'unknown'
    
    def run(self, file_path: str, use_cache: bool = True,
            architecture: str = None) -> Dict:
        """
        Run dynamic analysis on a file.
        
        Args:
            file_path: Path to file to analyze
            use_cache: Use cached results if available
            architecture: Force specific architecture (arm64, x64)
            
        Returns:
            Analysis result dictionary
        """
        start = time.time()
        
        if not os.path.exists(file_path):
            return {'verdict': 'ERROR', 'threat_score': 0, 'reasons': ['File not found']}
        
        file_hash = self._hash_file(file_path)
        
        # Check cache
        if use_cache and file_hash:
            cached = self.db.get_by_hash(file_hash)
            if cached:
                cached['cached'] = True
                return cached
        
        scorer = ThreatScorer(self.rules)
        file_type = self._detect_type(file_path)
        
        # Static analysis (YARA)
        scorer.add_yara_matches(self.yara.scan(file_path))
        
        # Script pattern matching
        if file_type in ['python', 'javascript', 'shell']:
            try:
                with open(file_path, 'r', errors='ignore') as f:
                    scorer.add_events(self.rules.match_script(file_type, f.read()))
            except Exception:
                pass
        
        # ELF analysis
        elif file_type.startswith('elf'):
            scorer.add_events(self.elf.analyze(file_path))
        
        # Dynamic analysis in VM
        sandbox_result = {}
        vm_used = False
        
        if self.vm_available:
            sandbox_result = self._run_in_vm(file_path, file_type, architecture)
            vm_used = True
            
            # Process VM events
            if sandbox_result.get('success'):
                self._process_vm_events(scorer, sandbox_result)
        else:
            sandbox_result = {'error': 'VM not available', 'success': False}
        
        duration = time.time() - start
        
        result = AnalysisResult(
            verdict=scorer.get_verdict(),
            threat_score=min(scorer.total_score, 100),
            reasons=scorer.get_reasons(),
            events=scorer.events,
            duration=duration,
            file_type=file_type,
            file_hash=file_hash,
            yara_matches=[m.rule for m in self.yara.scan(file_path)],
            mitre_techniques=scorer.get_mitre_techniques()
        )
        
        # Save to database
        try:
            self.db.save(file_path, result)
        except Exception:
            pass
        
        return {
            'verdict': result.verdict,
            'threat_score': result.threat_score,
            'duration': result.duration,
            'reasons': result.reasons,
            'file_type': result.file_type,
            'file_hash': result.file_hash,
            'yara_matches': result.yara_matches,
            'mitre_techniques': result.mitre_techniques,
            'sandbox': sandbox_result,
            'event_count': len(scorer.events),
            'vm_used': vm_used,
        }
    
    def _process_vm_events(self, scorer: ThreatScorer, sandbox_result: Dict):
        """Process events from VM analysis"""
        # Syscall events
        for event in sandbox_result.get('syscalls', []):
            syscall = event.get('syscall', '')
            if syscall in ['execve', 'execveat']:
                scorer.add_event(ThreatEvent(
                    source='vm', event_type='syscall',
                    details=f"exec: {event.get('args', [''])[0][:100]}",
                    score=10, mitre='T1059'
                ))
            elif syscall in ['connect', 'bind']:
                scorer.add_event(ThreatEvent(
                    source='vm', event_type='syscall',
                    details=f"network: {syscall}",
                    score=10, mitre='T1071'
                ))
            elif syscall == 'ptrace':
                scorer.add_event(ThreatEvent(
                    source='vm', event_type='syscall',
                    details='ptrace call detected',
                    score=20, mitre='T1055.008'
                ))
        
        # Network events
        for event in sandbox_result.get('network', []):
            dst = event.get('dst_addr', '')
            port = event.get('dst_port', 0)
            
            # Check for suspicious hosts
            for host, (mitre, score, desc) in SUSPICIOUS_HOSTS.items():
                if host in dst:
                    scorer.add_event(ThreatEvent(
                        source='vm', event_type='network',
                        details=f"{desc}: {dst}:{port}",
                        score=score, mitre=mitre
                    ))
                    break
            else:
                scorer.add_event(ThreatEvent(
                    source='vm', event_type='network',
                    details=f"connection to {dst}:{port}",
                    score=5, mitre='T1071'
                ))
        
        # File events
        for event in sandbox_result.get('files', []):
            path = event.get('path', '')
            event_type = event.get('event_type', '')
            
            # Check for sensitive file access
            if '/etc/shadow' in path or '/etc/passwd' in path:
                scorer.add_event(ThreatEvent(
                    source='vm', event_type='file',
                    details=f"sensitive file access: {path}",
                    score=20, mitre='T1003'
                ))
            elif '/.ssh/' in path:
                scorer.add_event(ThreatEvent(
                    source='vm', event_type='file',
                    details=f"SSH directory access: {path}",
                    score=15, mitre='T1552.004'
                ))
    
    def _run_in_vm(self, file_path: str, file_type: str,
                   architecture: str = None) -> Dict:
        """Run file in VM sandbox"""
        if not self._vm_manager:
            return {'error': 'VM manager not available', 'success': False}
        
        try:
            from vm_manager.vm_config import VMArchitecture
            
            # Determine architecture
            if architecture:
                arch = VMArchitecture.ARM64 if 'arm' in architecture.lower() else VMArchitecture.X64
            elif file_type == 'elf_arm64':
                arch = VMArchitecture.ARM64
            elif file_type == 'elf_x64':
                arch = VMArchitecture.X64
            else:
                # Default to ARM64 (native on RPi5)
                arch = VMArchitecture.ARM64
            
            # Run analysis
            result = self._vm_manager.analyze_file(
                file_path, arch=arch, timeout=self.timeout
            )
            
            return {
                'success': result.success,
                'error': result.error,
                'duration': result.duration,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'exit_code': result.exit_code,
                'syscalls': result.syscalls,
                'network': result.network_activity,
                'files': result.file_activity,
                'processes': result.process_activity,
                'events': result.events,
                'architecture': result.architecture,
            }
            
        except Exception as e:
            return {'error': str(e), 'success': False}
    
    def start_vm(self, architecture: str = 'arm64') -> bool:
        """Start VM for specified architecture"""
        if not self._vm_manager:
            return False
        
        try:
            from vm_manager.vm_config import VMArchitecture
            arch = VMArchitecture.ARM64 if 'arm' in architecture.lower() else VMArchitecture.X64
            return self._vm_manager.start_vm(arch)
        except Exception as e:
            print(f"[DynamicAnalyzer] Failed to start VM: {e}")
            return False
    
    def stop_vm(self, architecture: str = None):
        """Stop VM(s)"""
        if not self._vm_manager:
            return
        
        if architecture:
            try:
                from vm_manager.vm_config import VMArchitecture
                arch = VMArchitecture.ARM64 if 'arm' in architecture.lower() else VMArchitecture.X64
                self._vm_manager.stop_vm(arch)
            except Exception:
                pass
        else:
            self._vm_manager.stop_all()
    
    def get_status(self) -> Dict:
        """Get analyzer status"""
        status = {
            'yara_available': self.yara.available,
            'elf_analyzer': self.elf.available,
            'rules_loaded': len(self.rules.patterns) > 0,
            'vm_available': self.vm_available,
        }
        
        if self._vm_manager:
            try:
                vm_status = self._vm_manager.get_status()
                status['vm_arm64_running'] = vm_status.get('arm64', {}).get('running', False)
                status['vm_x64_running'] = vm_status.get('x64', {}).get('running', False)
            except Exception:
                pass
        
        return status
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._vm_manager:
            self._vm_manager.stop_all()


# Backward compatibility alias
VMDynamicAnalyzer = DynamicAnalyzer
