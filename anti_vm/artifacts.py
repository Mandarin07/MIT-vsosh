"""
User Artifacts Generator - Create realistic user environment

Malware often checks for signs of a real user environment:
- User documents and files
- Browser history
- Installed applications
- Recent files
- Desktop items
- Bash/shell history

This module generates realistic user artifacts to make the VM 
appear like an actively used system.
"""

import os
import random
import sqlite3
import time
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime, timedelta


@dataclass
class BrowserHistoryEntry:
    """Browser history entry"""
    url: str
    title: str
    visit_count: int = 1
    last_visit_time: Optional[float] = None


@dataclass
class UserFile:
    """User file specification"""
    path: str
    content: bytes
    mtime: Optional[float] = None


@dataclass
class ArtifactsConfig:
    """Artifacts generation configuration"""
    
    # Base user home directory
    home_dir: str = "/home/user"
    
    # Number of items to generate
    num_documents: int = 20
    num_pictures: int = 15
    num_downloads: int = 10
    num_history_entries: int = 100
    
    # Time range for file dates (days back)
    date_range_days: int = 90
    
    # Generate bash history
    bash_history: bool = True
    
    # Generate browser history
    browser_history: bool = True


# Common website URLs for browser history
COMMON_URLS = [
    ("https://www.google.com/", "Google"),
    ("https://www.google.com/search?q=weather", "weather - Google Search"),
    ("https://www.google.com/search?q=python+tutorial", "python tutorial - Google Search"),
    ("https://www.youtube.com/", "YouTube"),
    ("https://www.youtube.com/watch?v=dQw4w9WgXcQ", "YouTube"),
    ("https://www.facebook.com/", "Facebook"),
    ("https://twitter.com/", "X (Twitter)"),
    ("https://www.reddit.com/", "Reddit"),
    ("https://www.reddit.com/r/programming/", "r/programming"),
    ("https://www.amazon.com/", "Amazon.com"),
    ("https://www.wikipedia.org/", "Wikipedia"),
    ("https://en.wikipedia.org/wiki/Python_(programming_language)", "Python - Wikipedia"),
    ("https://github.com/", "GitHub"),
    ("https://github.com/trending", "Trending repositories on GitHub"),
    ("https://stackoverflow.com/", "Stack Overflow"),
    ("https://stackoverflow.com/questions/tagged/python", "python - Stack Overflow"),
    ("https://www.linkedin.com/", "LinkedIn"),
    ("https://mail.google.com/", "Gmail"),
    ("https://outlook.live.com/", "Outlook"),
    ("https://www.netflix.com/", "Netflix"),
    ("https://www.spotify.com/", "Spotify"),
    ("https://www.twitch.tv/", "Twitch"),
    ("https://discord.com/", "Discord"),
    ("https://slack.com/", "Slack"),
    ("https://zoom.us/", "Zoom"),
    ("https://www.microsoft.com/", "Microsoft"),
    ("https://www.apple.com/", "Apple"),
    ("https://news.ycombinator.com/", "Hacker News"),
    ("https://medium.com/", "Medium"),
    ("https://www.bbc.com/news", "BBC News"),
    ("https://www.cnn.com/", "CNN"),
    ("https://www.nytimes.com/", "The New York Times"),
    ("https://www.weather.com/", "Weather"),
    ("https://maps.google.com/", "Google Maps"),
    ("https://drive.google.com/", "Google Drive"),
    ("https://docs.google.com/", "Google Docs"),
    ("https://www.dropbox.com/", "Dropbox"),
    ("https://www.paypal.com/", "PayPal"),
    ("https://www.ebay.com/", "eBay"),
    ("https://www.walmart.com/", "Walmart"),
]

# Common bash commands for history
COMMON_BASH_COMMANDS = [
    "ls -la",
    "cd Documents",
    "cd Downloads",
    "cd ..",
    "pwd",
    "cat file.txt",
    "nano notes.txt",
    "vim config.yaml",
    "python3 script.py",
    "pip install requests",
    "pip3 list",
    "git status",
    "git pull",
    "git push",
    "git add .",
    "git commit -m 'update'",
    "sudo apt update",
    "sudo apt upgrade",
    "df -h",
    "free -m",
    "htop",
    "top",
    "ps aux",
    "kill -9 1234",
    "grep -r 'error' logs/",
    "find . -name '*.py'",
    "tar -xvf archive.tar.gz",
    "unzip file.zip",
    "wget https://example.com/file",
    "curl -O https://example.com/api",
    "ssh user@server",
    "scp file.txt user@server:",
    "chmod +x script.sh",
    "chown user:user file",
    "./run.sh",
    "make",
    "make install",
    "npm install",
    "npm run build",
    "docker ps",
    "docker-compose up",
    "history",
    "clear",
    "exit",
]

# Document file templates
DOCUMENT_TEMPLATES = {
    'report.docx': b'PK\x03\x04' + b'\x00' * 100,  # Minimal DOCX header
    'budget.xlsx': b'PK\x03\x04' + b'\x00' * 100,  # Minimal XLSX header
    'presentation.pptx': b'PK\x03\x04' + b'\x00' * 100,
    'notes.txt': b'Meeting notes\n\n- Discussed project timeline\n- Budget review\n- Next steps\n',
    'todo.txt': b'TODO List\n\n[ ] Complete report\n[ ] Review code\n[x] Send email\n',
    'readme.md': b'# Project\n\n## Description\n\nThis is a project readme.\n',
}


class ArtifactsGenerator:
    """
    Generates realistic user artifacts for the VM.
    """
    
    def __init__(self, config: Optional[ArtifactsConfig] = None):
        self.config = config or ArtifactsConfig()
    
    def generate_all(self):
        """Generate all artifacts"""
        self.create_directory_structure()
        self.generate_documents()
        self.generate_pictures()
        self.generate_downloads()
        
        if self.config.bash_history:
            self.generate_bash_history()
        
        if self.config.browser_history:
            self.generate_browser_history()
    
    def create_directory_structure(self):
        """Create user directory structure"""
        home = Path(self.config.home_dir)
        
        directories = [
            "Documents",
            "Documents/Work",
            "Documents/Personal",
            "Downloads",
            "Pictures",
            "Pictures/Vacation",
            "Pictures/Screenshots",
            "Videos",
            "Music",
            "Desktop",
            ".config",
            ".config/chromium/Default",
            ".config/google-chrome/Default",
            ".local/share/applications",
            ".cache",
        ]
        
        for d in directories:
            (home / d).mkdir(parents=True, exist_ok=True)
    
    def generate_documents(self):
        """Generate document files"""
        home = Path(self.config.home_dir)
        
        docs_dir = home / "Documents"
        work_dir = home / "Documents/Work"
        personal_dir = home / "Documents/Personal"
        
        # Work documents
        work_files = [
            ("quarterly_report_2024.docx", DOCUMENT_TEMPLATES['report.docx']),
            ("budget_2024.xlsx", DOCUMENT_TEMPLATES['budget.xlsx']),
            ("presentation_final.pptx", DOCUMENT_TEMPLATES['presentation.pptx']),
            ("meeting_notes.txt", DOCUMENT_TEMPLATES['notes.txt']),
            ("project_plan.docx", DOCUMENT_TEMPLATES['report.docx']),
        ]
        
        for name, content in work_files:
            self._write_file_with_random_time(work_dir / name, content)
        
        # Personal documents
        personal_files = [
            ("recipes.txt", b"Chocolate Cake Recipe\n\nIngredients:\n- 2 cups flour\n- 1 cup sugar\n"),
            ("shopping_list.txt", b"Shopping List\n\n- Milk\n- Bread\n- Eggs\n- Butter\n"),
            ("notes.txt", DOCUMENT_TEMPLATES['notes.txt']),
        ]
        
        for name, content in personal_files:
            self._write_file_with_random_time(personal_dir / name, content)
    
    def generate_pictures(self):
        """Generate picture files (minimal valid JPEGs)"""
        home = Path(self.config.home_dir)
        pics_dir = home / "Pictures"
        vacation_dir = home / "Pictures/Vacation"
        
        # Minimal valid JPEG (1x1 pixel red)
        minimal_jpeg = bytes([
            0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01,
            0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xFF, 0xDB, 0x00, 0x43,
            0x00, 0x08, 0x06, 0x06, 0x07, 0x06, 0x05, 0x08, 0x07, 0x07, 0x07, 0x09,
            0x09, 0x08, 0x0A, 0x0C, 0x14, 0x0D, 0x0C, 0x0B, 0x0B, 0x0C, 0x19, 0x12,
            0x13, 0x0F, 0x14, 0x1D, 0x1A, 0x1F, 0x1E, 0x1D, 0x1A, 0x1C, 0x1C, 0x20,
            0x24, 0x2E, 0x27, 0x20, 0x22, 0x2C, 0x23, 0x1C, 0x1C, 0x28, 0x37, 0x29,
            0x2C, 0x30, 0x31, 0x34, 0x34, 0x34, 0x1F, 0x27, 0x39, 0x3D, 0x38, 0x32,
            0x3C, 0x2E, 0x33, 0x34, 0x32, 0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x01,
            0x00, 0x01, 0x01, 0x01, 0x11, 0x00, 0xFF, 0xC4, 0x00, 0x1F, 0x00, 0x00,
            0x01, 0x05, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0xFF, 0xC4, 0x00, 0xB5, 0x10, 0x00, 0x02, 0x01, 0x03,
            0x03, 0x02, 0x04, 0x03, 0x05, 0x05, 0x04, 0x04, 0x00, 0x00, 0x01, 0x7D,
            0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00, 0xFB, 0xD5,
            0xDB, 0x20, 0xBA, 0xA1, 0x02, 0xC6, 0xFF, 0xD9
        ])
        
        # Generate vacation photos
        for i in range(min(5, self.config.num_pictures)):
            self._write_file_with_random_time(
                vacation_dir / f"IMG_{20230801 + i}.jpg",
                minimal_jpeg
            )
        
        # Generate screenshots
        screenshots_dir = home / "Pictures/Screenshots"
        for i in range(3):
            self._write_file_with_random_time(
                screenshots_dir / f"Screenshot_{20240101 + i}.png",
                b'\x89PNG\r\n\x1a\n' + b'\x00' * 50  # Minimal PNG header
            )
    
    def generate_downloads(self):
        """Generate download files"""
        home = Path(self.config.home_dir)
        downloads_dir = home / "Downloads"
        
        files = [
            ("installer.exe", b'MZ' + b'\x00' * 100),  # Minimal PE header
            ("document.pdf", b'%PDF-1.4\n' + b'\x00' * 100),
            ("archive.zip", b'PK\x03\x04' + b'\x00' * 100),
            ("data.csv", b'name,value,date\ntest,123,2024-01-01\n'),
            ("readme.txt", b'Installation Instructions\n\n1. Run installer\n2. Follow prompts\n'),
        ]
        
        for name, content in files:
            self._write_file_with_random_time(downloads_dir / name, content)
    
    def generate_bash_history(self):
        """Generate bash history file"""
        home = Path(self.config.home_dir)
        history_file = home / ".bash_history"
        
        # Generate random command history
        commands = []
        for _ in range(200):
            cmd = random.choice(COMMON_BASH_COMMANDS)
            commands.append(cmd)
        
        history_file.write_text('\n'.join(commands) + '\n')
        
        # Set reasonable mtime
        self._set_random_time(history_file)
    
    def generate_browser_history(self):
        """Generate browser history database"""
        home = Path(self.config.home_dir)
        
        # Chromium history
        chromium_dir = home / ".config/chromium/Default"
        chromium_dir.mkdir(parents=True, exist_ok=True)
        
        self._create_chrome_history(chromium_dir / "History")
        
        # Google Chrome history
        chrome_dir = home / ".config/google-chrome/Default"
        chrome_dir.mkdir(parents=True, exist_ok=True)
        
        self._create_chrome_history(chrome_dir / "History")
    
    def _create_chrome_history(self, db_path: Path):
        """Create Chrome/Chromium history SQLite database"""
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        
        # Create tables (simplified Chrome schema)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS urls (
                id INTEGER PRIMARY KEY,
                url TEXT NOT NULL,
                title TEXT,
                visit_count INTEGER DEFAULT 1,
                typed_count INTEGER DEFAULT 0,
                last_visit_time INTEGER,
                hidden INTEGER DEFAULT 0
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS visits (
                id INTEGER PRIMARY KEY,
                url INTEGER NOT NULL,
                visit_time INTEGER NOT NULL,
                from_visit INTEGER,
                transition INTEGER DEFAULT 0,
                segment_id INTEGER,
                visit_duration INTEGER DEFAULT 0
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT NOT NULL UNIQUE PRIMARY KEY,
                value TEXT
            )
        ''')
        
        # Insert meta info
        cursor.execute("INSERT OR REPLACE INTO meta VALUES ('version', '48')")
        
        # Generate history entries
        now = time.time()
        day_seconds = 86400
        
        for i in range(self.config.num_history_entries):
            url, title = random.choice(COMMON_URLS)
            
            # Random time in the last N days
            visit_time = now - random.randint(0, self.config.date_range_days * day_seconds)
            # Chrome uses microseconds since Jan 1, 1601
            chrome_time = int((visit_time + 11644473600) * 1000000)
            
            visit_count = random.randint(1, 20)
            
            cursor.execute(
                "INSERT INTO urls (url, title, visit_count, last_visit_time) VALUES (?, ?, ?, ?)",
                (url, title, visit_count, chrome_time)
            )
            url_id = cursor.lastrowid
            
            # Add visit record
            cursor.execute(
                "INSERT INTO visits (url, visit_time, visit_duration) VALUES (?, ?, ?)",
                (url_id, chrome_time, random.randint(1000, 300000))
            )
        
        conn.commit()
        conn.close()
    
    def _write_file_with_random_time(self, path: Path, content: bytes):
        """Write file with random modification time"""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        self._set_random_time(path)
    
    def _set_random_time(self, path: Path):
        """Set random modification time on file"""
        now = time.time()
        random_time = now - random.randint(0, self.config.date_range_days * 86400)
        os.utime(path, (random_time, random_time))


def generate_user_artifacts(home_dir: str = "/home/user",
                           num_history: int = 100) -> ArtifactsGenerator:
    """
    Convenience function to generate user artifacts.
    
    Args:
        home_dir: User home directory
        num_history: Number of browser history entries
        
    Returns:
        ArtifactsGenerator instance
    """
    config = ArtifactsConfig(
        home_dir=home_dir,
        num_history_entries=num_history,
    )
    
    generator = ArtifactsGenerator(config)
    generator.generate_all()
    
    return generator
