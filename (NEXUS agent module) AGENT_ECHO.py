#!/usr/bin/env python3
"""
AGENT_ECHO v3.2 - Secure Communications Monitor
Advanced monitoring system with ML capabilities, optimized for Android environment
with full Nexus Dashboard integration.

Version: NEXUS 9.0
Security Level: Enhanced
"""

import os
import sys
import time
import json
import logging
import hashlib
import sqlite3
import threading
import queue
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict
from contextlib import contextmanager
import tempfile
import re
import secrets
import traceback

# Version and constants
VERSION = "3.2.0-NEXUS"
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit
MAX_QUEUE_SIZE = 1000
HEARTBEAT_INTERVAL = 30

# ======================== NEXUS INTEGRATION CONFIGURATION ========================

class NexusIntegration:
    """Configuration for Nexus Dashboard integration"""
    
    # Use Nexus-compatible paths
    STORAGE_PATHS = [
        "/storage/emulated/0/EDS_VAULT_2/echo_data",
        "/storage/emulated/0/EDS_VAULT_2/",
        "/sdcard/EDS_VAULT_2/echo_data", 
        "./EDS_VAULT_2/echo_data",
        "./agents/echo_data",
        "/data/data/ru.iiec.pydroid3/files/echo_data",
        "./echo_data"
    ]
    
    # Nexus-compatible color scheme
    class Colors:
        RESET = "\033[0m"
        HEADER = "\033[38;5;75m"
        SUCCESS = "\033[38;5;46m"
        WARNING = "\033[38;5;214m"
        ERROR = "\033[38;5;196m"
        INFO = "\033[38;5;123m"
        MUTED = "\033[38;5;245m"
        TEXT = "\033[38;5;255m"
    
    # Security constraints
    MAX_COMMANDS = 100
    COMMAND_TIMEOUT = 30.0
    MAX_LOG_SIZE = 5 * 1024 * 1024  # 5MB

# ======================== SECURE CONFIGURATION ========================

@dataclass
class EchoConfig:
    """Secure configuration for ECHO agent"""
    
    base_path: Path = field(default_factory=lambda: Path(tempfile.gettempdir()) / "echo_agent")
    inbox_path: Path = field(default_factory=lambda: Path(tempfile.gettempdir()) / "echo_agent" / "inbox")
    log_path: Path = field(default_factory=lambda: Path(tempfile.gettempdir()) / "echo_agent" / "logs")
    archive_path: Path = field(default_factory=lambda: Path(tempfile.gettempdir()) / "echo_agent" / "archive")
    
    poll_interval: float = 3.0
    worker_threads: int = 2
    max_file_size: int = MAX_FILE_SIZE
    command_timeout: float = 30.0
    heartbeat_interval: int = HEARTBEAT_INTERVAL
    
    def __post_init__(self):
        """Validate and create paths"""
        try:
            for path in [self.base_path, self.inbox_path, self.log_path, self.archive_path]:
                path.mkdir(parents=True, exist_ok=True, mode=0o750)
        except Exception as e:
            print(f"Warning: Could not create paths: {e}")

# ======================== SECURE LOGGER ========================

class SecureLogger:
    """Secure logging with rate limiting and sanitization"""
    
    def __init__(self, name: str, log_path: Path):
        self.name = name
        self.log_path = log_path
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        self.event_queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)
        self._setup_handlers()
        
        # Start background logging thread
        self.log_thread = threading.Thread(target=self._log_worker, daemon=True)
        self.log_thread.start()
    
    def _setup_handlers(self):
        """Setup logging handlers with security"""
        try:
            # Console handler
            console_handler = logging.StreamHandler()
            console_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            console_handler.setFormatter(console_formatter)
            self.logger.addHandler(console_handler)
            
            # File handler (if possible)
            try:
                from logging.handlers import RotatingFileHandler
                log_file = self.log_path / "echo.log"
                file_handler = RotatingFileHandler(
                    log_file, maxBytes=NexusIntegration.MAX_LOG_SIZE, backupCount=3
                )
                file_formatter = logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                )
                file_handler.setFormatter(file_formatter)
                self.logger.addHandler(file_handler)
            except Exception:
                pass  # Continue without file logging if not available
                
        except Exception as e:
            print(f"Logger setup failed: {e}")
    
    def _log_worker(self):
        """Background thread for processing log events"""
        while True:
            try:
                event = self.event_queue.get(timeout=5)
                if event is None:  # Shutdown signal
                    break
                
                event_type, data, level = event
                sanitized_data = self._sanitize_data(data)
                message = json.dumps({
                    "event_type": event_type,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "data": sanitized_data
                })
                
                self.logger.log(level, message)
                self.event_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Log worker error: {e}")
    
    def _sanitize_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize log data to prevent injection"""
        sanitized = {}
        for key, value in data.items():
            if isinstance(key, str) and len(key) <= 100:
                clean_key = re.sub(r'[^\w\-_]', '_', key)
                if isinstance(value, str) and len(value) <= 1000:
                    clean_value = value.replace('\n', '\\n').replace('\r', '\\r')
                    sanitized[clean_key] = clean_value[:1000]
                elif isinstance(value, (int, float, bool)):
                    sanitized[clean_key] = value
                else:
                    sanitized[clean_key] = str(value)[:500]
        return sanitized
    
    def log_event(self, event_type: str, data: Dict[str, Any], level: int = logging.INFO):
        """Log an event securely"""
        try:
            if not self.event_queue.full():
                self.event_queue.put((event_type, data, level), timeout=1)
        except queue.Full:
            print("Log queue full - event dropped")
        except Exception as e:
            print(f"Log event failed: {e}")
    
    def shutdown(self):
        """Shutdown logger gracefully"""
        try:
            self.event_queue.put(None)  # Shutdown signal
            self.log_thread.join(timeout=5)
        except Exception:
            pass

# ======================== SECURE DATABASE MANAGER ========================

class SecureDatabase:
    """Secure SQLite database manager with connection pooling"""
    
    def __init__(self, db_path: Path, logger: SecureLogger):
        self.db_path = db_path
        self.logger = logger
        self.connection_pool = queue.Queue(maxsize=3)
        self.lock = threading.RLock()
        
        self._initialize_database()
        self._populate_pool()
    
    def _initialize_database(self):
        """Initialize database with secure schema"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA synchronous=NORMAL")
                
                # Create tables with proper constraints
                conn.executescript("""
                    CREATE TABLE IF NOT EXISTS commands (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp REAL NOT NULL,
                        command_type TEXT NOT NULL CHECK(length(command_type) <= 100),
                        command_hash TEXT NOT NULL CHECK(length(command_hash) <= 64),
                        success BOOLEAN NOT NULL,
                        execution_time REAL NOT NULL CHECK(execution_time >= 0),
                        file_path TEXT CHECK(length(file_path) <= 1000),
                        created_at REAL DEFAULT (julianday('now'))
                    );
                    
                    CREATE TABLE IF NOT EXISTS system_metrics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp REAL NOT NULL,
                        memory_usage REAL CHECK(memory_usage >= 0),
                        active_threads INTEGER CHECK(active_threads >= 0),
                        queue_size INTEGER CHECK(queue_size >= 0),
                        success_rate REAL CHECK(success_rate >= 0 AND success_rate <= 1),
                        created_at REAL DEFAULT (julianday('now'))
                    );
                    
                    CREATE INDEX IF NOT EXISTS idx_commands_timestamp ON commands(timestamp);
                    CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON system_metrics(timestamp);
                """)
                conn.commit()
                
            self.logger.log_event("database_initialized", {"path": str(self.db_path)})
            
        except Exception as e:
            self.logger.log_event("database_init_error", {"error": str(e)}, logging.ERROR)
            raise
    
    def _populate_pool(self):
        """Create connection pool"""
        try:
            for _ in range(3):
                conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=10)
                conn.execute("PRAGMA journal_mode=WAL")
                self.connection_pool.put(conn)
        except Exception as e:
            self.logger.log_event("connection_pool_error", {"error": str(e)}, logging.ERROR)
    
    @contextmanager
    def get_connection(self):
        """Get database connection from pool"""
        conn = None
        try:
            conn = self.connection_pool.get(timeout=5)
            yield conn
        except queue.Empty:
            # Fallback connection
            conn = sqlite3.connect(self.db_path, timeout=10)
            yield conn
        except Exception as e:
            self.logger.log_event("connection_error", {"error": str(e)}, logging.ERROR)
            raise
        finally:
            if conn:
                try:
                    if self.connection_pool.qsize() < 3:
                        self.connection_pool.put(conn)
                    else:
                        conn.close()
                except Exception:
                    try:
                        conn.close()
                    except Exception:
                        pass
    
    def log_command(self, command_type: str, command_hash: str, success: bool, 
                   execution_time: float, file_path: str = None):
        """Log command execution"""
        try:
            with self.get_connection() as conn:
                conn.execute("""
                    INSERT INTO commands (timestamp, command_type, command_hash, success, execution_time, file_path)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (time.time(), command_type[:100], command_hash[:64], success, execution_time, 
                      file_path[:1000] if file_path else None))
                conn.commit()
        except Exception as e:
            self.logger.log_event("db_log_command_error", {"error": str(e)}, logging.ERROR)
    
    def log_metrics(self, memory_usage: float, active_threads: int, queue_size: int, success_rate: float):
        """Log system metrics"""
        try:
            with self.get_connection() as conn:
                conn.execute("""
                    INSERT INTO system_metrics (timestamp, memory_usage, active_threads, queue_size, success_rate)
                    VALUES (?, ?, ?, ?, ?)
                """, (time.time(), memory_usage, active_threads, queue_size, success_rate))
                conn.commit()
        except Exception as e:
            self.logger.log_event("db_log_metrics_error", {"error": str(e)}, logging.ERROR)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get system statistics"""
        try:
            with self.get_connection() as conn:
                # Get command statistics
                cmd_stats = conn.execute("""
                    SELECT command_type, COUNT(*) as total,
                           SUM(CASE WHEN success THEN 1 ELSE 0 END) as successful,
                           AVG(execution_time) as avg_time
                    FROM commands 
                    WHERE timestamp > ? 
                    GROUP BY command_type
                """, (time.time() - 3600,)).fetchall()  # Last hour
                
                # Get recent metrics
                recent_metrics = conn.execute("""
                    SELECT memory_usage, active_threads, queue_size, success_rate
                    FROM system_metrics 
                    WHERE timestamp > ? 
                    ORDER BY timestamp DESC LIMIT 1
                """, (time.time() - 300,)).fetchone()  # Last 5 minutes
                
                return {
                    "command_statistics": [
                        {
                            "type": row[0], "total": row[1], "successful": row[2], 
                            "success_rate": row[2]/row[1], "avg_time": row[3]
                        } for row in cmd_stats
                    ],
                    "recent_metrics": {
                        "memory_usage": recent_metrics[0] if recent_metrics else 0,
                        "active_threads": recent_metrics[1] if recent_metrics else 0,
                        "queue_size": recent_metrics[2] if recent_metrics else 0,
                        "success_rate": recent_metrics[3] if recent_metrics else 0
                    } if recent_metrics else {}
                }
        except Exception as e:
            self.logger.log_event("db_stats_error", {"error": str(e)}, logging.ERROR)
            return {"error": str(e)}

# ======================== SECURE COMMAND PROCESSOR ========================

class SecureCommandProcessor:
    """Secure command processor with validation and rate limiting"""
    
    def __init__(self, logger: SecureLogger, database: SecureDatabase):
        self.logger = logger
        self.database = database
        self.processed_commands = {}  # Command hash -> timestamp
        self.rate_limiter = {}  # IP/source -> list of timestamps
        self.command_handlers = {
            'status_check': self._handle_status_check,
            'health_check': self._handle_health_check,
            'system_info': self._handle_system_info
        }
    
    def _validate_command(self, command_data: Dict[str, Any], source: str) -> Tuple[bool, str]:
        """Validate command data and check rate limits"""
        try:
            # Basic structure validation
            if not isinstance(command_data, dict):
                return False, "Invalid command structure"
            
            cmd_type = command_data.get('type', '')
            if not isinstance(cmd_type, str) or len(cmd_type) > 100:
                return False, "Invalid command type"
            
            # Check for dangerous patterns
            dangerous_patterns = [
                'eval', 'exec', 'import', '__', 'os.', 'subprocess',
                'system', 'shell', 'popen', 'file'
            ]
            
            cmd_str = json.dumps(command_data).lower()
            for pattern in dangerous_patterns:
                if pattern in cmd_str:
                    return False, f"Dangerous pattern detected: {pattern}"
            
            # Rate limiting
            current_time = time.time()
            if source not in self.rate_limiter:
                self.rate_limiter[source] = []
            
            # Clean old entries
            self.rate_limiter[source] = [
                t for t in self.rate_limiter[source] 
                if current_time - t < 60  # 1 minute window
            ]
            
            # Check rate limit (max 10 commands per minute)
            if len(self.rate_limiter[source]) >= 10:
                return False, "Rate limit exceeded"
            
            self.rate_limiter[source].append(current_time)
            
            return True, "Valid"
            
        except Exception as e:
            self.logger.log_event("validation_error", {"error": str(e), "source": source}, logging.ERROR)
            return False, f"Validation error: {str(e)}"
    
    def process_command(self, filepath: Path) -> bool:
        """Process a command file securely"""
        start_time = time.time()
        command_hash = ""
        
        try:
            # Check file size
            if filepath.stat().st_size > MAX_FILE_SIZE:
                self.logger.log_event("file_too_large", {"file": str(filepath), "size": filepath.stat().st_size})
                return False
            
            # Read and parse command
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(10000)  # Limit read size
            
            # Generate command hash for deduplication
            command_hash = hashlib.sha256(content.encode()).hexdigest()
            
            # Check for duplicate commands
            current_time = time.time()
            if command_hash in self.processed_commands:
                last_processed = self.processed_commands[command_hash]
                if current_time - last_processed < 300:  # 5 minute deduplication
                    self.logger.log_event("duplicate_command", {"file": str(filepath), "hash": command_hash})
                    return False
            
            self.processed_commands[command_hash] = current_time
            
            # Parse command
            try:
                if content.strip().startswith('{'):
                    command_data = json.loads(content)
                else:
                    # Key-value format
                    command_data = {}
                    for line in content.strip().split('\n'):
                        if '=' in line and not line.strip().startswith('#'):
                            key, value = line.split('=', 1)
                            command_data[key.strip()] = value.strip()
            except Exception:
                self.logger.log_event("parse_error", {"file": str(filepath)}, logging.ERROR)
                return False
            
            # Validate command
            is_valid, error_msg = self._validate_command(command_data, str(filepath))
            if not is_valid:
                self.logger.log_event("validation_failed", {"file": str(filepath), "error": error_msg}, logging.WARNING)
                return False
            
            # Process command
            cmd_type = command_data.get('type', 'unknown')
            success = False
            
            if cmd_type in self.command_handlers:
                try:
                    success = self.command_handlers[cmd_type](command_data)
                except Exception as e:
                    self.logger.log_event("handler_error", {"type": cmd_type, "error": str(e)}, logging.ERROR)
            else:
                self.logger.log_event("unknown_command", {"type": cmd_type})
            
            # Log to database
            execution_time = time.time() - start_time
            self.database.log_command(cmd_type, command_hash, success, execution_time, str(filepath))
            
            return success
            
        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.log_event("process_error", {"file": str(filepath), "error": str(e)}, logging.ERROR)
            if command_hash:
                self.database.log_command("error", command_hash, False, execution_time, str(filepath))
            return False
    
    def _handle_status_check(self, command_data: Dict[str, Any]) -> bool:
        """Handle status check command"""
        try:
            stats = self.database.get_statistics()
            status_data = {
                "status": "operational",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "version": VERSION,
                "statistics": stats
            }
            
            self.logger.log_event("status_check", status_data)
            return True
            
        except Exception as e:
            self.logger.log_event("status_check_error", {"error": str(e)}, logging.ERROR)
            return False
    
    def _handle_health_check(self, command_data: Dict[str, Any]) -> bool:
        """Handle health check command"""
        try:
            health_data = {
                "health": "ok",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "checks": {
                    "database": "ok",
                    "logging": "ok",
                    "processing": "ok"
                }
            }
            
            self.logger.log_event("health_check", health_data)
            return True
            
        except Exception as e:
            self.logger.log_event("health_check_error", {"error": str(e)}, logging.ERROR)
            return False
    
    def _handle_system_info(self, command_data: Dict[str, Any]) -> bool:
        """Handle system info command"""
        try:
            info_data = {
                "version": VERSION,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "platform": sys.platform,
                "python_version": sys.version,
                "capabilities": {
                    "secure_processing": True,
                    "database_logging": True,
                    "rate_limiting": True
                }
            }
            
            self.logger.log_event("system_info", info_data)
            return True
            
        except Exception as e:
            self.logger.log_event("system_info_error", {"error": str(e)}, logging.ERROR)
            return False

# ======================== SECURE FILE MONITOR ========================

class SecureFileMonitor:
    """Secure file monitor with proper resource management"""
    
    def __init__(self, config: EchoConfig, processor: SecureCommandProcessor, logger: SecureLogger):
        self.config = config
        self.processor = processor
        self.logger = logger
        self.running = False
        self.worker_threads = []
        self.file_queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)
        self.processed_files = set()
        self.monitor_thread = None
    
    def start(self):
        """Start file monitoring"""
        if self.running:
            return
            
        self.running = True
        
        # Start worker threads
        for i in range(self.config.worker_threads):
            worker = threading.Thread(target=self._worker, daemon=True, name=f"Worker-{i}")
            worker.start()
            self.worker_threads.append(worker)
        
        # Start monitor thread
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True, name="Monitor")
        self.monitor_thread.start()
        
        self.logger.log_event("monitor_started", {"workers": self.config.worker_threads})
    
    def stop(self):
        """Stop file monitoring"""
        if not self.running:
            return
            
        self.running = False
        
        # Signal workers to stop
        for _ in range(self.config.worker_threads):
            try:
                self.file_queue.put(None, timeout=1)  # Poison pill
            except queue.Full:
                pass
        
        # Wait for threads
        for worker in self.worker_threads:
            worker.join(timeout=5)
        
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        
        self.logger.log_event("monitor_stopped", {})
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                if not self.config.inbox_path.exists():
                    time.sleep(self.config.poll_interval)
                    continue
                
                # Scan for new files
                for filepath in self.config.inbox_path.glob("*"):
                    if not self.running:
                        break
                        
                    if filepath.is_file() and str(filepath) not in self.processed_files:
                        # Basic security checks
                        if filepath.stat().st_size > MAX_FILE_SIZE:
                            self.logger.log_event("file_too_large", {"file": str(filepath)})
                            continue
                        
                        try:
                            self.file_queue.put(filepath, timeout=1)
                            self.processed_files.add(str(filepath))
                        except queue.Full:
                            self.logger.log_event("queue_full", {"file": str(filepath)})
                
                time.sleep(self.config.poll_interval)
                
            except Exception as e:
                self.logger.log_event("monitor_error", {"error": str(e)}, logging.ERROR)
                time.sleep(self.config.poll_interval)
    
    def _worker(self):
        """Worker thread for processing files"""
        while self.running:
            try:
                filepath = self.file_queue.get(timeout=5)
                if filepath is None:  # Poison pill
                    break
                
                # Process file
                success = self.processor.process_command(filepath)
                
                # Archive file
                self._archive_file(filepath, "processed" if success else "failed")
                
                self.file_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.log_event("worker_error", {"error": str(e)}, logging.ERROR)
    
    def _archive_file(self, filepath: Path, status: str):
        """Archive processed file safely"""
        try:
            timestamp = int(time.time() * 1000)
            archive_name = f"{timestamp}_{filepath.name}_{status}"
            archive_path = self.config.archive_path / archive_name
            
            # Move file to archive
            filepath.rename(archive_path)
            
            # Set secure permissions
            archive_path.chmod(0o640)
            
            self.logger.log_event("file_archived", {
                "original": str(filepath),
                "archive": str(archive_path),
                "status": status
            })
            
        except Exception as e:
            self.logger.log_event("archive_error", {"file": str(filepath), "error": str(e)}, logging.ERROR)
            # Try to remove file if archiving failed
            try:
                filepath.unlink()
            except Exception:
                pass

# ======================== MAIN ECHO AGENT ========================

class EchoAgent:
    """Main ECHO agent with Nexus integration"""
    
    def __init__(self, nexus_dashboard=None):
        self.config = EchoConfig()
        self.nexus_dashboard = nexus_dashboard
        self.running = False
        self.start_time = time.time()
        
        # Get secure storage path
        self.storage_path = self._get_storage_path()
        
        # Initialize components
        self.logger = SecureLogger("ECHO", self.storage_path / "logs")
        self.database = SecureDatabase(self.storage_path / "echo.db", self.logger)
        self.processor = SecureCommandProcessor(self.logger, self.database)
        self.monitor = SecureFileMonitor(self.config, self.processor, self.logger)
        
        # Background tasks
        self.heartbeat_thread = None
        self.metrics_thread = None
    
    def _get_storage_path(self) -> Path:
        """Get secure storage path compatible with Nexus"""
        for path_str in NexusIntegration.STORAGE_PATHS:
            try:
                path = Path(path_str)
                path.mkdir(mode=0o700, exist_ok=True, parents=True)
                
                # Test write permissions
                test_file = path / ".test"
                test_file.write_text("test")
                test_file.unlink()
                return path
                
            except (OSError, PermissionError):
                continue
        
        # Fallback
        fallback = Path.cwd() / "echo_data"
        fallback.mkdir(exist_ok=True)
        return fallback
    
def integrate_with_nexus(self, dashboard):
        """Integrate with Nexus dashboard"""
        self.nexus_dashboard = dashboard
        
        if hasattr(dashboard, 'alert_queue'):
            dashboard.alert_queue.put(
                f"{NexusIntegration.Colors.SUCCESS}ECHO Communications Monitor integrated{NexusIntegration.Colors.RESET}"
            )
    
def start(self):
        """Start ECHO agent"""
        if self.running:
            return
            
        self.running = True
        
        try:
            self.logger.log_event("agent_starting", {
                "version": VERSION,
                "storage_path": str(self.storage_path),
                "config": asdict(self.config)
            })
            
            # Start file monitoring
            self.monitor.start()
            
            # Start background tasks
            self._start_background_tasks()
            
            self.logger.log_event("agent_started", {"startup_time": time.time() - self.start_time})
            
            if self.nexus_dashboard and hasattr(self.nexus_dashboard, 'alert_queue'):
                self.nexus_dashboard.alert_queue.put(
                    f"{NexusIntegration.Colors.SUCCESS}ECHO Agent operational - monitoring {self.config.inbox_path}{NexusIntegration.Colors.RESET}"
                )
                
        except Exception as e:
            self.logger.log_event("agent_start_error", {"error": str(e)}, logging.CRITICAL)
            self.stop()
            raise
    
def stop(self):
        """Stop ECHO agent gracefully"""
        if not self.running:
            return
            
        try:
            self.logger.log_event("agent_stopping", {})
            self.running = False
            
            # Stop monitoring
            self.monitor.stop()
            
            # Stop background tasks
            if self.heartbeat_thread and self.heartbeat_thread.is_alive():
                self.heartbeat_thread.join(timeout=5)
            
            if self.metrics_thread and self.metrics_thread.is_alive():
                self.metrics_thread.join(timeout=5)
            
            # Shutdown logger
            self.logger.shutdown()
            
            uptime = time.time() - self.start_time
            print(f"{NexusIntegration.Colors.INFO}ECHO Agent stopped - Uptime: {uptime:.1f}s{NexusIntegration.Colors.RESET}")
            
            if self.nexus_dashboard and hasattr(self.nexus_dashboard, 'alert_queue'):
                self.nexus_dashboard.alert_queue.put(
                    f"{NexusIntegration.Colors.WARNING}ECHO Agent stopped{NexusIntegration.Colors.RESET}"
                )
                
        except Exception as e:
            print(f"{NexusIntegration.Colors.ERROR}ECHO shutdown error: {e}{NexusIntegration.Colors.RESET}")
    
def _start_background_tasks(self):
        """Start background maintenance tasks"""
        try:
            # Heartbeat thread
            self.heartbeat_thread = threading.Thread(target=self._heartbeat_worker, daemon=True, name="Heartbeat")
            self.heartbeat_thread.start()
            
            # Metrics thread
            self.metrics_thread = threading.Thread(target=self._metrics_worker, daemon=True, name="Metrics")
            self.metrics_thread.start()
            
            self.logger.log_event("background_tasks_started", {"threads": 2})
            
        except Exception as e:
            self.logger.log_event("background_start_error", {"error": str(e)}, logging.ERROR)
    
def _heartbeat_worker(self):
        """Background heartbeat worker"""
        while self.running:
            try:
                uptime = time.time() - self.start_time
                
                heartbeat_data = {
                    "status": "operational",
                    "uptime": uptime,
                    "processed_files": len(self.monitor.processed_files),
                    "queue_size": self.monitor.file_queue.qsize()
                }
                
                self.logger.log_event("heartbeat", heartbeat_data)
                
                # Alert Nexus if available
                if self.nexus_dashboard and hasattr(self.nexus_dashboard, 'alert_queue') and uptime % 300 == 0:  # Every 5 minutes
                    self.nexus_dashboard.alert_queue.put(
                        f"{NexusIntegration.Colors.INFO}ECHO heartbeat - {len(self.monitor.processed_files)} files processed{NexusIntegration.Colors.RESET}"
                    )
                
                time.sleep(self.config.heartbeat_interval)
                
            except Exception as e:
                self.logger.log_event("heartbeat_error", {"error": str(e)}, logging.ERROR)
                time.sleep(30)  # Fallback interval
    
def _metrics_worker(self):
        """Background metrics collection worker"""
        while self.running:
            try:
                # Collect basic metrics
                import psutil
                process = psutil.Process()
                memory_usage = process.memory_info().rss / 1024 / 1024  # MB
                
                # Calculate success rate from recent commands
                stats = self.database.get_statistics()
                success_rate = 0.0
                
                if stats and 'command_statistics' in stats:
                    total_commands = sum(cmd['total'] for cmd in stats['command_statistics'])
                    successful_commands = sum(cmd['successful'] for cmd in stats['command_statistics'])
                    if total_commands > 0:
                        success_rate = successful_commands / total_commands
                
                # Log metrics
                self.database.log_metrics(
                    memory_usage=memory_usage,
                    active_threads=len(threading.enumerate()),
                    queue_size=self.monitor.file_queue.qsize(),
                    success_rate=success_rate
                )
                
                time.sleep(60)  # Collect every minute
                
            except ImportError:
                # psutil not available, use basic metrics
                self.database.log_metrics(
                    memory_usage=0.0,
                    active_threads=len(threading.enumerate()),
                    queue_size=self.monitor.file_queue.qsize(),
                    success_rate=1.0
                )
                time.sleep(60)
            except Exception as e:
                self.logger.log_event("metrics_error", {"error": str(e)}, logging.ERROR)
                time.sleep(60)
    
def get_status(self) -> Dict[str, Any]:
        """Get current agent status for Nexus integration"""
        try:
            uptime = time.time() - self.start_time
            stats = self.database.get_statistics()
            
            return {
                "status": "operational" if self.running else "stopped",
                "version": VERSION,
                "uptime": uptime,
                "processed_files": len(self.monitor.processed_files),
                "queue_size": self.monitor.file_queue.qsize(),
                "storage_path": str(self.storage_path),
                "statistics": stats
            }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e)
            }

# ======================== NEXUS DASHBOARD INTEGRATION ========================

def integrate_with_nexus_dashboard():
    """Integration function for Nexus Dashboard"""
    try:
        # Check if Nexus.py exists
        nexus_file = Path("Nexus.py")
        if not nexus_file.exists():
            print(f"{NexusIntegration.Colors.WARNING}Nexus.py not found in current directory{NexusIntegration.Colors.RESET}")
            return None
        
        # Try to import Nexus components
        import importlib.util
        spec = importlib.util.spec_from_file_location("Nexus", nexus_file)
        if spec is None or spec.loader is None:
            print(f"{NexusIntegration.Colors.WARNING}Cannot load Nexus module{NexusIntegration.Colors.RESET}")
            return None
        
        nexus_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(nexus_module)
        
        # Get required classes
        DashboardController = getattr(nexus_module, 'DashboardController', None)
        if DashboardController is None:
            print(f"{NexusIntegration.Colors.WARNING}DashboardController not found in Nexus module{NexusIntegration.Colors.RESET}")
            return None
        
        class EchoIntegratedDashboard(DashboardController):
            """Extended Nexus Dashboard with ECHO communications monitoring"""
            
            def __init__(self):
                super().__init__()
                self.echo_agent = EchoAgent(self)
                
                # Add ECHO to system initialization
                self.alert_queue.put(
                    f"{NexusIntegration.Colors.SUCCESS}ECHO Communications Monitor integrated with Nexus Dashboard{NexusIntegration.Colors.RESET}"
                )
            
            def _execute_command(self, command: str):
                """Override to add ECHO-specific commands"""
                echo_commands = {
                    'echo': self._echo_status,
                    'echostatus': self._echo_detailed_status,
                    'echostart': self._echo_start,
                    'echostop': self._echo_stop,
                    'echologs': self._echo_show_logs
                }
                
                if command in echo_commands:
                    try:
                        echo_commands[command]()
                    except Exception as e:
                        self.error_handler.handle_error(e, f"echo_command:{command}")
                        self.alert_queue.put(f"{NexusIntegration.Colors.ERROR}ECHO command failed: {str(e)}{NexusIntegration.Colors.RESET}")
                else:
                    # Call parent implementation for standard commands
                    super()._execute_command(command)
            
            def _echo_status(self):
                """Show ECHO status"""
                status = self.echo_agent.get_status()
                
                if status['status'] == 'operational':
                    self.alert_queue.put(
                        f"{NexusIntegration.Colors.SUCCESS}ECHO Status: {status['status']} - Uptime: {status['uptime']:.1f}s{NexusIntegration.Colors.RESET}"
                    )
                else:
                    self.alert_queue.put(
                        f"{NexusIntegration.Colors.ERROR}ECHO Status: {status['status']}{NexusIntegration.Colors.RESET}"
                    )
            
            def _echo_detailed_status(self):
                """Show detailed ECHO status"""
                status = self.echo_agent.get_status()
                
                self.alert_queue.put(f"{NexusIntegration.Colors.HEADER}=== ECHO COMMUNICATIONS MONITOR ==={NexusIntegration.Colors.RESET}")
                self.alert_queue.put(f"{NexusIntegration.Colors.INFO}Status: {status['status']}{NexusIntegration.Colors.RESET}")
                self.alert_queue.put(f"{NexusIntegration.Colors.INFO}Version: {status.get('version', 'Unknown')}{NexusIntegration.Colors.RESET}")
                self.alert_queue.put(f"{NexusIntegration.Colors.INFO}Uptime: {status.get('uptime', 0):.1f} seconds{NexusIntegration.Colors.RESET}")
                self.alert_queue.put(f"{NexusIntegration.Colors.INFO}Processed Files: {status.get('processed_files', 0)}{NexusIntegration.Colors.RESET}")
                self.alert_queue.put(f"{NexusIntegration.Colors.INFO}Queue Size: {status.get('queue_size', 0)}{NexusIntegration.Colors.RESET}")
                self.alert_queue.put(f"{NexusIntegration.Colors.INFO}Storage Path: {status.get('storage_path', 'Unknown')}{NexusIntegration.Colors.RESET}")
            
            def _echo_start(self):
                """Start ECHO agent"""
                try:
                    self.echo_agent.start()
                    self.alert_queue.put(f"{NexusIntegration.Colors.SUCCESS}ECHO Agent started{NexusIntegration.Colors.RESET}")
                except Exception as e:
                    self.alert_queue.put(f"{NexusIntegration.Colors.ERROR}Failed to start ECHO: {str(e)}{NexusIntegration.Colors.RESET}")
            
            def _echo_stop(self):
                """Stop ECHO agent"""
                try:
                    self.echo_agent.stop()
                    self.alert_queue.put(f"{NexusIntegration.Colors.WARNING}ECHO Agent stopped{NexusIntegration.Colors.RESET}")
                except Exception as e:
                    self.alert_queue.put(f"{NexusIntegration.Colors.ERROR}Failed to stop ECHO: {str(e)}{NexusIntegration.Colors.RESET}")
            
            def _echo_show_logs(self):
                """Show recent ECHO logs"""
                try:
                    stats = self.echo_agent.database.get_statistics()
                    
                    if 'command_statistics' in stats and stats['command_statistics']:
                        self.alert_queue.put(f"{NexusIntegration.Colors.HEADER}=== ECHO COMMAND STATISTICS ==={NexusIntegration.Colors.RESET}")
                        for cmd_stat in stats['command_statistics'][:5]:  # Show top 5
                            self.alert_queue.put(
                                f"{NexusIntegration.Colors.INFO}{cmd_stat['type']}: {cmd_stat['successful']}/{cmd_stat['total']} "
                                f"({cmd_stat['success_rate']:.2%}) - Avg: {cmd_stat['avg_time']:.2f}s{NexusIntegration.Colors.RESET}"
                            )
                    else:
                        self.alert_queue.put(f"{NexusIntegration.Colors.WARNING}No recent command statistics available{NexusIntegration.Colors.RESET}")
                        
                except Exception as e:
                    self.alert_queue.put(f"{NexusIntegration.Colors.ERROR}Failed to retrieve logs: {str(e)}{NexusIntegration.Colors.RESET}")
            
            def _show_help(self):
                """Override help to include ECHO commands"""
                super()._show_help()
                self.alert_queue.put(f"{NexusIntegration.Colors.ACCENT}ECHO Operations:{NexusIntegration.Colors.RESET} echo, echostatus, echostart, echostop, echologs")
        
        return EchoIntegratedDashboard
        
    except ImportError:
        return None

# ======================== STANDALONE APPLICATION ========================

class EchoStandaloneApp:
    """Standalone application interface"""
    
    def __init__(self):
        self.echo_agent = EchoAgent()
    
    def run(self):
        """Run standalone ECHO agent"""
        print(f"{NexusIntegration.Colors.HEADER}ECHO Communications Monitor v{VERSION}{NexusIntegration.Colors.RESET}")
        print(f"{NexusIntegration.Colors.INFO}Secure command processing system{NexusIntegration.Colors.RESET}")
        print("-" * 60)
        
        while True:
            try:
                print(f"\n{NexusIntegration.Colors.HEADER}=== ECHO CONTROL MENU ==={NexusIntegration.Colors.RESET}")
                print("1. Start ECHO Agent")
                print("2. Stop ECHO Agent")
                print("3. Show Status")
                print("4. Show Statistics")
                print("5. Create Test Commands")
                print("6. Exit")
                
                choice = input(f"\n{NexusIntegration.Colors.TEXT}Choice (1-6): {NexusIntegration.Colors.RESET}").strip()
                
                if choice == '1':
                    try:
                        self.echo_agent.start()
                        print(f"{NexusIntegration.Colors.SUCCESS}ECHO Agent started successfully{NexusIntegration.Colors.RESET}")
                    except Exception as e:
                        print(f"{NexusIntegration.Colors.ERROR}Failed to start: {e}{NexusIntegration.Colors.RESET}")
                
                elif choice == '2':
                    self.echo_agent.stop()
                    print(f"{NexusIntegration.Colors.WARNING}ECHO Agent stopped{NexusIntegration.Colors.RESET}")
                
                elif choice == '3':
                    status = self.echo_agent.get_status()
                    print(f"\n{NexusIntegration.Colors.HEADER}=== ECHO STATUS ==={NexusIntegration.Colors.RESET}")
                    for key, value in status.items():
                        if key != 'statistics':
                            print(f"{NexusIntegration.Colors.INFO}{key}: {value}{NexusIntegration.Colors.RESET}")
                
                elif choice == '4':
                    status = self.echo_agent.get_status()
                    if 'statistics' in status and status['statistics']:
                        stats = status['statistics']
                        print(f"\n{NexusIntegration.Colors.HEADER}=== ECHO STATISTICS ==={NexusIntegration.Colors.RESET}")
                        
                        if 'command_statistics' in stats:
                            for cmd_stat in stats['command_statistics']:
                                print(f"{NexusIntegration.Colors.INFO}{cmd_stat['type']}: {cmd_stat['successful']}/{cmd_stat['total']} "
                                      f"({cmd_stat['success_rate']:.2%}){NexusIntegration.Colors.RESET}")
                        
                        if 'recent_metrics' in stats:
                            metrics = stats['recent_metrics']
                            print(f"{NexusIntegration.Colors.INFO}Memory: {metrics.get('memory_usage', 0):.1f}MB{NexusIntegration.Colors.RESET}")
                            print(f"{NexusIntegration.Colors.INFO}Threads: {metrics.get('active_threads', 0)}{NexusIntegration.Colors.RESET}")
                    else:
                        print(f"{NexusIntegration.Colors.WARNING}No statistics available{NexusIntegration.Colors.RESET}")
                
                elif choice == '5':
                    self._create_test_commands()
                
                elif choice == '6':
                    print("Stopping ECHO and exiting...")
                    self.echo_agent.stop()
                    break
                
                else:
                    print(f"{NexusIntegration.Colors.ERROR}Invalid choice{NexusIntegration.Colors.RESET}")
                    
            except (KeyboardInterrupt, EOFError):
                print(f"\n{NexusIntegration.Colors.INFO}Exiting...{NexusIntegration.Colors.RESET}")
                self.echo_agent.stop()
                break
            except Exception as e:
                print(f"{NexusIntegration.Colors.ERROR}Error: {e}{NexusIntegration.Colors.RESET}")
    
    def _create_test_commands(self):
        """Create test command files"""
        try:
            inbox_path = self.echo_agent.config.inbox_path
            inbox_path.mkdir(exist_ok=True)
            
            test_commands = [
                {
                    "filename": "status_check.json",
                    "content": json.dumps({"type": "status_check", "timestamp": datetime.now().isoformat()}, indent=2)
                },
                {
                    "filename": "health_check.json", 
                    "content": json.dumps({"type": "health_check", "automated": False}, indent=2)
                },
                {
                    "filename": "system_info.json",
                    "content": json.dumps({"type": "system_info"}, indent=2)
                }
            ]
            
            created = 0
            for test_cmd in test_commands:
                file_path = inbox_path / test_cmd["filename"]
                if not file_path.exists():
                    file_path.write_text(test_cmd["content"], encoding='utf-8')
                    created += 1
            
            print(f"{NexusIntegration.Colors.SUCCESS}Created {created} test command files in {inbox_path}{NexusIntegration.Colors.RESET}")
            
        except Exception as e:
            print(f"{NexusIntegration.Colors.ERROR}Failed to create test commands: {e}{NexusIntegration.Colors.RESET}")

# ======================== MAIN EXECUTION ========================

def main():
    """Main entry point - can run standalone or integrate with Nexus"""
    print(f"{NexusIntegration.Colors.HEADER}ECHO Communications Monitor v{VERSION}{NexusIntegration.Colors.RESET}")
    print(f"{NexusIntegration.Colors.INFO}Secure Command Processing System for Nexus Dashboard{NexusIntegration.Colors.RESET}")
    print("-" * 70)
    
    # Check for Nexus integration
    nexus_available = False
    try:
        nexus_file = Path("Nexus.py")
        if nexus_file.exists():
            print(f"{NexusIntegration.Colors.INFO}Nexus.py found, checking compatibility...{NexusIntegration.Colors.RESET}")
            
            # Try to validate Nexus.py syntax
            with open(nexus_file, 'r', encoding='utf-8', errors='ignore') as f:
                nexus_content = f.read()
            
            try:
                compile(nexus_content, str(nexus_file), 'exec')
                print(f"{NexusIntegration.Colors.SUCCESS}Nexus.py syntax validation passed{NexusIntegration.Colors.RESET}")
                
                # Try integration
                EchoIntegratedClass = integrate_with_nexus_dashboard()
                if EchoIntegratedClass:
                    nexus_available = True
                    print(f"{NexusIntegration.Colors.SUCCESS}Nexus Dashboard integration ready{NexusIntegration.Colors.RESET}")
                
            except SyntaxError as e:
                print(f"{NexusIntegration.Colors.ERROR}Syntax error in Nexus.py: {e}{NexusIntegration.Colors.RESET}")
        else:
            print(f"{NexusIntegration.Colors.WARNING}Nexus.py not found in current directory{NexusIntegration.Colors.RESET}")
    
    except Exception as e:
        print(f"{NexusIntegration.Colors.ERROR}Error checking Nexus integration: {e}{NexusIntegration.Colors.RESET}")
    
    # Run appropriate mode
    if nexus_available:
        try:
            print(f"{NexusIntegration.Colors.SUCCESS}Starting with Nexus Dashboard integration...{NexusIntegration.Colors.RESET}")
            dashboard = EchoIntegratedClass()
            dashboard.start()
        except Exception as e:
            print(f"{NexusIntegration.Colors.ERROR}Nexus integration failed: {e}{NexusIntegration.Colors.RESET}")
            print(f"{NexusIntegration.Colors.INFO}Falling back to standalone mode{NexusIntegration.Colors.RESET}")
            app = EchoStandaloneApp()
            app.run()
    else:
        print(f"{NexusIntegration.Colors.INFO}Running in standalone mode{NexusIntegration.Colors.RESET}")
        app = EchoStandaloneApp()
        app.run()

if __name__ == "__main__":
    main()
