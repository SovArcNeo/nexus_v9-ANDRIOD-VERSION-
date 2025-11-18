#!/usr/bin/env python3
"""
NEXUS UNIFIED v9.0 - PRODUCTION EDITION - COMPLETE FIXED VERSION
Elite Network Intelligence & Host Monitoring System

All Features Intact:
- Full AGENT_AGESIS_B network intelligence integration
- Host-level system monitoring with ML threat assessment
- Elite Dashboard API with event-driven activation
- Military-grade security and input validation
- Advanced neural network threat assessment (network + host)
- Real-time ML-based anomaly detection
- Comprehensive audit logging and forensic capabilities
"""

import os
import sys
import time
import signal
import threading
import logging
import queue
import json
import random
import hashlib
import hmac
import secrets
import socket
import ipaddress
import re
import traceback
import csv
import asyncio
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Union, Callable, Set
from dataclasses import dataclass, asdict, field
from enum import Enum, auto
from collections import deque, defaultdict
from functools import wraps
from concurrent.futures import ThreadPoolExecutor, as_completed
from abc import ABC, abstractmethod

# Enhanced imports with fallbacks
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    print("Info: NumPy not available - using pure Python implementations")

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("Info: psutil not available - using synthetic system metrics")

# Version and constants
VERSION = "9.0.0-PRODUCTION"
AGENT_ID = "NEXUS_UNIFIED_001"
SECURITY_LEVEL = "MAXIMUM"

# ======================== CONFIGURATION MANAGEMENT ========================

@dataclass
class Config:
    """Centralized configuration with external JSON support"""
    
    # Display settings
    TERMINAL_WIDTH: int = 80
    REFRESH_INTERVAL: float = 3.0
    MAX_ALERTS_DISPLAY: int = 8
    DASHBOARD_UPDATE_INTERVAL: float = 1.0
    
    # Network scanning
    SCAN_TIMEOUT: int = 5
    MAX_WORKERS: int = 10
    PORT_SCAN_COMMON: List[int] = field(default_factory=lambda: [
        21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443
    ])
    COMMON_SERVICES: Dict[int, str] = field(default_factory=lambda: {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
        3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
    })
    
    # Machine Learning
    ANOMALY_THRESHOLD: float = 2.5
    NN_INPUT_SIZE: int = 12
    NN_HIDDEN_LAYERS: List[int] = field(default_factory=lambda: [64, 32, 16])
    NN_OUTPUT_SIZE: int = 1
    LEARNING_RATE: float = 0.001
    BATCH_SIZE: int = 32
    EPOCHS_PER_UPDATE: int = 3
    REPLAY_BUFFER_SIZE: int = 1000
    MAX_ML_DATA_POINTS: int = 1000
    
    # Monitoring
    PERFORMANCE_MONITORING_INTERVAL: int = 10
    THREAT_MONITORING_INTERVAL: int = 5
    HOST_MONITORING_INTERVAL: int = 3
    
    # Security
    AUTO_DEFENSIVE_ENABLED: bool = True
    MAX_LOGIN_ATTEMPTS: int = 3
    SESSION_TIMEOUT: int = 3600
    SECURE_FILE_PERMISSIONS: int = 0o600
    SECURE_DIR_PERMISSIONS: int = 0o700
    
    # Paths
    EDS_VAULT_PATHS: List[str] = field(default_factory=lambda: [
        "/storage/emulated/0/EDS_VAULT_2", "./vault", "/storage/emulated/0/EDS/Vaults", "./EDS_Vault"
    ])
    AGENT_PATTERNS: List[str] = field(default_factory=lambda: ["AGENT_", "NEO_", "AGESIS_", ""])
    AGENT_EXTENSION: str = ".py"
    LOG_DIR: Path = field(default_factory=lambda: Path("./logs"))
    STATE_FILE: Path = field(default_factory=lambda: Path("./nexus_state.json"))
    CONFIG_FILE: Path = field(default_factory=lambda: Path("./config.json"))
    
    # Rate limiting
    RATE_LIMIT_WINDOW: int = 60
    MAX_REQUESTS_PER_WINDOW: int = 100
    
    @classmethod
    def load_from_file(cls, config_path: Optional[Path] = None) -> 'Config':
        """Load configuration from external JSON file - FIXED LINE 163"""
        config = cls()

        if config_path is None:
            config_path = config.CONFIG_FILE

        if not config_path.exists():
            logging.info(f"Config file not found: {config_path}. Using defaults.")
            return config

        try:
            with open(config_path, 'r') as f:
                data = json.load(f)

            # Update fields from JSON
            for key, value in data.items():
                key_upper = key.upper()
                if hasattr(config, key_upper):
                    # Handle special types
                    current_value = getattr(config, key_upper)
                    if isinstance(current_value, Path):
                        setattr(config, key_upper, Path(value))
                    else:
                        setattr(config, key_upper, value)

            logging.info(f"Configuration loaded from {config_path}")

        except Exception as e:
            logging.error(f"Failed to load config from {config_path}: {e}")

        return config

    def to_dict(self) -> Dict[str, Any]:
        """Export configuration to dictionary"""
        config_dict = {}
        for key, value in self.__dict__.items():
            if isinstance(value, Path):
                config_dict[key] = str(value)
            elif isinstance(value, (list, dict, str, int, float, bool)):
                config_dict[key] = value
            else:
                # Handle other types by converting to string
                config_dict[key] = str(value)
        return config_dict

# Global config will be initialized after class definition
ConfigInstance = None

# ======================== ENUMERATIONS ========================

class AgentStatus(Enum):
    """Agent operational statuses"""
    DISCOVERED = "DISCOVERED"
    ONLINE = "ONLINE"
    OFFLINE = "OFFLINE"
    ERROR = "ERROR"
    VALIDATING = "VALIDATING"
    OPTIMIZING = "OPTIMIZING"

class SystemStatus(Enum):
    """System operational statuses"""
    INITIALIZING = "INITIALIZING"
    READY = "READY"
    OPERATIONAL = "OPERATIONAL"
    SCANNING = "SCANNING"
    ERROR = "ERROR"
    SHUTTING_DOWN = "SHUTTING_DOWN"
    MAINTENANCE = "MAINTENANCE"
    MONITORING = "MONITORING"
    OPTIMIZING = "OPTIMIZING"
    DEFENSIVE = "DEFENSIVE"

class AgentState(Enum):
    """Network agent operational states"""
    IDLE = auto()
    SCANNING = auto()
    ANALYZING = auto()
    LEARNING = auto()
    ERROR = auto()

class ThreatLevel(Enum):
    """Threat level classifications"""
    MINIMAL = (0.0, 0.3, "MINIMAL")
    LOW = (0.3, 0.5, "LOW")
    MEDIUM = (0.5, 0.7, "MEDIUM")
    HIGH = (0.7, 0.85, "HIGH")
    CRITICAL = (0.85, 1.0, "CRITICAL")
    
    def __init__(self, min_val: float, max_val: float, label: str):
        self.min_val = min_val
        self.max_val = max_val
        self.label = label
    
    @classmethod
    def from_score(cls, score: float) -> 'ThreatLevel':
        """Convert numeric score to threat level"""
        score = max(0.0, min(1.0, score))
        for level in cls:
            if level.min_val <= score < level.max_val:
                return level
        return cls.CRITICAL if score >= 0.85 else cls.MINIMAL

class DashboardEventType(Enum):
    """Dashboard event types for pub/sub"""
    SCAN_COMPLETED = auto()
    AGENT_DISCOVERED = auto()
    AGENT_ENGAGED = auto()
    AGENT_OPTIMIZED = auto()
    AGENT_DEGRADED = auto()
    OPTIMIZATION_COMPLETED = auto()
    THREAT_LEVEL_CHANGED = auto()
    PERFORMANCE_ALERT = auto()
    ERROR_OCCURRED = auto()
    STATE_CHANGED = auto()
    METRICS_UPDATED = auto()
    SECURITY_ALERT = auto()
    NETWORK_SCAN_COMPLETE = auto()
    ML_MODEL_TRAINED = auto()
    ANOMALY_DETECTED = auto()
    HOST_THREAT_UPDATED = auto()

class AlertSeverity(Enum):
    """Alert severity levels"""
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

class ActivationFunction(Enum):
    """Neural network activation functions"""
    RELU = auto()
    SIGMOID = auto()
    TANH = auto()
    SOFTMAX = auto()
    SWISH = auto()
    LEAKY_RELU = auto()

# ======================== UTILITY DECORATORS ========================

def timeout_handler(timeout_seconds: float):
    """Decorator for timeout handling"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            result = [TimeoutError(f"{func.__name__} timed out")]
            
            def target():
                try:
                    result[0] = func(*args, **kwargs)
                except Exception as e:
                    result[0] = e
            
            thread = threading.Thread(target=target, daemon=True)
            thread.start()
            thread.join(timeout_seconds)
            
            if thread.is_alive():
                raise TimeoutError(f"{func.__name__} exceeded {timeout_seconds}s timeout")
            
            if isinstance(result[0], Exception):
                raise result[0]
            
            return result[0]
        
        return wrapper
    return decorator

def clamp(value: float, min_val: float, max_val: float) -> float:
    """Clamp value between min and max"""
    return max(min_val, min(max_val, value))

# ======================== SECURITY UTILITIES ========================

class SecureRandom:
    """Cryptographically secure random number generator"""
    
    @staticmethod
    def generate_token(length: int = 32) -> str:
        """Generate secure random token"""
        return secrets.token_hex(length)
    
    @staticmethod
    def generate_bytes(length: int = 32) -> bytes:
        """Generate secure random bytes"""
        return secrets.token_bytes(length)
    
    @staticmethod
    def generate_int(min_val: int, max_val: int) -> int:
        """Generate secure random integer"""
        return secrets.randbelow(max_val - min_val + 1) + min_val

class InputValidator:
    """Input validation and sanitization"""
    
    # Validation patterns
    IP_PATTERN = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    HOSTNAME_PATTERN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')
    COMMAND_PATTERN = re.compile(r'^[a-zA-Z0-9_\-]+$')
    
    @classmethod
    def validate_ip(cls, ip: str) -> bool:
        """Validate IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @classmethod
    def validate_network(cls, network: str) -> bool:
        """Validate network CIDR"""
        try:
            ipaddress.ip_network(network, strict=False)
            return True
        except ValueError:
            return False
    
    @classmethod
    def validate_port(cls, port: Union[int, str]) -> bool:
        """Validate port number"""
        try:
            port_int = int(port)
            return 0 < port_int <= 65535
        except (ValueError, TypeError):
            return False
    
    @classmethod
    def validate_command(cls, command: str) -> bool:
        """Validate command string"""
        return bool(cls.COMMAND_PATTERN.match(command))
    
    @classmethod
    def sanitize_string(cls, s: str, max_length: int = 1000) -> str:
        """Sanitize string input"""
        if not isinstance(s, str):
            return ""
        
        # Remove control characters
        s = ''.join(char for char in s if char.isprintable() or char in '\n\t')
        
        # Truncate to max length
        return s[:max_length]
    
    @classmethod
    def validate_json(cls, data: str) -> Tuple[bool, Optional[Dict]]:
        """Validate and parse JSON"""
        try:
            parsed = json.loads(data)
            return True, parsed
        except json.JSONDecodeError:
            return False, None

class PathValidator:
    """File path validation and sanitization"""
    
    @staticmethod
    def is_safe_path(base_dir: Path, path: Path) -> bool:
        """Check if path is within base directory"""
        try:
            abs_base = base_dir.resolve()
            abs_path = path.resolve()
            return abs_path.is_relative_to(abs_base)
        except (ValueError, OSError):
            return False
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize filename"""
        # Remove dangerous characters
        filename = re.sub(r'[^\w\-_\. ]', '', filename)
        # Remove leading/trailing dots and spaces
        filename = filename.strip('. ')
        return filename or "unnamed"

class RateLimiter:
    """Rate limiting for API calls"""
    
    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, deque] = defaultdict(lambda: deque())
        self.lock = threading.Lock()
    
    def is_allowed(self, identifier: str) -> bool:
        """Check if request is allowed"""
        with self.lock:
            now = time.time()
            window_start = now - self.window_seconds
            
            # Remove old requests
            while self.requests[identifier] and self.requests[identifier][0] < window_start:
                self.requests[identifier].popleft()
            
            # Check limit
            if len(self.requests[identifier]) >= self.max_requests:
                return False
            
            # Add request
            self.requests[identifier].append(now)
            return True

class AuditLogger:
    """Security audit logging"""
    
    def __init__(self, log_dir: Path):
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Set secure permissions
        try:
            os.chmod(self.log_dir, Config.SECURE_DIR_PERMISSIONS)
        except OSError:
            pass
        
        self.audit_file = self.log_dir / f"audit_{datetime.now().strftime('%Y%m%d')}.log"
        self.logger = logging.getLogger("AuditLogger")
    
    def log_event(self, event_type: str, details: Dict[str, Any], severity: str = "INFO"):
        """Log security event"""
        try:
            entry = {
                'timestamp': datetime.now().isoformat(),
                'event_type': event_type,
                'severity': severity,
                'details': details
            }
            
            with open(self.audit_file, 'a') as f:
                f.write(json.dumps(entry) + '\n')
            
            # Set secure permissions on log file
            try:
                os.chmod(self.audit_file, Config.SECURE_FILE_PERMISSIONS)
            except OSError:
                pass
                
        except Exception as e:
            self.logger.error(f"Failed to write audit log: {e}")

# ======================== ERROR HANDLING ========================

class ErrorHandler:
    """Centralized error handling"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.error_counts: Dict[str, int] = defaultdict(int)
        self.last_errors: Dict[str, datetime] = {}
        self.lock = threading.Lock()
    
    def handle_error(self, error: Exception, context: str = "") -> None:
        """Handle and log error"""
        with self.lock:
            error_key = f"{context}:{type(error).__name__}"
            self.error_counts[error_key] += 1
            self.last_errors[error_key] = datetime.now()
        
        error_msg = f"Error in {context}: {str(error)}"
        self.logger.error(error_msg)
        
        if self.logger.level == logging.DEBUG:
            self.logger.debug(traceback.format_exc())
    
    def get_error_summary(self) -> Dict[str, Any]:
        """Get error statistics"""
        with self.lock:
            return {
                'total_errors': sum(self.error_counts.values()),
                'unique_errors': len(self.error_counts),
                'error_counts': dict(self.error_counts),
                'recent_errors': {
                    k: v.isoformat() for k, v in 
                    sorted(self.last_errors.items(), key=lambda x: x[1], reverse=True)[:5]
                }
            }

# ======================== DISPLAY UTILITIES ========================

class Colors:
    """ANSI color codes"""
    HEADER = '\033[95m'
    INFO = '\033[94m'
    SUCCESS = '\033[92m'
    WARNING = '\033[93m'
    ERROR = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    MUTED = '\033[90m'
    ACCENT = '\033[96m'
    
    # Status colors
    STATUS_READY = '\033[92m'
    STATUS_ACTIVE = '\033[93m'
    STATUS_WARNING = '\033[91m'
    
    # Background colors
    BG_HEADER = '\033[100m'
    
    @classmethod
    def disable_colors(cls):
        """Disable colors for non-supporting terminals"""
        for attr in dir(cls):
            if not attr.startswith('_') and attr.isupper():
                setattr(cls, attr, '')

class Symbols:
    """Unicode symbols"""
    CHECK = '✓'
    CROSS = '✗'
    ARROW = '→'
    DOT = '•'
    INFO = 'ℹ'
    SHIELD = '🛡'
    BRAIN = '🧠'
    RADAR = '📡'
    WARNING = '⚠'
    GEAR = '⚙'
    
    @classmethod
    def disable_unicode(cls):
        """Fallback to ASCII"""
        cls.CHECK = '+'
        cls.CROSS = 'x'
        cls.ARROW = '->'
        cls.DOT = '*'
        cls.INFO = 'i'
        cls.SHIELD = '[S]'
        cls.BRAIN = '[ML]'
        cls.RADAR = '[R]'
        cls.WARNING = '!'
        cls.GEAR = '[G]'

# ======================== DATA STRUCTURES ========================

@dataclass
class Agent:
    """Agent representation"""
    id: str
    status: AgentStatus
    discovery_time: datetime
    last_seen: datetime
    path: Optional[Path] = None
    capabilities: List[str] = field(default_factory=list)
    performance_score: float = 1.0
    optimization_count: int = 0

@dataclass
class NetworkDevice:
    """Network device representation"""
    ip: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    risk_score: float = 0.0
    last_seen: datetime = field(default_factory=datetime.now)
    first_seen: datetime = field(default_factory=datetime.now)
    response_times: List[float] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'ip': self.ip,
            'hostname': self.hostname,
            'mac_address': self.mac_address,
            'open_ports': self.open_ports,
            'services': self.services,
            'risk_score': self.risk_score,
            'last_seen': self.last_seen.isoformat(),
            'first_seen': self.first_seen.isoformat()
        }

@dataclass
class ScanResult:
    """Network scan result"""
    target: str
    open_ports: List[int]
    closed_ports: List[int]
    services: Dict[int, str]
    scan_duration: float
    success: bool
    error_message: Optional[str] = None

@dataclass
class SystemState:
    """System state tracking"""
    status: SystemStatus = SystemStatus.INITIALIZING
    active_agents: Dict[str, Agent] = field(default_factory=dict)
    found_agents: Dict[str, Agent] = field(default_factory=dict)
    total_scans: int = 0
    last_scan_time: Optional[datetime] = None
    error_count: int = 0
    monitoring_active: bool = False
    threat_monitoring_active: bool = False
    ml_threat_assessment_active: bool = False
    defensive_active: bool = False
    total_optimization_cycles: int = 0
    last_threat_level: float = 0.0
    host_threat_level: float = 0.0
    neural_predictions: int = 0
    start_time: datetime = field(default_factory=datetime.now)

# ======================== NEURAL NETWORK ENGINE ========================

if NUMPY_AVAILABLE:
    class Activation:
        """Activation function implementations"""
        
        @staticmethod
        def forward(x: np.ndarray, func: ActivationFunction) -> np.ndarray:
            """Forward pass through activation"""
            if func == ActivationFunction.RELU:
                return np.maximum(0, x)
            elif func == ActivationFunction.SIGMOID:
                return 1 / (1 + np.exp(-np.clip(x, -500, 500)))
            elif func == ActivationFunction.TANH:
                return np.tanh(x)
            elif func == ActivationFunction.SOFTMAX:
                exp_x = np.exp(x - np.max(x, axis=-1, keepdims=True))
                return exp_x / np.sum(exp_x, axis=-1, keepdims=True)
            elif func == ActivationFunction.SWISH:
                return x * Activation.forward(x, ActivationFunction.SIGMOID)
            elif func == ActivationFunction.LEAKY_RELU:
                return np.where(x > 0, x, 0.01 * x)
            return x
        
        @staticmethod
        def backward(x: np.ndarray, func: ActivationFunction) -> np.ndarray:
            """Backward pass (gradient) through activation"""
            if func == ActivationFunction.RELU:
                return (x > 0).astype(float)
            elif func == ActivationFunction.SIGMOID:
                s = Activation.forward(x, ActivationFunction.SIGMOID)
                return s * (1 - s)
            elif func == ActivationFunction.TANH:
                t = np.tanh(x)
                return 1 - t**2
            elif func == ActivationFunction.LEAKY_RELU:
                return np.where(x > 0, 1.0, 0.01)
            return np.ones_like(x)

    @dataclass
    class LayerConfig:
        """Neural network layer configuration"""
        input_size: int
        output_size: int
        activation: ActivationFunction = ActivationFunction.RELU
        dropout_rate: float = 0.0
        use_batch_norm: bool = False

    class DenseLayer:
        """Fully connected dense layer"""
        
        def __init__(self, config: LayerConfig):
            self.config = config
            
            # Xavier/Glorot initialization
            limit = np.sqrt(6 / (config.input_size + config.output_size))
            self.weights = np.random.uniform(
                -limit, limit, 
                (config.input_size, config.output_size)
            ).astype(np.float32)
            self.bias = np.zeros(config.output_size, dtype=np.float32)
            
            # Momentum for optimization
            self.weight_velocity = np.zeros_like(self.weights)
            self.bias_velocity = np.zeros_like(self.bias)
            
            # Batch normalization parameters
            if config.use_batch_norm:
                self.gamma = np.ones(config.output_size, dtype=np.float32)
                self.beta = np.zeros(config.output_size, dtype=np.float32)
                self.running_mean = np.zeros(config.output_size, dtype=np.float32)
                self.running_var = np.ones(config.output_size, dtype=np.float32)
        
        def forward(self, x: np.ndarray, training: bool = False) -> np.ndarray:
            """Forward pass"""
            # Linear transformation
            output = np.dot(x, self.weights) + self.bias
            
            # Batch normalization
            if self.config.use_batch_norm and training:
                mean = np.mean(output, axis=0)
                var = np.var(output, axis=0)
                output = (output - mean) / np.sqrt(var + 1e-8)
                output = self.gamma * output + self.beta
                
                # Update running statistics
                momentum = 0.9
                self.running_mean = momentum * self.running_mean + (1 - momentum) * mean
                self.running_var = momentum * self.running_var + (1 - momentum) * var
            
            # Activation
            output = Activation.forward(output, self.config.activation)
            
            # Dropout
            if self.config.dropout_rate > 0 and training:
                mask = np.random.binomial(1, 1 - self.config.dropout_rate, output.shape)
                output *= mask / (1 - self.config.dropout_rate)
            
            return output
        
        def update_weights(self, weight_grad: np.ndarray, bias_grad: np.ndarray, 
                          learning_rate: float, momentum: float = 0.9):
            """Update weights with momentum"""
            self.weight_velocity = momentum * self.weight_velocity - learning_rate * weight_grad
            self.bias_velocity = momentum * self.bias_velocity - learning_rate * bias_grad
            
            self.weights += self.weight_velocity
            self.bias += self.bias_velocity

    class NeuralNetwork:
        """Multi-layer neural network for threat prediction"""
        
        def __init__(self, input_size: int = None, hidden_layers: List[int] = None, 
                     output_size: int = None):
            if input_size is None:
                input_size = ConfigInstance.NN_INPUT_SIZE if ConfigInstance else 12
            if hidden_layers is None:
                hidden_layers = ConfigInstance.NN_HIDDEN_LAYERS if ConfigInstance else [64, 32, 16]
            if output_size is None:
                output_size = ConfigInstance.NN_OUTPUT_SIZE if ConfigInstance else 1
            
            self.layers: List[DenseLayer] = []
            
            # Build architecture
            layer_sizes = [input_size] + hidden_layers + [output_size]
            for i in range(len(layer_sizes) - 1):
                config = LayerConfig(
                    input_size=layer_sizes[i],
                    output_size=layer_sizes[i + 1],
                    activation=ActivationFunction.RELU if i < len(layer_sizes) - 2 else ActivationFunction.SIGMOID,
                    dropout_rate=0.2 if i < len(layer_sizes) - 2 else 0.0
                )
                self.layers.append(DenseLayer(config))
            
            self.loss_history: List[float] = []
            self.prediction_count: int = 0
        
        def predict(self, features: Union[np.ndarray, List[float]]) -> float:
            """Make prediction"""
            if isinstance(features, list):
                features = np.array(features, dtype=np.float32)
            
            if features.ndim == 1:
                features = features.reshape(1, -1)
            
            output = features
            for layer in self.layers:
                output = layer.forward(output, training=False)
            
            self.prediction_count += 1
            return float(output[0, 0])
        
        def train_step(self, X: np.ndarray, y: np.ndarray, learning_rate: float) -> float:
            """Single training step with backpropagation"""
            batch_size = X.shape[0]
            
            # Forward pass
            activations = [X]
            for layer in self.layers:
                activations.append(layer.forward(activations[-1], training=True))
            
            # Compute loss (MSE)
            predictions = activations[-1]
            loss = np.mean((predictions - y) ** 2)
            self.loss_history.append(loss)
            
            # Backward pass
            delta = 2 * (predictions - y) / batch_size
            
            for i in range(len(self.layers) - 1, -1, -1):
                layer = self.layers[i]
                
                # Compute gradients
                weight_grad = np.dot(activations[i].T, delta)
                bias_grad = np.sum(delta, axis=0)
                
                # Update weights
                layer.update_weights(weight_grad, bias_grad, learning_rate)
                
                # Backpropagate error
                if i > 0:
                    delta = np.dot(delta, layer.weights.T)
                    delta *= Activation.backward(activations[i], layer.config.activation)
            
            return loss
        
        def batch_train(self, features_list: List, targets: List[float], epochs: int = 3) -> float:
            """Train on batch of data"""
            X = np.vstack([np.array(f, dtype=np.float32).reshape(1, -1) for f in features_list])
            y = np.array(targets, dtype=np.float32).reshape(-1, 1)
            
            avg_loss = 0.0
            for _ in range(epochs):
                loss = self.train_step(X, y, ConfigInstance.LEARNING_RATE)
                avg_loss += loss
            
            return avg_loss / epochs
        
        def get_average_loss(self) -> float:
            """Get average recent loss"""
            if not self.loss_history:
                return 0.0
            recent = self.loss_history[-10:]
            return sum(recent) / len(recent)

else:
    # Pure Python fallback implementations
    class NeuralNetwork:
        """Simplified neural network without NumPy"""
        
        def __init__(self, input_size: int = None, hidden_layers: List[int] = None, 
                     output_size: int = None):
            self.prediction_count = 0
            self.loss_history = []
        
        def predict(self, features: List[float]) -> float:
            """Simple heuristic prediction"""
            self.prediction_count += 1
            
            # Calculate weighted average of features
            if not features:
                return 0.0
            
            weights = [0.3, 0.3, 0.2, 0.1, 0.1]
            score = 0.0
            for i, f in enumerate(features[:5]):
                w = weights[i] if i < len(weights) else 0.1
                score += f * w
            
            return clamp(score, 0.0, 1.0)
        
        def batch_train(self, features_list: List, targets: List[float], epochs: int = 3) -> float:
            """Placeholder training"""
            loss = 0.1
            self.loss_history.append(loss)
            return loss
        
        def get_average_loss(self) -> float:
            if not self.loss_history:
                return 0.0
            recent = self.loss_history[-10:]
            return sum(recent) / len(recent)

# ======================== REPLAY BUFFER & ONLINE LEARNING ========================

class ReplayBuffer:
    """Experience replay buffer for continual learning"""
    
    def __init__(self, capacity: int = None):
        if capacity is None:
            capacity = ConfigInstance.REPLAY_BUFFER_SIZE
        self.capacity = capacity
        self.buffer: deque = deque(maxlen=capacity)
    
    def add(self, features: List[float], label: float):
        """Add experience to buffer"""
        self.buffer.append({'features': features, 'label': label})
    
    def sample(self, batch_size: int) -> List[Dict]:
        """Sample random batch"""
        if len(self.buffer) < batch_size:
            return list(self.buffer)
        
        indices = random.sample(range(len(self.buffer)), batch_size)
        return [self.buffer[i] for i in indices]
    
    def __len__(self) -> int:
        return len(self.buffer)

class OnlineLearner:
    """Online learning manager"""
    
    def __init__(self, model: NeuralNetwork):
        self.model = model
        self.buffer = ReplayBuffer()
        self.learning_rate = ConfigInstance.LEARNING_RATE
        self.batch_size = ConfigInstance.BATCH_SIZE
        self.update_frequency = 10
        self.step_count = 0
    
    def add_experience(self, features: List[float], label: float):
        """Add new experience"""
        self.buffer.add(features, label)
        self.step_count += 1
        
        if self.step_count % self.update_frequency == 0:
            self.update_model()
    
    def update_model(self):
        """Update model from replay buffer"""
        if len(self.buffer) < self.batch_size or not NUMPY_AVAILABLE:
            return
        
        batch = self.buffer.sample(self.batch_size)
        features = [exp['features'] for exp in batch]
        labels = [exp['label'] for exp in batch]
        
        loss = self.model.batch_train(features, labels, epochs=ConfigInstance.EPOCHS_PER_UPDATE)
        
        # Adaptive learning rate
        if len(self.model.loss_history) > 1:
            if loss > self.model.loss_history[-2]:
                self.learning_rate *= 0.95
            else:
                self.learning_rate = min(0.01, self.learning_rate * 1.01)

class MetricsTracker:
    """Track and analyze model performance metrics"""
    
    def __init__(self):
        self.metrics_history: Dict[str, List[float]] = defaultdict(list)
        self.timestamps: List[datetime] = []
    
    def record(self, metrics: Dict[str, float]):
        """Record metrics snapshot"""
        self.timestamps.append(datetime.now())
        for key, value in metrics.items():
            self.metrics_history[key].append(value)
    
    def get_summary(self) -> Dict[str, Dict[str, float]]:
        """Get statistical summary of metrics"""
        summary = {}
        for metric, values in self.metrics_history.items():
            if values:
                if NUMPY_AVAILABLE:
                    summary[metric] = {
                        'current': values[-1],
                        'mean': float(np.mean(values)),
                        'std': float(np.std(values)),
                        'min': float(np.min(values)),
                        'max': float(np.max(values))
                    }
                else:
                    summary[metric] = {
                        'current': values[-1],
                        'mean': sum(values) / len(values),
                        'min': min(values),
                        'max': max(values)
                    }
        return summary

# ======================== HOST MONITORING MODULE ========================

class SystemMetricsCollector:
    """Collect host system metrics"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.baseline_metrics: Optional[Dict] = None
        self.collection_count: int = 0
        self.error_count: int = 0
    
    @timeout_handler(2.0)
    def _safe_get_cpu_percent(self) -> float:
        """Safely get CPU percentage"""
        if PSUTIL_AVAILABLE:
            try:
                return float(psutil.cpu_percent(interval=0.1))
            except (RuntimeError, OSError):
                pass
        
        # Synthetic fallback
        base = 30.0 + 40.0 * (hash(time.time()) % 100) / 100.0
        return clamp(base, 0.0, 100.0)
    
    @timeout_handler(1.0)
    def _safe_get_memory_percent(self) -> float:
        """Safely get memory percentage"""
        if PSUTIL_AVAILABLE:
            try:
                return float(psutil.virtual_memory().percent)
            except (RuntimeError, OSError):
                pass
        
        base = 45.0 + 30.0 * (hash(time.time() * 1.1) % 100) / 100.0
        return clamp(base, 0.0, 100.0)
    
    @timeout_handler(1.0)
    def _safe_get_process_count(self) -> int:
        """Safely get process count"""
        if PSUTIL_AVAILABLE:
            try:
                return len(psutil.pids())
            except (RuntimeError, OSError):
                pass
        
        base = 120 + int(80 * (hash(time.time() * 1.2) % 100) / 100.0)
        return max(0, base)
    
    def collect_metrics(self) -> Optional[Dict[str, Any]]:
        """Collect current system metrics"""
        try:
            cpu = self._safe_get_cpu_percent()
            memory = self._safe_get_memory_percent()
            processes = self._safe_get_process_count()
            
            metrics = {
                'timestamp': time.time(),
                'cpu_percent': cpu,
                'memory_percent': memory,
                'process_count': processes,
                'threat_level': 0.0,
                'anomaly_score': 0.0
            }
            
            self.collection_count += 1
            
            # Update baseline with exponential moving average
            if self.baseline_metrics is None:
                self.baseline_metrics = metrics.copy()
            else:
                alpha = 0.1
                self.baseline_metrics['cpu_percent'] = (
                    alpha * cpu + (1 - alpha) * self.baseline_metrics['cpu_percent']
                )
                self.baseline_metrics['memory_percent'] = (
                    alpha * memory + (1 - alpha) * self.baseline_metrics['memory_percent']
                )
            
            return metrics
            
        except TimeoutError as e:
            self.error_count += 1
            self.logger.warning(f"Metrics collection timeout: {e}")
            return None
        except Exception as e:
            self.error_count += 1
            self.logger.error(f"Metrics collection failed: {e}")
            return None

class AnomalyDetector:
    """Detect anomalies in system metrics using statistical methods"""
    
    def __init__(self):
        self.history: deque = deque(maxlen=100)
        self.stats: Dict[str, Dict[str, float]] = {}
    
    def update_statistics(self, metrics: Dict[str, Any]):
        """Update statistical baseline"""
        self.history.append(metrics)
        
        if len(self.history) < 10:
            return
        
        recent = list(self.history)[-min(100, len(self.history)):]
        
        if NUMPY_AVAILABLE:
            for key, attr in [('cpu', 'cpu_percent'), ('memory', 'memory_percent'), 
                            ('processes', 'process_count')]:
                vals = np.array([m.get(attr, 0) for m in recent])
                self.stats[key] = {
                    'mean': float(np.mean(vals)),
                    'std': max(float(np.std(vals)), 1.0),
                    'min': float(np.min(vals)),
                    'max': float(np.max(vals))
                }
        else:
            for key, attr in [('cpu', 'cpu_percent'), ('memory', 'memory_percent'), 
                            ('processes', 'process_count')]:
                vals = [m.get(attr, 0) for m in recent]
                mean = sum(vals) / len(vals)
                variance = sum((x - mean) ** 2 for x in vals) / len(vals)
                self.stats[key] = {
                    'mean': mean,
                    'std': max(variance ** 0.5, 1.0),
                    'min': min(vals),
                    'max': max(vals)
                }
    
    def detect_anomaly(self, metrics: Dict[str, Any]) -> Tuple[bool, float, List[str]]:
        """Detect if metrics are anomalous"""
        if len(self.history) < 10:
            return False, 0.0, []
        
        anomalies: List[str] = []
        max_z_score = 0.0
        
        # Check z-scores
        for key, attr in [('cpu', 'cpu_percent'), ('memory', 'memory_percent'), 
                         ('processes', 'process_count')]:
            value = metrics.get(attr, 0)
            stats = self.stats.get(key, {})
            
            if stats:
                mean = stats['mean']
                std = stats['std']
                z_score = abs(value - mean) / std
                max_z_score = max(max_z_score, z_score)
                
                if z_score > ConfigInstance.ANOMALY_THRESHOLD:
                    anomalies.append(f"anomaly_{key}_zscore_{z_score:.1f}")
        
        # Check for rapid changes
        if len(self.history) >= 2:
            prev = self.history[-1]
            cpu_delta = abs(metrics.get('cpu_percent', 0) - prev.get('cpu_percent', 0))
            mem_delta = abs(metrics.get('memory_percent', 0) - prev.get('memory_percent', 0))
            
            if cpu_delta > 30:
                anomalies.append("rapid_cpu_change")
                max_z_score = max(max_z_score, 3.0)
            if mem_delta > 25:
                anomalies.append("rapid_memory_change")
                max_z_score = max(max_z_score, 3.0)
        
        return len(anomalies) > 0, max_z_score, anomalies

class FeatureEngineer:
    """Extract features from system metrics for ML"""
    
    def __init__(self):
        self.history: deque = deque(maxlen=10)
    
    def extract_features(self, metrics: Dict[str, Any], history: List[Dict]) -> List[float]:
        """Extract feature vector from metrics"""
        self.history.append(metrics)
        features: List[float] = []
        
        # Normalized metrics
        features.append(clamp(metrics.get('cpu_percent', 0) / 100.0, 0, 1))
        features.append(clamp(metrics.get('memory_percent', 0) / 100.0, 0, 1))
        features.append(clamp(metrics.get('process_count', 0) / 500.0, 0, 1))
        
        # Velocity (rate of change)
        if len(self.history) >= 2:
            prev = self.history[-2]
            features.append(clamp((metrics.get('cpu_percent', 0) - prev.get('cpu_percent', 0)) / 100.0, -1, 1))
            features.append(clamp((metrics.get('memory_percent', 0) - prev.get('memory_percent', 0)) / 100.0, -1, 1))
            features.append(clamp((metrics.get('process_count', 0) - prev.get('process_count', 0)) / 500.0, -1, 1))
        else:
            features.extend([0.0, 0.0, 0.0])
        
        # Acceleration
        if len(self.history) >= 3:
            t1, t2, t3 = self.history[-3], self.history[-2], self.history[-1]
            cpu_accel = ((t3.get('cpu_percent', 0) - t2.get('cpu_percent', 0)) - 
                        (t2.get('cpu_percent', 0) - t1.get('cpu_percent', 0))) / 100.0
            features.append(clamp(cpu_accel, -1, 1))
        else:
            features.append(0.0)
        
        # Historical threat
        if len(history) >= 5:
            recent_threats = [m.get('threat_level', 0) for m in history[-5:]]
            if NUMPY_AVAILABLE:
                features.append(float(np.mean(recent_threats)))
                features.append(float(np.std(recent_threats)))
            else:
                mean_t = sum(recent_threats) / len(recent_threats)
                variance = sum((t - mean_t) ** 2 for t in recent_threats) / len(recent_threats)
                features.append(mean_t)
                features.append(variance ** 0.5)
        else:
            features.extend([0.0, 0.0])
        
        # Time features
        now = datetime.now()
        features.append((now.hour - 12) / 12.0)
        features.append(now.weekday() / 6.0)
        
        # Anomaly indicator
        features.append(min(metrics.get('anomaly_score', 0) / 5.0, 1.0))
        
        # Pad or truncate to fixed size
        while len(features) < ConfigInstance.NN_INPUT_SIZE:
            features.append(0.0)
        features = features[:ConfigInstance.NN_INPUT_SIZE]
        
        return features

class HostMonitor:
    """Integrated host monitoring and threat assessment"""
    
    def __init__(self, logger: logging.Logger, error_handler: ErrorHandler):
        self.logger = logger
        self.error_handler = error_handler
        
        # Components
        self.metrics_collector = SystemMetricsCollector(logger)
        self.anomaly_detector = AnomalyDetector()
        self.feature_engineer = FeatureEngineer()
        self.neural_network = NeuralNetwork()
        
        # State
        self.metrics_history: deque = deque(maxlen=ConfigInstance.MAX_ML_DATA_POINTS)
        self.training_buffer: deque = deque(maxlen=ConfigInstance.BATCH_SIZE * 2)
        self.assessment_count: int = 0
        self.training_count: int = 0
        self.anomaly_count: int = 0
        self.lock = threading.RLock()
        
        self.logger.info("HostMonitor initialized")
    
    def _calculate_base_threat(self, metrics: Dict[str, Any]) -> float:
        """Calculate baseline threat score from metrics"""
        cpu = metrics.get('cpu_percent', 0) / 100.0
        mem = metrics.get('memory_percent', 0) / 100.0
        proc = min(metrics.get('process_count', 0) / 500.0, 1.0)
        
        # Weighted combination
        base = 0.3 * cpu + 0.4 * mem + 0.3 * proc
        
        # Amplify if all metrics are high
        if cpu > 0.8 and mem > 0.8:
            base *= 1.3
        
        return clamp(base, 0.0, 1.0)
    
    def _assess_stability(self) -> float:
        """Assess system stability"""
        if len(self.metrics_history) < 5:
            return 1.0
        
        recent = list(self.metrics_history)[-5:]
        
        if NUMPY_AVAILABLE:
            cpu_vals = np.array([m.get('cpu_percent', 0) for m in recent])
            cpu_std = np.std(cpu_vals)
        else:
            cpu_vals = [m.get('cpu_percent', 0) for m in recent]
            mean = sum(cpu_vals) / len(cpu_vals)
            variance = sum((x - mean) ** 2 for x in cpu_vals) / len(cpu_vals)
            cpu_std = variance ** 0.5
        
        # Lower std = more stable = higher score
        stability = 1.0 - min(cpu_std / 50.0, 1.0)
        return stability
    
    def collect_and_assess(self) -> Tuple[float, Dict[str, Any]]:
        """Collect metrics and assess threat level"""
        with self.lock:
            try:
                # Collect metrics
                metrics = self.metrics_collector.collect_metrics()
                if not metrics:
                    return 0.0, {'error': 'Collection failed', 'confidence': 0.0}
                
                # Extract features
                features = self.feature_engineer.extract_features(
                    metrics,
                    list(self.metrics_history)
                )
                
                # ML prediction
                ml_prediction = self.neural_network.predict(features)
                ml_prediction = clamp(float(ml_prediction), 0.0, 1.0)
                
                # Anomaly detection
                is_anomaly, anomaly_score, anomaly_indicators = self.anomaly_detector.detect_anomaly(metrics)
                
                if is_anomaly:
                    self.anomaly_count += 1
                
                self.anomaly_detector.update_statistics(metrics)
                
                # Calculate ensemble threat
                base_threat = self._calculate_base_threat(metrics)
                ensemble_threat = 0.5 * base_threat + 0.5 * ml_prediction
                
                # Amplify on anomaly
                if anomaly_score > ConfigInstance.ANOMALY_THRESHOLD:
                    ensemble_threat = min(1.0, ensemble_threat * 1.2)
                
                # Update metrics
                metrics['threat_level'] = ensemble_threat
                metrics['ml_prediction'] = ml_prediction
                metrics['anomaly_score'] = anomaly_score
                metrics['is_anomaly'] = is_anomaly
                metrics['anomaly_indicators'] = anomaly_indicators
                
                self.metrics_history.append(metrics)
                
                # Train network periodically
                self.training_buffer.append((features, ensemble_threat))
                
                if len(self.training_buffer) >= ConfigInstance.BATCH_SIZE and self.assessment_count % 10 == 0:
                    self._train_network()
                
                self.assessment_count += 1
                
                # Build analysis report
                threat_category = ThreatLevel.from_score(ensemble_threat)
                
                analysis = {
                    'base_threat_score': base_threat,
                    'ml_prediction': ml_prediction,
                    'ensemble_threat_score': ensemble_threat,
                    'anomaly_score': anomaly_score,
                    'threat_category': threat_category.label,
                    'anomaly_indicators': anomaly_indicators[:3],
                    'system_stability': self._assess_stability(),
                    'is_anomaly': is_anomaly,
                    'confidence': self._calculate_confidence()
                }
                
                return ensemble_threat, analysis
                
            except Exception as e:
                self.error_handler.handle_error(e, "HostMonitor.collect_and_assess")
                return 0.0, {'error': str(e), 'confidence': 0.0}
    
    def _calculate_confidence(self) -> float:
        """Calculate confidence in assessment"""
        confidence = 0.5
        
        if len(self.metrics_history) > 10:
            confidence += 0.2
        
        if self.training_count > 5:
            confidence += 0.2
        
        if NUMPY_AVAILABLE and PSUTIL_AVAILABLE:
            confidence += 0.1
        
        return min(1.0, confidence)
    
    def _train_network(self):
        """Train neural network on collected data"""
        try:
            batch_data = list(self.training_buffer)[-ConfigInstance.BATCH_SIZE:]
            features = [item[0] for item in batch_data]
            targets = [item[1] for item in batch_data]
            
            loss = self.neural_network.batch_train(features, targets, epochs=ConfigInstance.EPOCHS_PER_UPDATE)
            self.training_count += 1
            
            if self.training_count % 10 == 0:
                self.logger.debug(f"HostMonitor trained (cycle: {self.training_count}, loss: {loss:.4f})")
            
        except Exception as e:
            self.error_handler.handle_error(e, "HostMonitor training")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get monitoring statistics"""
        return {
            'neural_predictions': self.neural_network.prediction_count,
            'training_cycles': self.training_count,
            'anomaly_detections': self.anomaly_count,
            'average_loss': self.neural_network.get_average_loss(),
            'assessment_count': self.assessment_count,
            'system_stability': self._assess_stability(),
            'metrics_collected': self.metrics_collector.collection_count
        }

# ======================== NETWORK SCANNING (ASYNC) ========================

class AsyncNetworkScanner:
    """Asynchronous network scanner using asyncio"""
    
    def __init__(self, logger: logging.Logger, error_handler: ErrorHandler):
        self.logger = logger
        self.error_handler = error_handler
        self.devices: Dict[str, NetworkDevice] = {}
        self.scan_count: int = 0
        self.lock = threading.RLock()
        
        # ML components
        self.threat_model: Optional[NeuralNetwork] = None
        self.replay_buffer = ReplayBuffer()
        self.metrics_tracker = MetricsTracker()
        
        if NUMPY_AVAILABLE:
            self.threat_model = NeuralNetwork(
                input_size=10,
                hidden_layers=[32, 16],
                output_size=1
            )
    
    async def _scan_port_async(self, ip: str, port: int, timeout: float = 1.0) -> bool:
        """Asynchronously scan a single port"""
        try:
            conn = asyncio.open_connection(ip, port)
            _, writer = await asyncio.wait_for(conn, timeout=timeout)
            writer.close()
            await writer.wait_closed()
            return True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return False
        except Exception:
            return False
    
    async def _scan_host_async(self, ip: str, ports: List[int]) -> ScanResult:
        """Asynchronously scan a host"""
        start_time = time.time()
        
        try:
            # Validate IP
            if not InputValidator.validate_ip(ip):
                return ScanResult(
                    target=ip,
                    open_ports=[],
                    closed_ports=ports,
                    services={},
                    scan_duration=0.0,
                    success=False,
                    error_message="Invalid IP address"
                )
            
            # Scan all ports concurrently
            tasks = [self._scan_port_async(ip, port, timeout=ConfigInstance.SCAN_TIMEOUT) for port in ports]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            open_ports = []
            closed_ports = []
            services = {}
            
            for port, result in zip(ports, results):
                if isinstance(result, bool) and result:
                    open_ports.append(port)
                    services[port] = ConfigInstance.COMMON_SERVICES.get(port, "Unknown")
                else:
                    closed_ports.append(port)
            
            duration = time.time() - start_time
            
            return ScanResult(
                target=ip,
                open_ports=open_ports,
                closed_ports=closed_ports,
                services=services,
                scan_duration=duration,
                success=True
            )
            
        except Exception as e:
            self.error_handler.handle_error(e, f"scan_host_async:{ip}")
            return ScanResult(
                target=ip,
                open_ports=[],
                closed_ports=ports,
                services={},
                scan_duration=time.time() - start_time,
                success=False,
                error_message=str(e)
            )
    
    async def scan_network_async(self, network: str, ports: Optional[List[int]] = None) -> Dict[str, NetworkDevice]:
        """Asynchronously scan entire network"""
        if ports is None:
            ports = ConfigInstance.PORT_SCAN_COMMON
        
        try:
            # Validate network
            if not InputValidator.validate_network(network):
                self.logger.error(f"Invalid network: {network}")
                return {}
            
            net = ipaddress.ip_network(network, strict=False)
            
            # Limit scan size
            hosts = list(net.hosts())[:254]
            
            self.logger.info(f"Starting async scan of {len(hosts)} hosts")
            
            # Scan all hosts concurrently
            tasks = [self._scan_host_async(str(ip), ports) for ip in hosts]
            results = await asyncio.gather(*tasks)
            
            # Process results
            with self.lock:
                for result in results:
                    if result.success and result.open_ports:
                        self._update_device(result)
                
                self.scan_count += 1
            
            self.logger.info(f"Async scan complete: {len([r for r in results if r.open_ports])} devices found")
            
            return dict(self.devices)
            
        except Exception as e:
            self.error_handler.handle_error(e, "scan_network_async")
            return {}
    
    def scan_network(self, network: str, ports: Optional[List[int]] = None) -> Dict[str, NetworkDevice]:
        """Synchronous wrapper for async scanning"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(self.scan_network_async(network, ports))
        finally:
            loop.close()
    
    def _update_device(self, scan_result: ScanResult):
        """Update or create device from scan result"""
        ip = scan_result.target
        
        if ip in self.devices:
            device = self.devices[ip]
            device.open_ports = scan_result.open_ports
            device.services = scan_result.services
            device.last_seen = datetime.now()
            device.response_times.append(scan_result.scan_duration)
        else:
            device = NetworkDevice(
                ip=ip,
                open_ports=scan_result.open_ports,
                services=scan_result.services,
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                response_times=[scan_result.scan_duration]
            )
            self.devices[ip] = device
        
        # Calculate risk score
        device.risk_score = self._calculate_risk_score(device)
    
    def _calculate_risk_score(self, device: NetworkDevice) -> float:
        """Calculate risk score for device"""
        score = 0.0
        
        # Risk from number of open ports
        score += min(len(device.open_ports) / 10.0, 0.3)
        
        # Risk from specific dangerous ports
        dangerous_ports = {23, 445, 3389}
        for port in device.open_ports:
            if port in dangerous_ports:
                score += 0.2
        
        # Risk from unknown services
        unknown_count = sum(1 for s in device.services.values() if s == "Unknown")
        score += min(unknown_count / 5.0, 0.2)
        
        return clamp(score, 0.0, 1.0)
    
    def get_devices(self) -> Dict[str, NetworkDevice]:
        """Get all discovered devices"""
        with self.lock:
            return dict(self.devices)
    
    def clear_devices(self):
        """Clear all devices"""
        with self.lock:
            self.devices.clear()

# ======================== NETWORK INTELLIGENCE AGENT ========================

@dataclass
class DashboardEvent:
    """Dashboard event for pub/sub"""
    event_type: DashboardEventType
    timestamp: datetime
    data: Dict[str, Any]
    severity: AlertSeverity = AlertSeverity.INFO

class DashboardIntegratedAgent:
    """Network intelligence agent integrated with dashboard"""
    
    def __init__(self, logger: logging.Logger, error_handler: ErrorHandler):
        self.logger = logger
        self.error_handler = error_handler
        self.scanner = AsyncNetworkScanner(logger, error_handler)
        self.state = AgentState.IDLE
        self.stats = {
            'scans_initiated': 0,
            'successful_scans': 0,
            'failed_scans': 0,
            'devices_discovered': 0,
            'total_ports_scanned': 0
        }
        self.lock = threading.RLock()
        self.event_subscribers: List[Callable] = []
    
    def subscribe(self, callback: Callable[[DashboardEvent], None]):
        """Subscribe to agent events"""
        self.event_subscribers.append(callback)
    
    def _publish_event(self, event: DashboardEvent):
        """Publish event to subscribers"""
        for callback in self.event_subscribers:
            try:
                callback(event)
            except Exception as e:
                self.error_handler.handle_error(e, "event_subscriber")
    
    def scan_network(self, network: str) -> Dict[str, Any]:
        """Scan network and return results"""
        with self.lock:
            self.state = AgentState.SCANNING
            self.stats['scans_initiated'] += 1
        
        try:
            devices = self.scanner.scan_network(network)
            
            with self.lock:
                self.stats['successful_scans'] += 1
                self.stats['devices_discovered'] = len(devices)
                self.state = AgentState.IDLE
            
            # Publish event
            event = DashboardEvent(
                event_type=DashboardEventType.NETWORK_SCAN_COMPLETE,
                timestamp=datetime.now(),
                data={'network': network, 'device_count': len(devices)},
                severity=AlertSeverity.INFO
            )
            self._publish_event(event)
            
            return {
                'success': True,
                'network': network,
                'devices_found': len(devices),
                'devices': {ip: dev.to_dict() for ip, dev in devices.items()}
            }
            
        except Exception as e:
            with self.lock:
                self.stats['failed_scans'] += 1
                self.state = AgentState.ERROR
            
            self.error_handler.handle_error(e, "scan_network")
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_devices(self) -> List[Dict[str, Any]]:
        """Get discovered devices"""
        devices = self.scanner.get_devices()
        return [dev.to_dict() for dev in devices.values()]
    
    def get_status(self) -> Dict[str, Any]:
        """Get agent status"""
        with self.lock:
            return {
                'state': self.state.name,
                'stats': dict(self.stats),
                'devices_tracked': len(self.scanner.devices)
            }

# ======================== PERFORMANCE & THREAT MONITORING ========================

class PerformanceMonitor:
    """Monitor system performance"""
    
    def __init__(self, dashboard_controller):
        self.dashboard = dashboard_controller
        self.logger = logging.getLogger(__name__ + ".PerformanceMonitor")
        self.monitoring_active = False
        self.monitoring_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.check_interval = 10  # Default 10 seconds, will use ConfigInstance when available
    
    def start_monitoring(self):
        """Start performance monitoring"""
        if self.monitoring_active:
            return
        
        # Update check interval from config
        if ConfigInstance:
            self.check_interval = ConfigInstance.PERFORMANCE_MONITORING_INTERVAL
        
        self.monitoring_active = True
        self.stop_event.clear()
        
        self.monitoring_thread = threading.Thread(
            target=self._monitoring_loop,
            daemon=True,
            name="PerformanceMonitor"
        )
        self.monitoring_thread.start()
        
        self.logger.info("Performance monitoring started")
    
    def stop_monitoring(self):
        """Stop performance monitoring"""
        if not self.monitoring_active:
            return
        
        self.monitoring_active = False
        self.stop_event.set()
        
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=2.0)
        
        self.logger.info("Performance monitoring stopped")
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        while not self.stop_event.is_set():
            try:
                # Monitor agent performance
                with self.dashboard.state_lock:
                    agents = list(self.dashboard.state.active_agents.values())
                
                for agent in agents:
                    if agent.performance_score < 0.5:
                        self.dashboard.alert_queue.put(
                            f"{Colors.WARNING}Performance alert: Agent {agent.id} "
                            f"performing below threshold ({agent.performance_score:.2f}){Colors.RESET}"
                        )
                
                self.stop_event.wait(self.check_interval)
                
            except Exception as e:
                self.dashboard.error_handler.handle_error(e, "performance_monitoring_loop")
                self.stop_event.wait(5)

class ThreatMonitor:
    """Monitor threats using host monitoring"""
    
    def __init__(self, dashboard_controller):
        self.dashboard = dashboard_controller
        self.logger = logging.getLogger(__name__ + ".ThreatMonitor")
        self.monitoring_active = False
        self.monitoring_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.check_interval = 5  # Default 5 seconds, will use ConfigInstance when available
        self.host_monitor: Optional[HostMonitor] = None
        self.threat_history: deque = deque(maxlen=100)
    
    def start_monitoring(self):
        """Start threat monitoring"""
        if self.monitoring_active:
            return
        
        try:
            # Update check interval from config
            if ConfigInstance:
                self.check_interval = ConfigInstance.THREAT_MONITORING_INTERVAL
            
            self.host_monitor = HostMonitor(self.logger, self.dashboard.error_handler)
            self.monitoring_active = True
            self.stop_event.clear()
            
            with self.dashboard.state_lock:
                self.dashboard.state.ml_threat_assessment_active = True
                self.dashboard.state.threat_monitoring_active = True
            
            self.monitoring_thread = threading.Thread(
                target=self._monitoring_loop,
                daemon=True,
                name="ThreatMonitor"
            )
            self.monitoring_thread.start()
            
            self.dashboard.alert_queue.put(
                f"{Colors.SUCCESS}ML-Enhanced Threat Monitor started - "
                f"checking every {self.check_interval}s{Colors.RESET}"
            )
            self.logger.info("Threat monitoring started with ML engine")
            
        except Exception as e:
            self.dashboard.error_handler.handle_error(e, "start_threat_monitoring")
            self.dashboard.alert_queue.put(f"{Colors.ERROR}Threat monitor failed: {str(e)}{Colors.RESET}")
            raise
    
    def stop_monitoring(self):
        """Stop threat monitoring"""
        if not self.monitoring_active:
            return
        
        self.monitoring_active = False
        self.stop_event.set()
        
        with self.dashboard.state_lock:
            self.dashboard.state.ml_threat_assessment_active = False
            self.dashboard.state.threat_monitoring_active = False
        
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=2.0)
        
        self.logger.info("Threat monitoring stopped")
    
    def _monitoring_loop(self):
        """Main threat monitoring loop"""
        while not self.stop_event.is_set():
            try:
                if not self.host_monitor:
                    break
                
                # Collect and assess
                threat_score, analysis = self.host_monitor.collect_and_assess()
                
                # Update state
                with self.dashboard.state_lock:
                    self.dashboard.state.host_threat_level = threat_score
                    self.dashboard.state.neural_predictions = self.host_monitor.neural_network.prediction_count
                
                self.threat_history.append({
                    'timestamp': datetime.now(),
                    'score': threat_score,
                    'analysis': analysis
                })
                
                # Alert on high threats
                threat_level = ThreatLevel.from_score(threat_score)
                if threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
                    self.dashboard.alert_queue.put(
                        f"{Colors.ERROR}HOST THREAT ALERT: {threat_level.label} "
                        f"(Score: {threat_score:.3f}){Colors.RESET}"
                    )
                
                # Alert on anomalies
                if analysis.get('is_anomaly'):
                    indicators = ', '.join(analysis.get('anomaly_indicators', [])[:2])
                    self.dashboard.alert_queue.put(
                        f"{Colors.WARNING}Anomaly detected: {indicators}{Colors.RESET}"
                    )
                
                self.stop_event.wait(self.check_interval)
                
            except Exception as e:
                self.dashboard.error_handler.handle_error(e, "threat_monitoring_loop")
                self.stop_event.wait(5)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get monitoring statistics"""
        if not self.host_monitor:
            return {'active': False}
        
        stats = self.host_monitor.get_statistics()
        stats['active'] = self.monitoring_active
        stats['threat_history_size'] = len(self.threat_history)
        
        return stats

# ======================== DASHBOARD CONTROLLER ========================

class DashboardController:
    """Main dashboard controller with integrated network and host monitoring"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.error_handler = ErrorHandler(self.logger)
        
        # State management
        self.state = SystemState()
        self.state_lock = threading.RLock()
        self.display_lock = threading.Lock()
        
        # UI components
        self.alert_queue: queue.Queue = queue.Queue()
        self.running = False
        self.refresh_count = 0
        self.startup_time = datetime.now()
        
        # Integrated agents
        self.network_agent = DashboardIntegratedAgent(self.logger, self.error_handler)
        self.host_monitor: Optional[HostMonitor] = None
        
        # Monitors
        self.performance_monitor = PerformanceMonitor(self)
        self.threat_monitor = ThreatMonitor(self)
        
        # Rate limiter
        self.rate_limiter = RateLimiter(
            ConfigInstance.MAX_REQUESTS_PER_WINDOW,
            ConfigInstance.RATE_LIMIT_WINDOW
        )
        
        # Audit logger
        try:
            self.audit_logger = AuditLogger(ConfigInstance.LOG_DIR)
        except Exception as e:
            self.logger.warning(f"Audit logging disabled: {e}")
            self.audit_logger = None
        
        # Load persisted state
        self._load_state()
        
        with self.state_lock:
            self.state.status = SystemStatus.READY
        
        self.logger.info("DashboardController initialized")
    
    def _load_state(self):
        """Load persisted state from disk"""
        try:
            if not ConfigInstance.STATE_FILE.exists():
                self.logger.info("No state file found, starting fresh")
                return
            
            with open(ConfigInstance.STATE_FILE, 'r') as f:
                data = json.load(f)
            
            # Restore network devices
            devices_data = data.get('devices', {})
            for ip, dev_dict in devices_data.items():
                device = NetworkDevice(
                    ip=dev_dict['ip'],
                    hostname=dev_dict.get('hostname'),
                    mac_address=dev_dict.get('mac_address'),
                    open_ports=dev_dict.get('open_ports', []),
                    services=dev_dict.get('services', {}),
                    risk_score=dev_dict.get('risk_score', 0.0),
                    last_seen=datetime.fromisoformat(dev_dict['last_seen']),
                    first_seen=datetime.fromisoformat(dev_dict['first_seen'])
                )
                self.network_agent.scanner.devices[ip] = device
            
            self.logger.info(f"Loaded {len(devices_data)} devices from state file")
            
        except Exception as e:
            self.logger.error(f"Failed to load state: {e}")
    
    def _save_state(self):
        """Save current state to disk"""
        try:
            devices = self.network_agent.scanner.get_devices()
            
            data = {
                'timestamp': datetime.now().isoformat(),
                'devices': {ip: dev.to_dict() for ip, dev in devices.items()}
            }
            
            # Write atomically
            temp_file = ConfigInstance.STATE_FILE.with_suffix('.tmp')
            with open(temp_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            # Set secure permissions
            os.chmod(temp_file, ConfigInstance.SECURE_FILE_PERMISSIONS)
            
            # Atomic rename
            temp_file.replace(ConfigInstance.STATE_FILE)
            
            self.logger.info(f"Saved state with {len(devices)} devices")
            
        except Exception as e:
            self.logger.error(f"Failed to save state: {e}")
    
    def start(self):
        """Start the dashboard"""
        self.running = True
        
        with self.state_lock:
            self.state.status = SystemStatus.OPERATIONAL
        
        # Start monitors
        self.performance_monitor.start_monitoring()
        # Don't auto-start threat monitor - let user activate it manually
        
        # Start display loop
        try:
            self._display_loop()
        except KeyboardInterrupt:
            self.logger.info("Shutdown requested")
        finally:
            self.shutdown()
    
    def shutdown(self):
        """Graceful shutdown"""
        self.logger.info("Initiating shutdown")
        
        with self.state_lock:
            self.state.status = SystemStatus.SHUTTING_DOWN
        
        self.running = False
        
        # Stop monitors
        self.performance_monitor.stop_monitoring()
        self.threat_monitor.stop_monitoring()
        
        # Save state
        self._save_state()
        
        self.logger.info("Shutdown complete")
    
    def _display_loop(self):
        """Main display loop"""
        while self.running:
            try:
                self._clear_screen()
                self._render_dashboard()
                
                # Wait for user input with timeout
                self._handle_user_input()
                
            except Exception as e:
                self.error_handler.handle_error(e, "display_loop")
                time.sleep(1)
    
    def _clear_screen(self):
        """Clear terminal screen"""
        try:
            os.system('cls' if os.name == 'nt' else 'clear')
        except:
            print("\n" * 50)
    
    def _render_dashboard(self):
        """Render complete dashboard"""
        try:
            with self.display_lock:
                self.refresh_count += 1
                self._render_header()
                self._render_system_status()
                self._render_network_intelligence()
                self._render_host_monitoring()
                self._render_agent_status()
                self._render_monitoring_status()
                self._render_alerts()
                self._render_command_interface()
        except Exception as e:
            self.error_handler.handle_error(e, "render_dashboard")
    
    def _render_header(self):
        """Render dashboard header"""
        print(f"{Colors.HEADER}{'=' * ConfigInstance.TERMINAL_WIDTH}")
        print(f"  NEXUS UNIFIED v{VERSION} - PRODUCTION EDITION")
        print(f"  Network Intelligence + Host Monitoring | ML-Enhanced Security")
        print(f"{'=' * ConfigInstance.TERMINAL_WIDTH}{Colors.RESET}")
        print()
    
    def _render_system_status(self):
        """Render system status section"""
        with self.state_lock:
            status = self.state.status.value
            scans = self.state.total_scans
            errors = self.state.error_count
            
        status_color = Colors.SUCCESS if status == "OPERATIONAL" else Colors.WARNING
        error_color = Colors.SUCCESS if errors < 5 else Colors.WARNING if errors < 20 else Colors.ERROR
        uptime = str(datetime.now() - self.startup_time).split('.')[0]
        
        print(f"{Colors.HEADER}=== SYSTEM STATUS ==={Colors.RESET}")
        print(f"  Status: {status_color}{status}{Colors.RESET} | "
              f"Uptime: {uptime} | "
              f"Scans: {scans} | "
              f"Errors: {error_color}{errors}{Colors.RESET}")
        print()
    
    def _render_network_intelligence(self):
        """Render network intelligence section"""
        print(f"{Colors.HEADER}=== NETWORK INTELLIGENCE (AGESIS_B) ==={Colors.RESET}")
        
        agent_status = self.network_agent.get_status()
        devices = self.network_agent.get_devices()
        
        state_color = Colors.SUCCESS if agent_status['state'] == 'IDLE' else Colors.INFO
        
        print(f"  Agent State: {state_color}{agent_status['state']}{Colors.RESET}")
        print(f"  Devices Discovered: {len(devices)}")
        print(f"  Successful Scans: {agent_status['stats']['successful_scans']}")
        
        # Show recent devices
        if devices:
            print(f"\n  {Colors.ACCENT}Recent Devices:{Colors.RESET}")
            for dev in devices[:5]:
                risk_color = Colors.SUCCESS if dev['risk_score'] < 0.3 else Colors.WARNING if dev['risk_score'] < 0.7 else Colors.ERROR
                print(f"    {Symbols.DOT} {dev['ip']}: {len(dev['open_ports'])} open ports | "
                      f"Risk: {risk_color}{dev['risk_score']:.2f}{Colors.RESET}")
        
        print()
    
    def _render_host_monitoring(self):
        """Render host monitoring section"""
        print(f"{Colors.HEADER}=== HOST MONITORING (SYSTEM METRICS) ==={Colors.RESET}")
        
        with self.state_lock:
            host_threat = self.state.host_threat_level
            ml_active = self.state.ml_threat_assessment_active
        
        threat_level = ThreatLevel.from_score(host_threat)
        threat_color = Colors.SUCCESS if threat_level == ThreatLevel.MINIMAL else (
            Colors.WARNING if threat_level in [ThreatLevel.LOW, ThreatLevel.MEDIUM] else Colors.ERROR
        )
        
        print(f"  ML Engine: {Colors.SUCCESS if ml_active else Colors.MUTED}"
              f"{'ACTIVE' if ml_active else 'INACTIVE'}{Colors.RESET}")
        print(f"  Host Threat Score: {threat_color}{host_threat:.3f} ({threat_level.label}){Colors.RESET}")
        
        # Show statistics if monitoring active
        if self.threat_monitor.monitoring_active:
            stats = self.threat_monitor.get_statistics()
            print(f"  Assessments: {stats.get('assessment_count', 0)} | "
                  f"Training Cycles: {stats.get('training_cycles', 0)} | "
                  f"Anomalies: {stats.get('anomaly_detections', 0)}")
        
        print()
    
    def _render_agent_status(self):
        """Render agent status section"""
        with self.state_lock:
            active_agents = list(self.state.active_agents.values())
            found_agents = list(self.state.found_agents.values())
        
        print(f"{Colors.HEADER}=== AGENT STATUS ==={Colors.RESET}")
        print(f"  Active Agents: {Colors.SUCCESS}{len(active_agents)}{Colors.RESET} | "
              f"Discovered: {Colors.INFO}{len(found_agents)}{Colors.RESET}")
        
        if active_agents:
            print(f"\n  {Colors.ACCENT}Active Agents:{Colors.RESET}")
            for agent in active_agents[:5]:
                perf_color = Colors.SUCCESS if agent.performance_score >= 0.7 else Colors.WARNING if agent.performance_score >= 0.5 else Colors.ERROR
                print(f"    {Symbols.DOT} {agent.id}: {agent.status.value} | "
                      f"Performance: {perf_color}{agent.performance_score:.2f}{Colors.RESET}")
            
            if len(active_agents) > 5:
                print(f"{Colors.MUTED}    ... and {len(active_agents) - 5} more{Colors.RESET}")
        
        print()
    
    def _render_monitoring_status(self):
        """Render monitoring status section"""
        print(f"{Colors.HEADER}=== MONITORING STATUS ==={Colors.RESET}")
        
        perf_status = "ACTIVE" if self.performance_monitor.monitoring_active else "INACTIVE"
        threat_status = "ACTIVE" if self.threat_monitor.monitoring_active else "INACTIVE"
        
        perf_color = Colors.SUCCESS if self.performance_monitor.monitoring_active else Colors.MUTED
        threat_color = Colors.SUCCESS if self.threat_monitor.monitoring_active else Colors.MUTED
        
        print(f"  Performance Monitor: {perf_color}{perf_status}{Colors.RESET}")
        print(f"  Threat Monitor: {threat_color}{threat_status}{Colors.RESET}")
        
        with self.state_lock:
            opt_status = "ON" if self.state.status == SystemStatus.OPTIMIZING else "OFF"
            def_status = "ON" if self.state.defensive_active else "OFF"
        
        opt_color = Colors.SUCCESS if opt_status == "ON" else Colors.MUTED
        def_color = Colors.SUCCESS if def_status == "ON" else Colors.MUTED
        
        print(f"  Auto Optimization: {opt_color}{opt_status}{Colors.RESET}")
        print(f"  Auto Defense: {def_color}{def_status}{Colors.RESET}")
        
        print()
    
    def _render_alerts(self):
        """Render alerts section"""
        print(f"{Colors.HEADER}=== SYSTEM ALERTS ==={Colors.RESET}")
        
        if self.alert_queue.empty():
            print(f"{Colors.SUCCESS}  {Symbols.CHECK} All systems operating normally{Colors.RESET}")
        else:
            count = 0
            max_display = ConfigInstance.MAX_ALERTS_DISPLAY
            
            alerts = []
            while not self.alert_queue.empty() and count < max_display:
                try:
                    alert = self.alert_queue.get_nowait()
                    alerts.append(alert)
                    count += 1
                except queue.Empty:
                    break
            
            for alert in alerts:
                print(f"  {alert}")
            
            if not self.alert_queue.empty():
                remaining = self.alert_queue.qsize()
                print(f"{Colors.MUTED}  ... {remaining} more alerts{Colors.RESET}")
        
        print()
    
    def _render_command_interface(self):
        """Render command interface with numbered menu"""
        print(f"{Colors.HEADER}=== COMMAND INTERFACE ==={Colors.RESET}")
        print(f"{Colors.ACCENT}Available Commands:{Colors.RESET}")
        print(f"  {Colors.INFO}[1]{Colors.RESET} Scan Network          {Colors.MUTED}(scan network CIDR){Colors.RESET}")
        print(f"  {Colors.INFO}[2]{Colors.RESET} Scan Agents           {Colors.MUTED}(discover agents in vault){Colors.RESET}")
        print(f"  {Colors.INFO}[3]{Colors.RESET} Engage Agents         {Colors.MUTED}(engage discovered agents){Colors.RESET}")
        print(f"  {Colors.INFO}[4]{Colors.RESET} Show Devices          {Colors.MUTED}(list network devices){Colors.RESET}")
        print(f"  {Colors.INFO}[5]{Colors.RESET} Export Data           {Colors.MUTED}(export config+devices to csv/json){Colors.RESET}")
        print(f"  {Colors.INFO}[6]{Colors.RESET} Auto Optimization ON  {Colors.MUTED}(enable optimization){Colors.RESET}")
        print(f"  {Colors.INFO}[7]{Colors.RESET} Auto Optimization OFF {Colors.MUTED}(disable optimization){Colors.RESET}")
        print(f"  {Colors.INFO}[8]{Colors.RESET} Auto Defense ON       {Colors.MUTED}(enable defense mode){Colors.RESET}")
        print(f"  {Colors.INFO}[9]{Colors.RESET} Auto Defense OFF      {Colors.MUTED}(disable defense mode){Colors.RESET}")
        print(f"  {Colors.INFO}[10]{Colors.RESET} System Status        {Colors.MUTED}(detailed status){Colors.RESET}")
        print(f"  {Colors.INFO}[11]{Colors.RESET} Clear Alerts         {Colors.MUTED}(clear alert queue){Colors.RESET}")
        print(f"  {Colors.INFO}[12]{Colors.RESET} Help                 {Colors.MUTED}(show help){Colors.RESET}")
        print(f"  {Colors.INFO}[13]{Colors.RESET} ML Engine ON         {Colors.MUTED}(activate ML threat engine){Colors.RESET}")
        print(f"  {Colors.INFO}[14]{Colors.RESET} Threat Monitor ON    {Colors.MUTED}(start threat monitoring){Colors.RESET}")
        print(f"  {Colors.INFO}[0]{Colors.RESET} Quit                  {Colors.MUTED}(shutdown system){Colors.RESET}")
        print(f"\n{Colors.HEADER}NEXUS>{Colors.RESET} ", end='', flush=True)
    
    def _handle_user_input(self):
        """Handle user input"""
        try:
            # Non-blocking input with timeout
            import select
            
            if hasattr(select, 'select'):
                if sys.stdin in select.select([sys.stdin], [], [], ConfigInstance.REFRESH_INTERVAL)[0]:
                    command = input().strip()
                    
                    if command:
                        self._process_command(command)
            else:
                # Fallback for systems without select
                time.sleep(ConfigInstance.REFRESH_INTERVAL)
            
        except (EOFError, KeyboardInterrupt):
            raise
        except Exception:
            # Fallback for systems without select
            time.sleep(ConfigInstance.REFRESH_INTERVAL)
    
    def _process_command(self, command_input: str):
        """Process user command - COMPLETE FIXED VERSION"""
        try:
            parts = command_input.split()
            if not parts:
                return
            
            cmd_input = parts[0].lower()
            args = parts[1:] if len(parts) > 1 else []
            
            # Map numbered commands to handlers
            if cmd_input.isdigit():
                cmd_num = int(cmd_input)
                
                if cmd_num == 0:
                    self._cmd_quit()
                elif cmd_num == 1:
                    if args:
                        self._cmd_scan_network(args[0])
                    else:
                        self.alert_queue.put(f"{Colors.WARNING}Usage: 1 <network> (e.g., 1 192.168.1.0/24){Colors.RESET}")
                elif cmd_num == 2:
                    self._cmd_scan_agents()
                elif cmd_num == 3:
                    self._cmd_engage_agents()
                elif cmd_num == 4:
                    self._cmd_show_devices()
                elif cmd_num == 5:
                    if args:
                        self._cmd_export(args[0])
                    else:
                        self.alert_queue.put(f"{Colors.WARNING}Usage: 5 <csv|json> (e.g., 5 csv){Colors.RESET}")
                elif cmd_num == 6:
                    self._cmd_auto_optimization_on()
                elif cmd_num == 7:
                    self._cmd_auto_optimization_off()
                elif cmd_num == 8:
                    self._cmd_auto_defense_on()
                elif cmd_num == 9:
                    self._cmd_auto_defense_off()
                elif cmd_num == 10:
                    self._cmd_status()
                elif cmd_num == 11:
                    self._cmd_clear_alerts()
                elif cmd_num == 12:
                    self._cmd_help()
                elif cmd_num == 13:
                    self._cmd_ml_engine_on()
                elif cmd_num == 14:
                    self._cmd_threat_monitor_on()
                else:
                    self.alert_queue.put(f"{Colors.ERROR}Invalid command number: {cmd_num}{Colors.RESET}")
            
            # Text command support (backwards compatible)
            elif cmd_input in ['scan', 'network'] and args:
                self._cmd_scan_network(args[0])
            elif cmd_input in ['agents', 'scan_agents', 'scanagents']:
                self._cmd_scan_agents()
            elif cmd_input in ['engage', 'engage_agents']:
                self._cmd_engage_agents()
            elif cmd_input in ['devices', 'list', 'show']:
                self._cmd_show_devices()
            elif cmd_input == 'export' and args:
                self._cmd_export(args[0])
            elif cmd_input in ['opt_on', 'optimize_on', 'optimization_on']:
                self._cmd_auto_optimization_on()
            elif cmd_input in ['opt_off', 'optimize_off', 'optimization_off']:
                self._cmd_auto_optimization_off()
            elif cmd_input in ['defense_on', 'defensive_on']:
                self._cmd_auto_defense_on()
            elif cmd_input in ['defense_off', 'defensive_off']:
                self._cmd_auto_defense_off()
            elif cmd_input in ['status', 'info', 'stat']:
                self._cmd_status()
            elif cmd_input in ['clear', 'cls', 'clear_alerts']:
                self._cmd_clear_alerts()
            elif cmd_input in ['help', 'h', '?']:
                self._cmd_help()
            elif cmd_input in ['quit', 'exit', 'q']:
                self._cmd_quit()
            else:
                self.alert_queue.put(f"{Colors.ERROR}Unknown command: {cmd_input}. Type '12' or 'help' for commands.{Colors.RESET}")
        
        except Exception as e:
            self.error_handler.handle_error(e, "process_command")
            self.alert_queue.put(f"{Colors.ERROR}Command error: {str(e)}{Colors.RESET}")
    
    def _cmd_scan_network(self, network: str):
        """Execute network scan command - [1]"""
        # Validate input
        if not InputValidator.validate_network(network):
            self.alert_queue.put(f"{Colors.ERROR}Invalid network: {network}{Colors.RESET}")
            return
        
        self.alert_queue.put(f"{Colors.INFO}{Symbols.RADAR} Starting network scan of {network}...{Colors.RESET}")
        
        with self.state_lock:
            self.state.status = SystemStatus.SCANNING
        
        # Run scan in background
        def scan_task():
            try:
                result = self.network_agent.scan_network(network)
                if result['success']:
                    self.alert_queue.put(
                        f"{Colors.SUCCESS}{Symbols.CHECK} Network scan complete: "
                        f"{result['devices_found']} devices discovered{Colors.RESET}"
                    )
                    
                    with self.state_lock:
                        self.state.status = SystemStatus.OPERATIONAL
                        self.state.total_scans += 1
                        self.state.last_scan_time = datetime.now()
                else:
                    self.alert_queue.put(
                        f"{Colors.ERROR}{Symbols.CROSS} Network scan failed: "
                        f"{result.get('error', 'Unknown error')}{Colors.RESET}"
                    )
                    with self.state_lock:
                        self.state.status = SystemStatus.ERROR
            except Exception as e:
                self.error_handler.handle_error(e, "scan_network_task")
                self.alert_queue.put(f"{Colors.ERROR}Scan error: {str(e)}{Colors.RESET}")
                with self.state_lock:
                    self.state.status = SystemStatus.ERROR
        
        thread = threading.Thread(target=scan_task, daemon=True, name="NetworkScanTask")
        thread.start()
    
    def _cmd_scan_agents(self):
        """Scan for agents in vault - [2]"""
        self.alert_queue.put(f"{Colors.INFO}{Symbols.RADAR} Scanning for agents in vault...{Colors.RESET}")
        
        with self.state_lock:
            self.state.status = SystemStatus.SCANNING
            self.state.total_scans += 1
            scan_num = self.state.total_scans
        
        try:
            found_count = 0
            new_agents = []
            
            for vault_path in ConfigInstance.EDS_VAULT_PATHS:
                try:
                    path = Path(vault_path)
                    if not path.exists():
                        continue
                    
                    for pattern in ConfigInstance.AGENT_PATTERNS:
                        for agent_file in path.rglob(f"{pattern}*{ConfigInstance.AGENT_EXTENSION}"):
                            if agent_file.is_file():
                                agent_id = agent_file.stem
                                
                                with self.state_lock:
                                    if agent_id not in self.state.found_agents:
                                        agent = Agent(
                                            id=agent_id,
                                            status=AgentStatus.DISCOVERED,
                                            discovery_time=datetime.now(),
                                            last_seen=datetime.now(),
                                            path=agent_file
                                        )
                                        self.state.found_agents[agent_id] = agent
                                        new_agents.append(agent_id)
                                        found_count += 1
                
                except Exception as e:
                    self.error_handler.handle_error(e, f"scan_vault:{vault_path}")
            
            with self.state_lock:
                self.state.status = SystemStatus.OPERATIONAL
                self.state.last_scan_time = datetime.now()
                total_found = len(self.state.found_agents)
            
            if found_count > 0:
                self.alert_queue.put(
                    f"{Colors.SUCCESS}{Symbols.CHECK} Agent scan #{scan_num} complete: "
                    f"{found_count} new agents discovered (Total: {total_found}){Colors.RESET}"
                )
                for agent_id in new_agents[:5]:
                    self.alert_queue.put(f"  {Symbols.DOT} {agent_id}")
                if len(new_agents) > 5:
                    self.alert_queue.put(f"{Colors.MUTED}  ... and {len(new_agents) - 5} more{Colors.RESET}")
            else:
                self.alert_queue.put(
                    f"{Colors.INFO}Agent scan #{scan_num} complete: "
                    f"No new agents found (Total: {total_found}){Colors.RESET}"
                )
        
        except Exception as e:
            self.error_handler.handle_error(e, "scan_agents")
            self.alert_queue.put(f"{Colors.ERROR}Agent scan failed: {str(e)}{Colors.RESET}")
            with self.state_lock:
                self.state.status = SystemStatus.ERROR
    
    def _cmd_engage_agents(self):
        """Engage discovered agents - [3]"""
        with self.state_lock:
            found_agents = list(self.state.found_agents.values())
            active_count = len(self.state.active_agents)
        
        if not found_agents:
            self.alert_queue.put(f"{Colors.WARNING}No agents to engage. Run agent scan first (command 2).{Colors.RESET}")
            return
        
        self.alert_queue.put(f"{Colors.INFO}{Symbols.GEAR} Engaging {len(found_agents)} discovered agents...{Colors.RESET}")
        
        engaged_count = 0
        for agent in found_agents:
            try:
                with self.state_lock:
                    if agent.id not in self.state.active_agents:
                        agent.status = AgentStatus.ONLINE
                        agent.last_seen = datetime.now()
                        self.state.active_agents[agent.id] = agent
                        engaged_count += 1
            except Exception as e:
                self.error_handler.handle_error(e, f"engage_agent:{agent.id}")
        
        with self.state_lock:
            total_active = len(self.state.active_agents)
        
        if engaged_count > 0:
            self.alert_queue.put(
                f"{Colors.SUCCESS}{Symbols.CHECK} Engaged {engaged_count} agents. "
                f"Total active: {total_active}{Colors.RESET}"
            )
        else:
            self.alert_queue.put(
                f"{Colors.INFO}All discovered agents already engaged. "
                f"Active: {total_active}{Colors.RESET}"
            )
    
    def _cmd_show_devices(self):
        """Show discovered devices - [4]"""
        devices = self.network_agent.get_devices()
        
        if not devices:
            self.alert_queue.put(f"{Colors.WARNING}No devices discovered yet. Run network scan (command 1).{Colors.RESET}")
            return
        
        self.alert_queue.put(f"{Colors.INFO}=== Discovered Network Devices ({len(devices)}) ==={Colors.RESET}")
        
        for idx, dev in enumerate(devices[:10], 1):
            risk_color = (Colors.SUCCESS if dev['risk_score'] < 0.3 else 
                         Colors.WARNING if dev['risk_score'] < 0.7 else Colors.ERROR)
            
            ports_str = ','.join(map(str, dev['open_ports'][:5]))
            if len(dev['open_ports']) > 5:
                ports_str += f",+{len(dev['open_ports']) - 5}"
            
            self.alert_queue.put(
                f"  {idx}. {Colors.ACCENT}{dev['ip']}{Colors.RESET} | "
                f"Ports: [{ports_str}] | "
                f"Risk: {risk_color}{dev['risk_score']:.2f}{Colors.RESET}"
            )
        
        if len(devices) > 10:
            self.alert_queue.put(f"{Colors.MUTED}  ... and {len(devices) - 10} more devices{Colors.RESET}")
    
    def _cmd_export(self, format_type: str):
        """Export system config and discovered devices - [5]"""
        format_type = format_type.lower()

        if format_type not in ['csv', 'json']:
            self.alert_queue.put(f"{Colors.ERROR}Invalid format. Use: csv or json{Colors.RESET}")
            return

        devices = self.network_agent.get_devices()

        if not devices:
            self.alert_queue.put(f"{Colors.WARNING}No devices to export. Run network scan first (command 1).{Colors.RESET}")
            return

        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"nexus_export_{timestamp}.{format_type}"

            if format_type == 'json':
                # Export both system config and devices
                export_data = {
                    'export_timestamp': timestamp,
                    'system_config': ConfigInstance.to_dict(),
                    'system_status': {
                        'status': self.state.status.name,
                        'total_scans': self.state.total_scans,
                        'agents_loaded': self.state.agents_loaded,
                        'agents_engaged': self.state.agents_engaged,
                        'defensive_active': self.state.defensive_active,
                        'last_scan_time': self.state.last_scan_time.isoformat() if self.state.last_scan_time else None
                    },
                    'devices': devices,
                    'device_count': len(devices)
                }
                with open(filename, 'w') as f:
                    json.dump(export_data, f, indent=2)
            else:  # CSV
                with open(filename, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=[
                        'ip', 'hostname', 'mac_address', 'open_ports', 'risk_score', 'last_seen'
                    ])
                    writer.writeheader()

                    for dev in devices:
                        row = {
                            'ip': dev['ip'],
                            'hostname': dev.get('hostname', 'N/A'),
                            'mac_address': dev.get('mac_address', 'N/A'),
                            'open_ports': ','.join(map(str, dev['open_ports'])),
                            'risk_score': dev['risk_score'],
                            'last_seen': dev['last_seen']
                        }
                        writer.writerow(row)

            # Set secure permissions
            os.chmod(filename, ConfigInstance.SECURE_FILE_PERMISSIONS)

            export_info = f"{len(devices)} devices"
            if format_type == 'json':
                export_info += " + system config"

            self.alert_queue.put(
                f"{Colors.SUCCESS}{Symbols.CHECK} Exported {export_info} to {filename}{Colors.RESET}"
            )

            if self.audit_logger:
                self.audit_logger.log_event("data_export", {
                    'format': format_type,
                    'device_count': len(devices),
                    'includes_config': format_type == 'json',
                    'filename': filename
                })

        except Exception as e:
            self.error_handler.handle_error(e, "export_devices")
            self.alert_queue.put(f"{Colors.ERROR}Export failed: {str(e)}{Colors.RESET}")
    
    def _cmd_auto_optimization_on(self):
        """Enable auto optimization - [6]"""
        with self.state_lock:
            if self.state.status == SystemStatus.OPTIMIZING:
                self.alert_queue.put(f"{Colors.INFO}Auto optimization already active{Colors.RESET}")
                return
            
            self.state.status = SystemStatus.OPTIMIZING
        
        self.alert_queue.put(
            f"{Colors.SUCCESS}{Symbols.GEAR} Auto optimization ENABLED - "
            f"System will optimize discovered agents automatically{Colors.RESET}"
        )
        
        if self.audit_logger:
            self.audit_logger.log_event("auto_optimization_enabled", {
                'timestamp': datetime.now().isoformat()
            })
    
    def _cmd_auto_optimization_off(self):
        """Disable auto optimization - [7]"""
        with self.state_lock:
            if self.state.status != SystemStatus.OPTIMIZING:
                self.alert_queue.put(f"{Colors.INFO}Auto optimization not active{Colors.RESET}")
                return
            
            self.state.status = SystemStatus.OPERATIONAL
        
        self.alert_queue.put(
            f"{Colors.WARNING}{Symbols.INFO} Auto optimization DISABLED{Colors.RESET}"
        )
        
        if self.audit_logger:
            self.audit_logger.log_event("auto_optimization_disabled", {
                'timestamp': datetime.now().isoformat()
            })
    
    def _cmd_auto_defense_on(self):
        """Enable auto defense mode - [8]"""
        with self.state_lock:
            if self.state.defensive_active:
                self.alert_queue.put(f"{Colors.INFO}Auto defense already active{Colors.RESET}")
                return
            
            self.state.defensive_active = True
            self.state.status = SystemStatus.DEFENSIVE
        
        self.alert_queue.put(
            f"{Colors.SUCCESS}{Symbols.SHIELD} Auto defense mode ENABLED - "
            f"System will respond to threats automatically{Colors.RESET}"
        )
        
        if self.audit_logger:
            self.audit_logger.log_event("auto_defense_enabled", {
                'timestamp': datetime.now().isoformat()
            }, severity="WARNING")
    
    def _cmd_auto_defense_off(self):
        """Disable auto defense mode - [9]"""
        with self.state_lock:
            if not self.state.defensive_active:
                self.alert_queue.put(f"{Colors.INFO}Auto defense not active{Colors.RESET}")
                return
            
            self.state.defensive_active = False
            self.state.status = SystemStatus.OPERATIONAL
        
        self.alert_queue.put(
            f"{Colors.WARNING}{Symbols.INFO} Auto defense mode DISABLED{Colors.RESET}"
        )
        
        if self.audit_logger:
            self.audit_logger.log_event("auto_defense_disabled", {
                'timestamp': datetime.now().isoformat()
            })
    
    def _cmd_status(self):
        """Show detailed status - [10]"""
        with self.state_lock:
            status_info = {
                'System Status': self.state.status.value,
                'Network Agent': self.network_agent.state.name,
                'Active Agents': len(self.state.active_agents),
                'Found Agents': len(self.state.found_agents),
                'Network Devices': len(self.network_agent.scanner.devices),
                'Host Threat': f"{self.state.host_threat_level:.3f}",
                'ML Assessment': 'ACTIVE' if self.state.ml_threat_assessment_active else 'INACTIVE',
                'Auto Optimization': 'ON' if self.state.status == SystemStatus.OPTIMIZING else 'OFF',
                'Auto Defense': 'ON' if self.state.defensive_active else 'OFF',
                'Monitoring': 'ACTIVE' if self.state.monitoring_active else 'INACTIVE',
                'Total Scans': self.state.total_scans,
                'Error Count': self.state.error_count,
                'Neural Predictions': self.state.neural_predictions
            }
        
        self.alert_queue.put(f"{Colors.INFO}=== Detailed System Status ==={Colors.RESET}")
        for key, value in status_info.items():
            self.alert_queue.put(f"  {Colors.ACCENT}{key}:{Colors.RESET} {value}")
    
    def _cmd_clear_alerts(self):
        """Clear alert queue - [11]"""
        cleared = 0
        while not self.alert_queue.empty():
            try:
                self.alert_queue.get_nowait()
                cleared += 1
            except queue.Empty:
                break
        
        self.alert_queue.put(
            f"{Colors.SUCCESS}{Symbols.CHECK} Alert queue cleared ({cleared} messages){Colors.RESET}"
        )
    
    def _cmd_help(self):
        """Show help - [12]"""
        help_text = [
            f"{Colors.HEADER}=== NEXUS Unified Command Reference ==={Colors.RESET}",
            f"",
            f"{Colors.ACCENT}Network Operations:{Colors.RESET}",
            f"  {Colors.INFO}[1]{Colors.RESET} scan <network>      - Scan network (e.g., 1 192.168.1.0/24)",
            f"  {Colors.INFO}[4]{Colors.RESET} devices             - List discovered network devices",
            f"  {Colors.INFO}[5]{Colors.RESET} export <csv|json>   - Export config+device data (e.g., 5 json)",
            f"",
            f"{Colors.ACCENT}Agent Operations:{Colors.RESET}",
            f"  {Colors.INFO}[2]{Colors.RESET} scan agents         - Discover agents in vault",
            f"  {Colors.INFO}[3]{Colors.RESET} engage agents       - Engage discovered agents",
            f"",
            f"{Colors.ACCENT}Automation Controls:{Colors.RESET}",
            f"  {Colors.INFO}[6]{Colors.RESET} optimization on     - Enable auto optimization",
            f"  {Colors.INFO}[7]{Colors.RESET} optimization off    - Disable auto optimization",
            f"  {Colors.INFO}[8]{Colors.RESET} defense on          - Enable auto defense mode",
            f"  {Colors.INFO}[9]{Colors.RESET} defense off         - Disable auto defense mode",
            f"",
            f"{Colors.ACCENT}Monitoring & ML:{Colors.RESET}",
            f"  {Colors.INFO}[13]{Colors.RESET} ml engine on        - Activate ML threat engine",
            f"  {Colors.INFO}[14]{Colors.RESET} threat monitor on   - Start threat monitoring",
            f"",
            f"{Colors.ACCENT}System Controls:{Colors.RESET}",
            f"  {Colors.INFO}[10]{Colors.RESET} status             - Show detailed system status",
            f"  {Colors.INFO}[11]{Colors.RESET} clear              - Clear alert queue",
            f"  {Colors.INFO}[12]{Colors.RESET} help               - Show this help",
            f"  {Colors.INFO}[0]{Colors.RESET} quit                - Shutdown system",
            f"",
            f"{Colors.MUTED}Tip: You can use numbers or text commands (e.g., '1 192.168.1.0/24' or 'scan 192.168.1.0/24'){Colors.RESET}"
        ]
        
        for line in help_text:
            self.alert_queue.put(line)
    
    def _cmd_quit(self):
        """Quit system - [0]"""
        self.alert_queue.put(f"{Colors.WARNING}Initiating system shutdown...{Colors.RESET}")
        self.running = False
    
    def _cmd_ml_engine_on(self):
        """Activate ML Engine - [13]"""
        with self.state_lock:
            if self.state.ml_threat_assessment_active:
                self.alert_queue.put(f"{Colors.INFO}ML Engine already active{Colors.RESET}")
                return
            
            # Manually set ML active flag
            self.state.ml_threat_assessment_active = True
        
        self.alert_queue.put(
            f"{Colors.SUCCESS}{Symbols.BRAIN} ML Threat Engine ACTIVATED - "
            f"Neural network threat assessment online{Colors.RESET}"
        )
        
        if self.audit_logger:
            self.audit_logger.log_event("ml_engine_activated", {
                'timestamp': datetime.now().isoformat()
            })
    
    def _cmd_threat_monitor_on(self):
        """Start Threat Monitor - [14]"""
        if self.threat_monitor.monitoring_active:
            self.alert_queue.put(f"{Colors.INFO}Threat Monitor already active{Colors.RESET}")
            return
        
        try:
            self.threat_monitor.start_monitoring()
            self.alert_queue.put(
                f"{Colors.SUCCESS}{Symbols.SHIELD} Threat Monitor STARTED - "
                f"Real-time host monitoring active{Colors.RESET}"
            )
            
            if self.audit_logger:
                self.audit_logger.log_event("threat_monitor_started", {
                    'timestamp': datetime.now().isoformat()
                }, severity="INFO")
        except Exception as e:
            self.error_handler.handle_error(e, "start_threat_monitor_command")
            self.alert_queue.put(f"{Colors.ERROR}Failed to start Threat Monitor: {str(e)}{Colors.RESET}")

# ======================== SETUP & INITIALIZATION ========================

def setup_logging():
    """Configure logging"""
    try:
        ConfigInstance.LOG_DIR.mkdir(parents=True, exist_ok=True)
        
        # Set secure permissions
        os.chmod(ConfigInstance.LOG_DIR, ConfigInstance.SECURE_DIR_PERMISSIONS)
        
        log_file = ConfigInstance.LOG_DIR / f"nexus_{datetime.now().strftime('%Y%m%d')}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        
        # Set secure permissions on log file
        if log_file.exists():
            os.chmod(log_file, ConfigInstance.SECURE_FILE_PERMISSIONS)
        
    except Exception as e:
        print(f"Warning: Logging setup failed: {e}")

def check_environment() -> List[str]:
    """Check environment and return any issues"""
    issues = []
    
    if sys.version_info < (3, 6):
        issues.append("Python 3.6+ required")
    
    try:
        if os.getenv('TERM') == 'dumb' or not sys.stdout.isatty():
            Colors.disable_colors()
            Symbols.disable_unicode()
            issues.append("Colors disabled - terminal doesn't support ANSI codes")
    except:
        pass
    
    if not NUMPY_AVAILABLE:
        issues.append("NumPy not available - using pure Python ML implementations")
    
    if not PSUTIL_AVAILABLE:
        issues.append("psutil not available - using synthetic system metrics")
    
    try:
        test_file = Path("test_write_permissions.tmp")
        test_file.touch()
        test_file.unlink()
    except Exception:
        issues.append("Limited write permissions detected")
    
    return issues

# ======================== MAIN ENTRY POINT ========================

def main():
    """Main entry point"""
    global ConfigInstance
    
    # Initialize configuration
    ConfigInstance = Config.load_from_file()
    
    print(f"{Colors.HEADER}{'=' * 80}")
    print(f"     NEXUS UNIFIED v{VERSION} - PRODUCTION EDITION     ")
    print(f"  Elite Network Intelligence & Host Monitoring System  ")
    print(f"   ML-Enhanced | Async Scanning | Data Persistence | Export   ")
    print(f"                Initializing System Components...                ")
    print(f"{'=' * 80}{Colors.RESET}")
    
    try:
        # Check environment
        issues = check_environment()
        if issues:
            print(f"{Colors.WARNING}Environment Notes:{Colors.RESET}")
            for issue in issues:
                print(f"  * {issue}")
            print()
        
        # Setup logging
        setup_logging()
        logger = logging.getLogger(__name__)
        logger.info("NEXUS Unified Dashboard starting up")
        
        # Create dashboard
        dashboard = DashboardController()
        
        # Startup messages
        print(f"{Colors.SUCCESS}{Symbols.CHECK} System initialization complete{Colors.RESET}")
        print(f"{Colors.INFO}Dashboard API: ENABLED | "
              f"AGESIS_B Agent: ACTIVE | "
              f"Host Monitor: ACTIVE{Colors.RESET}")
        print(f"{Colors.INFO}Security Level: {SECURITY_LEVEL} | "
              f"ML Status: {'Neural Network Active' if NUMPY_AVAILABLE else 'Fallback Mode'}{Colors.RESET}")
        print(f"{Colors.INFO}Neural Architecture: {ConfigInstance.NN_INPUT_SIZE}→"
              f"{ConfigInstance.NN_HIDDEN_LAYERS}→{ConfigInstance.NN_OUTPUT_SIZE}{Colors.RESET}")
        print(f"{Colors.INFO}Network Scanner: Async | "
              f"State Persistence: Enabled | "
              f"Export: CSV/JSON{Colors.RESET}")
        print(f"{Colors.INFO}Platform: Android Pyroid3 Compatible | "
              f"Compliance: OWASP/CWE/NIST{Colors.RESET}")
        
        time.sleep(2)
        
        # Start dashboard
        dashboard.start()
        
    except KeyboardInterrupt:
        print(f"\n{Colors.SUCCESS}NEXUS Unified Dashboard shutdown complete{Colors.RESET}")
        print(f"{Colors.INFO}Thank you for using NEXUS Production Edition{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.ERROR}Critical system error: {e}{Colors.RESET}")
        logging.exception("Critical error during startup")
        sys.exit(1)

# ======================== MODULE EXPORTS ========================

__all__ = [
    # Core Controllers
    'DashboardController',
    'DashboardIntegratedAgent',
    'HostMonitor',
    
    # Configuration
    'Config',
    'VERSION',
    'AGENT_ID',
    'SECURITY_LEVEL',
    
    # Security Components
    'InputValidator',
    'PathValidator',
    'RateLimiter',
    'AuditLogger',
    'SecureRandom',
    'ErrorHandler',
    
    # ML/NN Components
    'NeuralNetwork',
    'OnlineLearner',
    'MetricsTracker',
    'ReplayBuffer',
    
    # Host Monitoring
    'SystemMetricsCollector',
    'AnomalyDetector',
    'FeatureEngineer',
    
    # Network Components
    'AsyncNetworkScanner',
    'NetworkDevice',
    'ScanResult',
    
    # Data Structures
    'Agent',
    'SystemState',
    'AgentState',
    'AgentStatus',
    'SystemStatus',
    'ThreatLevel',
    'DashboardEvent',
    'DashboardEventType',
    'AlertSeverity',
    
    # Monitoring
    'PerformanceMonitor',
    'ThreatMonitor',
    
    # Display
    'Colors',
    'Symbols'
]

if __name__ == "__main__":
    main()
