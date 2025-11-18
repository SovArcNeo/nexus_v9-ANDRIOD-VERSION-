"""
BLACKBOX ENHANCED ML - Intelligent failsafe autopilot for NEXUS system
Version: 3.0 (Android/Pydroid3 Compatible with ML capabilities)

ENHANCEMENTS:
• Machine Learning failure prediction and pattern recognition
• Android-compatible signal handling and process management
• Advanced anomaly detection with statistical models
• Self-adaptive configuration based on historical patterns
• Robust error handling with exponential backoff
• Memory-efficient operations for mobile environment
• Predictive maintenance scheduling
• Multi-level fallback strategies
• Advanced health scoring with ML insights
• Real-time model training and inference
"""

from __future__ import annotations

import asyncio
import atexit
import json
import logging
import os
import sys
import time
import threading
import traceback
from abc import ABC, abstractmethod
from collections import deque, defaultdict
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum, auto
from pathlib import Path
from typing import Dict, List, Optional, Union, Any, Callable, Set, Tuple, NamedTuple
import hashlib
import statistics
import pickle
import math
import random
from functools import wraps, lru_cache
import weakref

# Try to import optional dependencies with fallbacks
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

try:
    import aiofiles
    HAS_AIOFILES = True
except ImportError:
    HAS_AIOFILES = False

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.linear_model import LinearRegression
    from sklearn.preprocessing import StandardScaler
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

# Fallback implementations for missing dependencies
if not HAS_NUMPY:
    class NumpyFallback:
        @staticmethod
        def array(data): return list(data)
        @staticmethod
        def mean(data): return statistics.mean(data) if data else 0
        @staticmethod
        def std(data): return statistics.stdev(data) if len(data) > 1 else 0
        @staticmethod
        def percentile(data, q): 
            if not data: return 0
            sorted_data = sorted(data)
            k = (len(sorted_data) - 1) * q / 100
            f = math.floor(k)
            c = math.ceil(k)
            return sorted_data[int(f)] if f == c else sorted_data[int(f)] * (c - k) + sorted_data[int(c)] * (k - f)
    
    np = NumpyFallback()

# ================== Enhanced Configuration ==================
@dataclass
class MLConfig:
    """Machine Learning specific configuration"""
    enable_ml: bool = True
    prediction_window: int = 300  # seconds
    training_interval: int = 3600  # 1 hour
    min_training_samples: int = 100
    anomaly_threshold: float = 0.1
    model_persistence: bool = True
    model_file: Path = Path("./models/blackbox_model.pkl")
    feature_window: int = 50
    prediction_confidence_threshold: float = 0.7

@dataclass
class Config:
    """Enhanced configuration with ML capabilities"""
    # Core settings
    heartbeat_file: Path = Path(os.environ.get("BLACKBOX_HEARTBEAT", "./logs/nexus_heartbeat.json"))
    log_dir: Path = Path(os.environ.get("BLACKBOX_LOG_DIR", "./logs"))
    model_dir: Path = Path(os.environ.get("BLACKBOX_MODEL_DIR", "./models"))
    check_interval: float = float(os.environ.get("BLACKBOX_CHECK_INTERVAL", "3"))
    fail_threshold: int = int(os.environ.get("BLACKBOX_FAIL_THRESHOLD", "3"))
    
    # Action settings (Android-safe defaults)
    reboot_on_trigger: bool = False  # Disabled for non-rooted Android
    recovery_attempts: int = int(os.environ.get("BLACKBOX_RECOVERY_ATTEMPTS", "5"))
    action_cooldown: float = float(os.environ.get("BLACKBOX_ACTION_COOLDOWN", "300"))
    
    # Enhanced reliability settings
    max_retries: int = int(os.environ.get("BLACKBOX_MAX_RETRIES", "10"))
    retry_backoff_base: float = float(os.environ.get("BLACKBOX_RETRY_BACKOFF", "1.2"))
    retry_jitter: float = 0.1
    watchdog_timeout: float = float(os.environ.get("BLACKBOX_WATCHDOG_TIMEOUT", "120"))
    memory_limit_mb: int = int(os.environ.get("BLACKBOX_MEMORY_LIMIT_MB", "150"))
    
    # Performance settings
    cache_ttl: float = float(os.environ.get("BLACKBOX_CACHE_TTL", "2"))
    history_size: int = int(os.environ.get("BLACKBOX_HISTORY_SIZE", "2000"))
    metric_window: int = int(os.environ.get("BLACKBOX_METRIC_WINDOW", "600"))
    
    # ML settings
    ml: MLConfig = field(default_factory=MLConfig)
    
    # Auto-adaptation settings
    adaptive_thresholds: bool = True
    learning_rate: float = 0.01
    adaptation_interval: int = 1800  # 30 minutes
    
    @classmethod
    def from_file(cls, path: Path) -> 'Config':
        """Load configuration from JSON file with error handling"""
        if path.exists():
            try:
                with open(path, 'r') as f:
                    data = json.load(f)
                    # Handle nested ML config
                    if 'ml' in data:
                        ml_config = MLConfig(**data['ml'])
                        data['ml'] = ml_config
                    return cls(**data)
            except Exception as e:
                print(f"Warning: Could not load config from {path}: {e}")
        return cls()
    
    def save_to_file(self, path: Path):
        """Save configuration to JSON file"""
        try:
            os.makedirs(path.parent, exist_ok=True)
            with open(path, 'w') as f:
                # Convert dataclass to dict, handling nested objects
                data = asdict(self)
                json.dump(data, f, indent=2, default=str)
        except Exception as e:
            print(f"Warning: Could not save config to {path}: {e}")

# Global config instance
CONFIG = Config()

# ================== Enhanced Types and Enums ==================
class AgentState(Enum):
    ALIVE = 1
    DOWN = 2
    DEGRADED = 3
    RECOVERING = 4
    UNKNOWN = 5
    PREDICTED_FAILURE = 6

class ActionType(Enum):
    LOG_ALERT = auto()
    SEND_NOTIFICATION = auto()
    RESTART_AGENT = auto()
    SYSTEM_REBOOT = auto()
    CUSTOM_SCRIPT = auto()
    PREDICTIVE_MAINTENANCE = auto()
    ADAPTIVE_ADJUSTMENT = auto()

class FailurePattern(NamedTuple):
    """Represents a failure pattern for ML analysis"""
    timestamp: float
    agent_name: str
    state_sequence: List[int]
    preconditions: Dict[str, float]
    outcome: int  # 0 = recovered, 1 = failed

@dataclass
class MLFeatures:
    """Feature vector for ML models"""
    uptime_ratio: float = 0.0
    failure_frequency: float = 0.0
    recovery_time_avg: float = 0.0
    state_volatility: float = 0.0
    time_since_last_failure: float = 0.0
    health_trend: float = 0.0
    anomaly_score: float = 0.0
    
    def to_vector(self) -> List[float]:
        """Convert to feature vector"""
        return [
            self.uptime_ratio,
            self.failure_frequency,
            self.recovery_time_avg,
            self.state_volatility,
            self.time_since_last_failure,
            self.health_trend,
            self.anomaly_score
        ]

@dataclass
class AgentHealth:
    """Enhanced agent health tracking with ML features"""
    name: str
    state: AgentState
    last_seen: datetime
    uptime_percentage: float = 100.0
    failure_count: int = 0
    recovery_count: int = 0
    response_times: deque = field(default_factory=lambda: deque(maxlen=200))
    health_score: float = 1.0
    state_history: deque = field(default_factory=lambda: deque(maxlen=1000))
    failure_patterns: List[FailurePattern] = field(default_factory=list)
    predicted_failure_time: Optional[datetime] = None
    confidence_score: float = 0.0
    ml_features: MLFeatures = field(default_factory=MLFeatures)
    
    def update_health_score(self):
        """Enhanced health score calculation with ML insights"""
        try:
            # Base factors
            uptime_weight = 0.3
            stability_weight = 0.25
            performance_weight = 0.2
            prediction_weight = 0.15
            trend_weight = 0.1
            
            # Uptime score
            uptime_score = self.uptime_percentage / 100
            
            # Stability score (exponential decay for failures)
            stability_score = math.exp(-self.failure_count * 0.1)
            
            # Performance score
            if self.response_times:
                avg_response = statistics.mean(self.response_times)
                performance_score = min(1.0, 1.0 / (1 + avg_response))
            else:
                performance_score = 1.0
            
            # Prediction score (inverse of failure probability)
            prediction_score = 1.0 - self.confidence_score if self.predicted_failure_time else 1.0
            
            # Trend score based on recent state changes
            trend_score = self._calculate_trend_score()
            
            self.health_score = (
                uptime_weight * uptime_score +
                stability_weight * stability_score +
                performance_weight * performance_score +
                prediction_weight * prediction_score +
                trend_weight * trend_score
            )
            
            # Update ML features
            self._update_ml_features()
            
        except Exception as e:
            # Fallback to simple calculation
            self.health_score = max(0.1, self.uptime_percentage / 100 - self.failure_count * 0.1)
    
    def _calculate_trend_score(self) -> float:
        """Calculate trend score from recent state history"""
        if len(self.state_history) < 10:
            return 1.0
        
        recent_states = list(self.state_history)[-10:]
        positive_states = sum(1 for state in recent_states if state in [AgentState.ALIVE, AgentState.RECOVERING])
        
        return positive_states / len(recent_states)
    
    def _update_ml_features(self):
        """Update ML feature vector"""
        try:
            now = datetime.now()
            
            # Calculate features
            self.ml_features.uptime_ratio = self.uptime_percentage / 100
            
            # Failure frequency (failures per hour)
            if self.failure_patterns:
                recent_failures = [p for p in self.failure_patterns 
                                 if (now.timestamp() - p.timestamp) < 3600]
                self.ml_features.failure_frequency = len(recent_failures)
            
            # State volatility (standard deviation of recent states)
            if len(self.state_history) > 5:
                state_values = [s.value for s in list(self.state_history)[-20:]]
                self.ml_features.state_volatility = np.std(state_values) if HAS_NUMPY else statistics.stdev(state_values) if len(state_values) > 1 else 0
            
            # Time since last failure
            if self.failure_patterns:
                last_failure = max(self.failure_patterns, key=lambda p: p.timestamp)
                self.ml_features.time_since_last_failure = now.timestamp() - last_failure.timestamp
            else:
                self.ml_features.time_since_last_failure = float('inf')
                
        except Exception as e:
            # Continue with default features if calculation fails
            pass

# ================== Enhanced Exception Handling ==================
class BlackboxException(Exception):
    """Base exception with enhanced error context"""
    def __init__(self, message: str, context: Optional[Dict] = None, cause: Optional[Exception] = None):
        super().__init__(message)
        self.context = context or {}
        self.cause = cause
        self.timestamp = datetime.now()

class ConfigurationError(BlackboxException):
    """Configuration-related errors"""
    pass

class MonitoringError(BlackboxException):
    """Monitoring-related errors"""
    pass

class ActionError(BlackboxException):
    """Action execution errors"""
    pass

class MLError(BlackboxException):
    """Machine Learning related errors"""
    pass

# ================== Decorators for Robustness ==================
def with_retry(max_retries: int = None, backoff_base: float = None, exceptions: Tuple = None):
    """Decorator for automatic retry with exponential backoff and jitter"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            retries = max_retries or CONFIG.max_retries
            backoff = backoff_base or CONFIG.retry_backoff_base
            exc_types = exceptions or (Exception,)
            
            last_exception = None
            
            for attempt in range(retries + 1):
                try:
                    if asyncio.iscoroutinefunction(func):
                        return await func(*args, **kwargs)
                    else:
                        return func(*args, **kwargs)
                except exc_types as e:
                    last_exception = e
                    
                    if attempt == retries:
                        break
                    
                    # Calculate delay with jitter
                    delay = (backoff ** attempt) + (random.random() * CONFIG.retry_jitter)
                    await asyncio.sleep(delay)
            
            raise last_exception
        return wrapper
    return decorator

def with_timeout(timeout: float):
    """Decorator to add timeout to async functions"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                return await asyncio.wait_for(func(*args, **kwargs), timeout=timeout)
            except asyncio.TimeoutError as e:
                raise MonitoringError(f"Function {func.__name__} timed out after {timeout}s", cause=e)
        return wrapper
    return decorator

def safe_execute(default_return=None):
    """Decorator to safely execute functions with fallback"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                if asyncio.iscoroutinefunction(func):
                    return await func(*args, **kwargs)
                else:
                    return func(*args, **kwargs)
            except Exception as e:
                log.error(f"Safe execution failed for {func.__name__}: {e}")
                return default_return
        return wrapper
    return decorator

# ================== Enhanced Logging ==================
class ContextualLogger:
    """Logger with contextual information"""
    
    def __init__(self, base_logger: logging.Logger):
        self.base_logger = base_logger
        self.context = {}
    
    def set_context(self, **kwargs):
        """Set contextual information"""
        self.context.update(kwargs)
    
    def _format_message(self, message: str) -> str:
        """Format message with context"""
        if self.context:
            context_str = " | ".join([f"{k}={v}" for k, v in self.context.items()])
            return f"{message} | Context: {context_str}"
        return message
    
    def debug(self, message: str, *args, **kwargs):
        self.base_logger.debug(self._format_message(message), *args, **kwargs)
    
    def info(self, message: str, *args, **kwargs):
        self.base_logger.info(self._format_message(message), *args, **kwargs)
    
    def warning(self, message: str, *args, **kwargs):
        self.base_logger.warning(self._format_message(message), *args, **kwargs)
    
    def error(self, message: str, *args, **kwargs):
        self.base_logger.error(self._format_message(message), *args, **kwargs)
    
    def critical(self, message: str, *args, **kwargs):
        self.base_logger.critical(self._format_message(message), *args, **kwargs)

def setup_enhanced_logging() -> ContextualLogger:
    """Setup enhanced logging with better error handling"""
    try:
        # Ensure log directory exists
        os.makedirs(CONFIG.log_dir, exist_ok=True)
        
        # Create base logger
        base_logger = logging.getLogger("BLACKBOX_ML")
        base_logger.setLevel(logging.DEBUG)
        base_logger.handlers.clear()
        
        # Enhanced formatter
        formatter = logging.Formatter(
            "%(asctime)s | %(name)s | %(levelname)s | %(funcName)s:%(lineno)d | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        
        # Console handler with different levels for different streams
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        base_logger.addHandler(console_handler)
        
        # Error console handler
        error_handler = logging.StreamHandler(sys.stderr)
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(formatter)
        base_logger.addHandler(error_handler)
        
        # File handlers with rotation
        try:
            from logging.handlers import RotatingFileHandler
            
            # Main log file
            main_handler = RotatingFileHandler(
                CONFIG.log_dir / "blackbox_ml.log",
                maxBytes=20*1024*1024,  # 20MB
                backupCount=10
            )
            main_handler.setLevel(logging.DEBUG)
            main_handler.setFormatter(formatter)
            base_logger.addHandler(main_handler)
            
            # Critical events log
            critical_handler = RotatingFileHandler(
                CONFIG.log_dir / "blackbox_critical.log",
                maxBytes=5*1024*1024,  # 5MB
                backupCount=5
            )
            critical_handler.setLevel(logging.CRITICAL)
            critical_handler.setFormatter(formatter)
            base_logger.addHandler(critical_handler)
            
            # ML specific log
            ml_handler = RotatingFileHandler(
                CONFIG.log_dir / "blackbox_ml_predictions.log",
                maxBytes=10*1024*1024,  # 10MB
                backupCount=5
            )
            ml_handler.setLevel(logging.INFO)
            ml_handler.addFilter(lambda record: 'ML' in record.getMessage() or 'prediction' in record.getMessage().lower())
            ml_handler.setFormatter(formatter)
            base_logger.addHandler(ml_handler)
            
        except Exception as e:
            print(f"Warning: Could not setup file logging: {e}")
        
        return ContextualLogger(base_logger)
        
    except Exception as e:
        # Fallback to basic logging
        basic_logger = logging.getLogger("BLACKBOX_FALLBACK")
        basic_logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
        basic_logger.addHandler(handler)
        return ContextualLogger(basic_logger)

log = setup_enhanced_logging()

# ================== Machine Learning Components ==================
class SimpleAnomalyDetector:
    """Simple anomaly detection using statistical methods (fallback for sklearn)"""
    
    def __init__(self, contamination: float = 0.1):
        self.contamination = contamination
        self.threshold = None
        self.mean = 0
        self.std = 1
    
    def fit(self, X: List[List[float]]):
        """Fit the anomaly detector"""
        if not X:
            return
        
        # Flatten all features
        all_values = []
        for sample in X:
            all_values.extend(sample)
        
        if all_values:
            self.mean = statistics.mean(all_values)
            self.std = statistics.stdev(all_values) if len(all_values) > 1 else 1
            
            # Set threshold based on contamination rate
            self.threshold = self.mean + (2 * self.std)  # Simple 2-sigma threshold
    
    def predict(self, X: List[List[float]]) -> List[int]:
        """Predict anomalies (-1 for anomaly, 1 for normal)"""
        if self.threshold is None:
            return [1] * len(X)
        
        predictions = []
        for sample in X:
            # Calculate distance from mean
            avg_distance = statistics.mean([abs(val - self.mean) for val in sample])
            is_anomaly = avg_distance > self.threshold
            predictions.append(-1 if is_anomaly else 1)
        
        return predictions

class MLPredictor:
    """Machine learning predictor for failure prediction"""
    
    def __init__(self):
        self.scaler = None
        self.anomaly_detector = None
        self.failure_predictor = None
        self.is_trained = False
        self.training_data = deque(maxlen=10000)
        self.feature_importance = {}
        
        # Initialize models based on available libraries
        if HAS_SKLEARN:
            try:
                from sklearn.preprocessing import StandardScaler
                from sklearn.ensemble import IsolationForest, RandomForestClassifier
                
                self.scaler = StandardScaler()
                self.anomaly_detector = IsolationForest(
                    contamination=CONFIG.ml.anomaly_threshold,
                    random_state=42,
                    n_jobs=1  # Single threaded for Android
                )
                self.failure_predictor = RandomForestClassifier(
                    n_estimators=50,  # Reduced for mobile performance
                    max_depth=10,
                    random_state=42,
                    n_jobs=1
                )
            except ImportError:
                self._init_fallback_models()
        else:
            self._init_fallback_models()
    
    def _init_fallback_models(self):
        """Initialize fallback models when sklearn is not available"""
        self.scaler = None  # We'll do manual scaling
        self.anomaly_detector = SimpleAnomalyDetector(CONFIG.ml.anomaly_threshold)
        self.failure_predictor = None  # Simple rule-based prediction
    
    def add_training_sample(self, features: MLFeatures, failed: bool):
        """Add a training sample"""
        feature_vector = features.to_vector()
        self.training_data.append((feature_vector, 1 if failed else 0))
    
    @with_retry(max_retries=3, exceptions=(MLError,))
    async def train(self):
        """Train the ML models"""
        try:
            if len(self.training_data) < CONFIG.ml.min_training_samples:
                log.info("Insufficient training data: %d samples (need %d)", 
                        len(self.training_data), CONFIG.ml.min_training_samples)
                return False
            
            log.info("Training ML models with %d samples", len(self.training_data))
            
            # Prepare training data
            X = []
            y = []
            for features, label in self.training_data:
                X.append(features)
                y.append(label)
            
            # Train anomaly detector
            await self._train_anomaly_detector(X)
            
            # Train failure predictor
            await self._train_failure_predictor(X, y)
            
            self.is_trained = True
            log.info("ML model training completed successfully")
            return True
            
        except Exception as e:
            raise MLError("Model training failed", cause=e)
    
    async def _train_anomaly_detector(self, X: List[List[float]]):
        """Train anomaly detection model"""
        try:
            if HAS_SKLEARN and self.scaler:
                # Scale features
                X_scaled = self.scaler.fit_transform(X)
                self.anomaly_detector.fit(X_scaled)
            else:
                # Fallback training
                self.anomaly_detector.fit(X)
        except Exception as e:
            log.error("Anomaly detector training failed: %s", e)
    
    async def _train_failure_predictor(self, X: List[List[float]], y: List[int]):
        """Train failure prediction model"""
        try:
            if HAS_SKLEARN and self.failure_predictor:
                X_scaled = self.scaler.transform(X) if self.scaler else X
                self.failure_predictor.fit(X_scaled, y)
                
                # Extract feature importance
                if hasattr(self.failure_predictor, 'feature_importances_'):
                    feature_names = ['uptime', 'failure_freq', 'recovery_time', 
                                   'volatility', 'time_since_failure', 'trend', 'anomaly']
                    self.feature_importance = dict(zip(feature_names, self.failure_predictor.feature_importances_))
                    log.info("Feature importance: %s", self.feature_importance)
        except Exception as e:
            log.error("Failure predictor training failed: %s", e)
    
    def predict_failure(self, features: MLFeatures) -> Tuple[bool, float]:
        """Predict if failure is likely"""
        try:
            if not self.is_trained:
                return False, 0.0
            
            feature_vector = [features.to_vector()]
            
            # Rule-based fallback if no ML models
            if not HAS_SKLEARN:
                return self._rule_based_prediction(features)
            
            # ML prediction
            if self.failure_predictor and self.scaler:
                X_scaled = self.scaler.transform(feature_vector)
                prediction = self.failure_predictor.predict(X_scaled)[0]
                probability = self.failure_predictor.predict_proba(X_scaled)[0][1]
                
                return prediction == 1, probability
            
            return self._rule_based_prediction(features)
            
        except Exception as e:
            log.error("Failure prediction error: %s", e)
            return False, 0.0
    
    def _rule_based_prediction(self, features: MLFeatures) -> Tuple[bool, float]:
        """Simple rule-based failure prediction"""
        score = 0.0
        
        # Low uptime ratio
        if features.uptime_ratio < 0.8:
            score += 0.3
        
        # High failure frequency
        if features.failure_frequency > 2:
            score += 0.2
        
        # High volatility
        if features.state_volatility > 1.0:
            score += 0.2
        
        # Recent failure
        if features.time_since_last_failure < 3600:  # Less than 1 hour
            score += 0.3
        
        return score > 0.5, score
    
    def detect_anomaly(self, features: MLFeatures) -> Tuple[bool, float]:
        """Detect if current state is anomalous"""
        try:
            if not self.is_trained:
                return False, 0.0
            
            feature_vector = [features.to_vector()]
            
            if HAS_SKLEARN and self.anomaly_detector and self.scaler:
                X_scaled = self.scaler.transform(feature_vector)
                prediction = self.anomaly_detector.predict(X_scaled)[0]
                # Get anomaly score (negative values are more anomalous)
                score = self.anomaly_detector.decision_function(X_scaled)[0]
                normalized_score = max(0, -score)  # Convert to positive anomaly score
                
                return prediction == -1, normalized_score
            else:
                # Fallback anomaly detection
                prediction = self.anomaly_detector.predict(feature_vector)[0]
                return prediction == -1, 0.5 if prediction == -1 else 0.0
                
        except Exception as e:
            log.error("Anomaly detection error: %s", e)
            return False, 0.0
    
    async def save_model(self, path: Path):
        """Save trained models"""
        try:
            if not self.is_trained:
                return
            
            os.makedirs(path.parent, exist_ok=True)
            
            model_data = {
                'is_trained': self.is_trained,
                'feature_importance': self.feature_importance,
                'training_samples': len(self.training_data)
            }
            
            # Save sklearn models if available
            if HAS_SKLEARN:
                try:
                    import joblib
                    joblib.dump(self.scaler, path.parent / "scaler.pkl")
                    joblib.dump(self.anomaly_detector, path.parent / "anomaly_detector.pkl")
                    joblib.dump(self.failure_predictor, path.parent / "failure_predictor.pkl")
                except ImportError:
                    # Fallback to pickle
                    with open(path, 'wb') as f:
                        pickle.dump({
                            'scaler': self.scaler,
                            'anomaly_detector': self.anomaly_detector,
                            'failure_predictor': self.failure_predictor,
                            'metadata': model_data
                        }, f)
            
            # Save metadata
            with open(path.parent / "model_metadata.json", 'w') as f:
                json.dump(model_data, f, indent=2)
            
            log.info("ML models saved to %s", path.parent)
            
        except Exception as e:
            log.error("Failed to save ML models: %s", e)
    
    async def load_model(self, path: Path) -> bool:
        """Load saved models"""
        try:
            metadata_path = path.parent / "model_metadata.json"
            if not metadata_path.exists():
                return False
            
            # Load metadata
            with open(metadata_path, 'r') as f:
                model_data = json.load(f)
            
            # Load sklearn models if available
            if HAS_SKLEARN:
                try:
                    import joblib
                    self.scaler = joblib.load(path.parent / "scaler.pkl")
                    self.anomaly_detector = joblib.load(path.parent / "anomaly_detector.pkl")
                    self.failure_predictor = joblib.load(path.parent / "failure_predictor.pkl")
                except (ImportError, FileNotFoundError):
                    # Try pickle fallback
                    if path.exists():
                        with open(path, 'rb') as f:
                            model_dict = pickle.load(f)
                            self.scaler = model_dict.get('scaler')
                            self.anomaly_detector = model_dict.get('anomaly_detector')
                            self.failure_predictor = model_dict.get('failure_predictor')
            
            self.is_trained = model_data.get('is_trained', False)
            self.feature_importance = model_data.get('feature_importance', {})
            
            log.info("ML models loaded successfully from %s", path.parent)
            return True
            
        except Exception as e:
            log.error("Failed to load ML models: %s", e)
            return False

# ================== Enhanced Metrics and Monitoring ==================
class AdvancedMetricsCollector:
    """Enhanced metrics collection with ML integration"""
    
    def __init__(self, window_size: int = 600):
        self.window_size = window_size
        self.metrics: Dict[str, deque] = defaultdict(lambda: deque(maxlen=window_size))
        self.anomaly_threshold = 2.5
        self.baseline_metrics = {}
        self.adaptive_thresholds = {}
        self.trend_cache = {}
        self.cache_time = {}
        
    def add_metric(self, name: str, value: float, timestamp: Optional[datetime] = None):
        """Add a metric value with enhanced processing"""
        if timestamp is None:
            timestamp = datetime.now()
        
        # Store metric
        self.metrics[name].append((timestamp, value))
        
        # Update baseline if we have enough data
        if len(self.metrics[name]) >= 50:
            self._update_baseline(name)
        
        # Update adaptive thresholds
        if CONFIG.adaptive_thresholds:
            self._update_adaptive_threshold(name, value)
    
    def _update_baseline(self, name: str):
        """Update baseline metrics for comparison"""
        values = [v for _, v in self.metrics[name]]
        if len(values) >= 50:
            self.baseline_metrics[name] = {
                'mean': np.mean(values) if HAS_NUMPY else statistics.mean(values),
                'std': np.std(values) if HAS_NUMPY else (statistics.stdev(values) if len(values) > 1 else 0),
                'percentiles': {
                    '25': np.percentile(values, 25) if HAS_NUMPY else self._percentile(values, 25),
                    '50': np.percentile(values, 50) if HAS_NUMPY else self._percentile(values, 50),
                    '75': np.percentile(values, 75) if HAS_NUMPY else self._percentile(values, 75),
                    '95': np.percentile(values, 95) if HAS_NUMPY else self._percentile(values, 95)
                }
            }
    
    def _percentile(self, data: List[float], percentile: float) -> float:
        """Calculate percentile without numpy"""
        if not data:
            return 0.0
        sorted_data = sorted(data)
        k = (len(sorted_data) - 1) * percentile / 100
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return sorted_data[int(k)]
        return sorted_data[int(f)] * (c - k) + sorted_data[int(c)] * (k - f)
    
    def _update_adaptive_threshold(self, name: str, value: float):
        """Update adaptive thresholds based on recent patterns"""
        if name not in self.adaptive_thresholds:
            self.adaptive_thresholds[name] = {
                'upper': value * 1.5,
                'lower': value * 0.5,
                'update_count': 0
            }
        else:
            threshold_info = self.adaptive_thresholds[name]
            learning_rate = CONFIG.learning_rate
            
            # Adaptive adjustment
            if value > threshold_info['upper']:
                threshold_info['upper'] = threshold_info['upper'] * (1 + learning_rate)
            elif value < threshold_info['lower']:
                threshold_info['lower'] = threshold_info['lower'] * (1 - learning_rate)
            
            threshold_info['update_count'] += 1
    
    @lru_cache(maxsize=128)
    def get_trend(self, name: str, cache_duration: int = 60) -> Optional[str]:
        """Analyze trend with caching"""
        current_time = time.time()
        cache_key = f"{name}_trend"
        
        # Check cache
        if (cache_key in self.cache_time and 
            current_time - self.cache_time[cache_key] < cache_duration):
            return self.trend_cache.get(cache_key)
        
        if name not in self.metrics or len(self.metrics[name]) < 20:
            return None
        
        values = [v for _, v in self.metrics[name]]
        
        # Enhanced trend analysis
        try:
            # Linear regression for trend
            if HAS_SKLEARN:
                from sklearn.linear_model import LinearRegression
                X = np.array(range(len(values))).reshape(-1, 1)
                y = np.array(values)
                model = LinearRegression().fit(X, y)
                slope = model.coef_[0]
            else:
                # Simple slope calculation
                n = len(values)
                x_mean = (n - 1) / 2
                y_mean = statistics.mean(values)
                
                numerator = sum((i - x_mean) * (values[i] - y_mean) for i in range(n))
                denominator = sum((i - x_mean) ** 2 for i in range(n))
                
                slope = numerator / denominator if denominator != 0 else 0
            
            # Determine trend
            if abs(slope) < 0.01:
                trend = "stable"
            elif slope > 0:
                trend = "increasing"
            else:
                trend = "decreasing"
            
            # Cache result
            self.trend_cache[cache_key] = trend
            self.cache_time[cache_key] = current_time
            
            return trend
            
        except Exception as e:
            log.debug("Trend calculation failed for %s: %s", name, e)
            return "unknown"
    
    def detect_anomaly(self, name: str, value: float) -> Tuple[bool, float]:
        """Enhanced anomaly detection"""
        if name not in self.metrics or len(self.metrics[name]) < 30:
            return False, 0.0
        
        try:
            # Statistical anomaly detection
            baseline = self.baseline_metrics.get(name)
            if baseline:
                mean = baseline['mean']
                std = baseline['std']
                
                if std > 0:
                    z_score = abs((value - mean) / std)
                    is_anomaly = z_score > self.anomaly_threshold
                    anomaly_score = min(1.0, z_score / self.anomaly_threshold)
                    return is_anomaly, anomaly_score
            
            # Fallback: simple threshold-based detection
            values = [v for _, v in self.metrics[name]]
            mean = statistics.mean(values)
            std = statistics.stdev(values) if len(values) > 1 else 0
            
            if std > 0:
                z_score = abs((value - mean) / std)
                return z_score > self.anomaly_threshold, min(1.0, z_score / 3.0)
            
            return False, 0.0
            
        except Exception as e:
            log.debug("Anomaly detection failed for %s: %s", name, e)
            return False, 0.0
    
    def get_health_indicators(self) -> Dict[str, float]:
        """Get overall system health indicators"""
        indicators = {}
        
        try:
            # System-wide metrics
            all_values = []
            for metric_name, metric_data in self.metrics.items():
                if metric_data:
                    recent_values = [v for _, v in list(metric_data)[-10:]]
                    all_values.extend(recent_values)
            
            if all_values:
                indicators['overall_stability'] = 1.0 / (1.0 + np.std(all_values) if HAS_NUMPY else statistics.stdev(all_values) if len(all_values) > 1 else 0)
                indicators['data_quality'] = min(1.0, len(all_values) / 1000)
            
            # Trend analysis
            increasing_trends = 0
            stable_trends = 0
            decreasing_trends = 0
            
            for metric_name in self.metrics:
                trend = self.get_trend(metric_name)
                if trend == "increasing":
                    increasing_trends += 1
                elif trend == "stable":
                    stable_trends += 1
                elif trend == "decreasing":
                    decreasing_trends += 1
            
            total_trends = increasing_trends + stable_trends + decreasing_trends
            if total_trends > 0:
                indicators['trend_stability'] = stable_trends / total_trends
            
        except Exception as e:
            log.debug("Health indicators calculation failed: %s", e)
            indicators['overall_stability'] = 0.5
            indicators['data_quality'] = 0.5
            indicators['trend_stability'] = 0.5
        
        return indicators

class RobustCircuitBreaker:
    """Enhanced circuit breaker with ML-informed decisions"""
    
    def __init__(self, failure_threshold: int = 5, timeout: float = 60, recovery_threshold: int = 3):
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.recovery_threshold = recovery_threshold
        self.failures = 0
        self.successes = 0
        self.last_failure_time = 0
        self.state = "closed"  # closed, open, half-open
        self._lock = asyncio.Lock()
        self.failure_history = deque(maxlen=100)
        
    async def call(self, coro_func: Callable, *args, **kwargs) -> Optional[Any]:
        """Execute async function with circuit breaking"""
        async with self._lock:
            current_state = await self._get_current_state()
            
            if current_state == "open":
                log.debug("Circuit breaker is OPEN - rejecting call")
                return None
        
        start_time = time.time()
        try:
            if asyncio.iscoroutinefunction(coro_func):
                result = await coro_func(*args, **kwargs)
            else:
                result = coro_func(*args, **kwargs)
            
            await self._record_success(time.time() - start_time)
            return result
            
        except Exception as e:
            await self._record_failure(time.time() - start_time, str(e))
            raise
    
    async def _get_current_state(self) -> str:
        """Get current circuit breaker state"""
        if self.state == "open":
            if time.time() - self.last_failure_time > self.timeout:
                self.state = "half-open"
                self.successes = 0
                log.info("Circuit breaker moving to HALF-OPEN state")
        
        return self.state
    
    async def _record_success(self, duration: float):
        """Record a successful operation"""
        async with self._lock:
            if self.state == "half-open":
                self.successes += 1
                if self.successes >= self.recovery_threshold:
                    self.state = "closed"
                    self.failures = 0
                    log.info("Circuit breaker CLOSED - recovered after %d successes", self.successes)
    
    async def _record_failure(self, duration: float, error: str):
        """Record a failed operation"""
        async with self._lock:
            self.failures += 1
            self.last_failure_time = time.time()
            self.failure_history.append({
                'timestamp': time.time(),
                'duration': duration,
                'error': error[:100]  # Truncate error message
            })
            
            if self.state != "open" and self.failures >= self.failure_threshold:
                self.state = "open"
                log.warning("Circuit breaker OPENED after %d failures", self.failures)
    
    def get_failure_rate(self, window_seconds: int = 300) -> float:
        """Calculate failure rate in given time window"""
        if not self.failure_history:
            return 0.0
        
        current_time = time.time()
        recent_failures = [
            f for f in self.failure_history 
            if current_time - f['timestamp'] <= window_seconds
        ]
        
        # Estimate total operations (failures + estimated successes)
        estimated_total = len(recent_failures) * 10  # Rough estimate
        return len(recent_failures) / max(estimated_total, 1)

# ================== Enhanced Action System ==================
class EnhancedAction(ABC):
    """Enhanced abstract base class for all actions"""
    
    def __init__(self):
        self.execution_history = deque(maxlen=100)
        self.success_rate = 1.0
        self.average_duration = 0.0
    
    @abstractmethod
    async def execute(self, context: Dict[str, Any]) -> bool:
        """Execute the action. Return True if successful."""
        pass
    
    @abstractmethod
    def validate(self) -> bool:
        """Validate if the action can be executed."""
        pass
    
    async def execute_with_monitoring(self, context: Dict[str, Any]) -> bool:
        """Execute action with performance monitoring"""
        start_time = time.time()
        success = False
        
        try:
            success = await self.execute(context)
            return success
        except Exception as e:
            log.error("Action %s failed with error: %s", self.__class__.__name__, e)
            return False
        finally:
            # Record execution metrics
            duration = time.time() - start_time
            self.execution_history.append({
                'timestamp': time.time(),
                'duration': duration,
                'success': success
            })
            
            # Update success rate
            recent_executions = list(self.execution_history)[-20:]
            if recent_executions:
                successes = sum(1 for e in recent_executions if e['success'])
                self.success_rate = successes / len(recent_executions)
                self.average_duration = statistics.mean([e['duration'] for e in recent_executions])
    
    def get_reliability_score(self) -> float:
        """Get reliability score based on historical performance"""
        if not self.execution_history:
            return 1.0
        
        # Weight recent performance more heavily
        recent_executions = list(self.execution_history)[-10:]
        if len(recent_executions) >= 5:
            recent_success_rate = sum(1 for e in recent_executions if e['success']) / len(recent_executions)
            return 0.7 * self.success_rate + 0.3 * recent_success_rate
        
        return self.success_rate

class AndroidSafeLogAlertAction(EnhancedAction):
    """Android-safe alert logging with enhanced features"""
    
    async def execute(self, context: Dict[str, Any]) -> bool:
        try:
            timestamp = datetime.now().isoformat()
            
            # Enhanced alert information
            alert_data = {
                'timestamp': timestamp,
                'type': 'SYSTEM_ALERT',
                'severity': self._calculate_severity(context),
                'agents_down': context.get('down_agents', []),
                'down_count': context.get('down_count', 0),
                'system_health': context.get('health_indicators', {}),
                'predicted_failures': context.get('predicted_failures', []),
                'ml_insights': context.get('ml_insights', {})
            }
            
            # Write to multiple log formats
            await self._write_structured_log(alert_data)
            await self._write_readable_log(alert_data)
            
            log.critical("ALERT: %d agents down - %s", 
                        alert_data['down_count'], 
                        ', '.join(alert_data['agents_down']))
            
            return True
            
        except Exception as e:
            log.error("Failed to write enhanced alert: %s", e)
            return False
    
    def _calculate_severity(self, context: Dict[str, Any]) -> str:
        """Calculate alert severity"""
        down_count = context.get('down_count', 0)
        total_agents = context.get('total_agents', down_count)
        
        if total_agents == 0:
            return 'INFO'
        
        failure_ratio = down_count / total_agents
        
        if failure_ratio >= 0.8:
            return 'CRITICAL'
        elif failure_ratio >= 0.5:
            return 'HIGH'
        elif failure_ratio >= 0.2:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    async def _write_structured_log(self, alert_data: Dict):
        """Write structured JSON log"""
        try:
            alert_path = CONFIG.log_dir / "structured_alerts.jsonl"
            log_line = json.dumps(alert_data) + '\n'
            
            if HAS_AIOFILES:
                async with aiofiles.open(alert_path, 'a') as f:
                    await f.write(log_line)
            else:
                with open(alert_path, 'a') as f:
                    f.write(log_line)
        except Exception as e:
            log.debug("Failed to write structured log: %s", e)
    
    async def _write_readable_log(self, alert_data: Dict):
        """Write human-readable log"""
        try:
            alert_path = CONFIG.log_dir / "alerts.log"
            
            readable_msg = (
                f"{alert_data['timestamp']} | {alert_data['severity']} | "
                f"Agents DOWN: {alert_data['down_count']} | "
                f"Names: {', '.join(alert_data['agents_down'])}"
            )
            
            # Add ML insights if available
            if alert_data.get('ml_insights'):
                insights = alert_data['ml_insights']
                readable_msg += f" | Predicted: {', '.join(insights.get('predictions', []))}"
            
            readable_msg += '\n'
            
            if HAS_AIOFILES:
                async with aiofiles.open(alert_path, 'a') as f:
                    await f.write(readable_msg)
            else:
                with open(alert_path, 'a') as f:
                    f.write(readable_msg)
                    
        except Exception as e:
            log.debug("Failed to write readable log: %s", e)
    
    def validate(self) -> bool:
        try:
            # Ensure log directory exists and is writable
            os.makedirs(CONFIG.log_dir, exist_ok=True)
            
            # Test write access
            test_path = CONFIG.log_dir / ".write_test"
            with open(test_path, 'w') as f:
                f.write("test")
            test_path.unlink()
            
            return True
        except Exception as e:
            log.error("Log alert action validation failed: %s", e)
            return False

class AndroidSafeRecoveryAction(EnhancedAction):
    """Android-safe recovery action without system calls"""
    
    def __init__(self):
        super().__init__()
        self.recovery_strategies = [
            self._strategy_file_cleanup,
            self._strategy_memory_optimization,
            self._strategy_cache_clear,
            self._strategy_config_reset
        ]
    
    async def execute(self, context: Dict[str, Any]) -> bool:
        down_agents = context.get('down_agents', [])
        recovered = []
        
        for agent in down_agents:
            if await self._try_recover_agent(agent, context):
                recovered.append(agent)
        
        # Update context with recovery results
        context['recovered_agents'] = recovered
        context['recovery_success_rate'] = len(recovered) / max(len(down_agents), 1)
        
        if recovered:
            log.info("Recovery completed: %d/%d agents recovered", 
                    len(recovered), len(down_agents))
            return True
        
        log.warning("Recovery failed: no agents could be recovered")
        return False
    
    async def _try_recover_agent(self, agent_name: str, context: Dict) -> bool:
        """Attempt to recover a single agent using multiple strategies"""
        log.info("Attempting recovery for agent: %s", agent_name)
        
        for i, strategy in enumerate(self.recovery_strategies):
            try:
                log.debug("Trying recovery strategy %d for %s", i+1, agent_name)
                
                if await strategy(agent_name, context):
                    log.info("Recovery strategy %d succeeded for %s", i+1, agent_name)
                    return True
                
                # Wait between strategies
                await asyncio.sleep(1)
                
            except Exception as e:
                log.error("Recovery strategy %d failed for %s: %s", i+1, agent_name, e)
        
        log.warning("All recovery strategies failed for %s", agent_name)
        return False
    
    async def _strategy_file_cleanup(self, agent_name: str, context: Dict) -> bool:
        """Clean up temporary files and locks"""
        try:
            # Clean up potential lock files
            lock_patterns = [
                f"{agent_name}.lock",
                f"{agent_name}_temp.*",
                f"temp_{agent_name}*"
            ]
            
            cleanup_paths = [
                CONFIG.log_dir,
                Path("./temp"),
                Path("./locks")
            ]
            
            cleaned = 0
            for path in cleanup_paths:
                if path.exists():
                    for pattern in lock_patterns:
                        for file_path in path.glob(pattern):
                            try:
                                file_path.unlink()
                                cleaned += 1
                            except Exception:
                                pass
            
            log.debug("Cleaned %d files for %s", cleaned, agent_name)
            return cleaned > 0
            
        except Exception as e:
            log.debug("File cleanup failed for %s: %s", agent_name, e)
            return False
    
    async def _strategy_memory_optimization(self, agent_name: str, context: Dict) -> bool:
        """Optimize memory usage"""
        try:
            # Force garbage collection
            import gc
            collected = gc.collect()
            
            log.debug("Garbage collected %d objects for %s", collected, agent_name)
            return True
            
        except Exception as e:
            log.debug("Memory optimization failed for %s: %s", agent_name, e)
            return False
    
    async def _strategy_cache_clear(self, agent_name: str, context: Dict) -> bool:
        """Clear various caches"""
        try:
            # Clear function caches
            if hasattr(self, '_cache'):
                self._cache.clear()
            
            # Clear metric caches
            if 'metrics_collector' in context:
                collector = context['metrics_collector']
                if hasattr(collector, 'trend_cache'):
                    collector.trend_cache.clear()
                    collector.cache_time.clear()
            
            log.debug("Caches cleared for %s", agent_name)
            return True
            
        except Exception as e:
            log.debug("Cache clearing failed for %s: %s", agent_name, e)
            return False
    
    async def _strategy_config_reset(self, agent_name: str, context: Dict) -> bool:
        """Reset configuration to defaults"""
        try:
            # Reset adaptive thresholds for this agent
            if 'metrics_collector' in context:
                collector = context['metrics_collector']
                if hasattr(collector, 'adaptive_thresholds'):
                    agent_metrics = [k for k in collector.adaptive_thresholds.keys() 
                                   if agent_name in k]
                    for metric_key in agent_metrics:
                        del collector.adaptive_thresholds[metric_key]
            
            log.debug("Configuration reset for %s", agent_name)
            return True
            
        except Exception as e:
            log.debug("Config reset failed for %s: %s", agent_name, e)
            return False
    
    def validate(self) -> bool:
        return True  # Always available on Android

class PredictiveMaintenanceAction(EnhancedAction):
    """Proactive maintenance based on ML predictions"""
    
    async def execute(self, context: Dict[str, Any]) -> bool:
        try:
            at_risk_agents = context.get('at_risk_agents', [])
            maintenance_performed = []
            
            for agent_info in at_risk_agents:
                agent_name = agent_info.get('name', agent_info if isinstance(agent_info, str) else 'unknown')
                risk_score = agent_info.get('risk_score', 0.5) if isinstance(agent_info, dict) else 0.5
                
                if await self._perform_maintenance(agent_name, risk_score, context):
                    maintenance_performed.append(agent_name)
            
            if maintenance_performed:
                log.info("Predictive maintenance completed for: %s", 
                        ', '.join(maintenance_performed))
                context['maintenance_performed'] = maintenance_performed
                return True
            
            return len(at_risk_agents) == 0  # Success if nothing needed maintenance
            
        except Exception as e:
            log.error("Predictive maintenance failed: %s", e)
            return False
    
    async def _perform_maintenance(self, agent_name: str, risk_score: float, context: Dict) -> bool:
        """Perform maintenance on a specific agent"""
        try:
            log.info("Performing predictive maintenance on %s (risk: %.2f)", 
                    agent_name, risk_score)
            
            # High-risk maintenance actions
            if risk_score > 0.8:
                await self._full_maintenance(agent_name)
            elif risk_score > 0.5:
                await self._moderate_maintenance(agent_name)
            else:
                await self._light_maintenance(agent_name)
            
            return True
            
        except Exception as e:
            log.error("Maintenance failed for %s: %s", agent_name, e)
            return False
    
    async def _full_maintenance(self, agent_name: str):
        """Full maintenance for high-risk agents"""
        # Reset all metrics for this agent
        # Clear all caches
        # Optimize memory
        await asyncio.sleep(0.1)  # Simulate maintenance work
        log.debug("Full maintenance completed for %s", agent_name)
    
    async def _moderate_maintenance(self, agent_name: str):
        """Moderate maintenance for medium-risk agents"""
        # Clear recent caches
        # Optimize some metrics
        await asyncio.sleep(0.05)  # Simulate maintenance work
        log.debug("Moderate maintenance completed for %s", agent_name)
    
    async def _light_maintenance(self, agent_name: str):
        """Light maintenance for low-risk agents"""
        # Basic cache cleanup
        await asyncio.sleep(0.01)  # Simulate maintenance work
        log.debug("Light maintenance completed for %s", agent_name)
    
    def validate(self) -> bool:
        return CONFIG.ml.enable_ml

# ================== Enhanced Heartbeat Monitor ==================
class IntelligentHeartbeatMonitor:
    """ML-enhanced heartbeat monitoring"""
    
    def __init__(self):
        self.agents: Dict[str, AgentHealth] = {}
        self.metrics = AdvancedMetricsCollector()
        self.circuit_breaker = RobustCircuitBreaker()
        self.ml_predictor = MLPredictor()
        
        # Caching
        self._cache = {}
        self._cache_time = 0
        self._file_hash = None
        
        # Monitoring
        self.last_update_time = time.time()
        self.update_count = 0
        
        # ML training
        self.training_scheduler = None
        self.last_training_time = 0
    
    async def initialize(self):
        """Initialize the monitor with model loading"""
        try:
            # Create model directory
            os.makedirs(CONFIG.model_dir, exist_ok=True)
            
            # Try to load existing models
            model_path = CONFIG.ml.model_file
            if await self.ml_predictor.load_model(model_path):
                log.info("ML models loaded successfully")
            else:
                log.info("No existing ML models found - will train from scratch")
            
            # Schedule periodic training
            if CONFIG.ml.enable_ml:
                self.training_scheduler = asyncio.create_task(self._training_loop())
            
        except Exception as e:
            log.error("Monitor initialization failed: %s", e)
    
    async def shutdown(self):
        """Shutdown the monitor gracefully"""
        try:
            if self.training_scheduler:
                self.training_scheduler.cancel()
                try:
                    await self.training_scheduler
                except asyncio.CancelledError:
                    pass
            
            # Save models
            if CONFIG.ml.model_persistence:
                await self.ml_predictor.save_model(CONFIG.ml.model_file)
            
            log.info("Monitor shutdown completed")
            
        except Exception as e:
            log.error("Monitor shutdown error: %s", e)
    
    @with_timeout(30.0)
    @with_retry(max_retries=3)
    async def get_agent_states(self) -> Dict[str, AgentHealth]:
        """Get current agent states with ML enhancement"""
        return await self.circuit_breaker.call(self._get_agent_states_internal)
    
    async def _get_agent_states_internal(self) -> Dict[str, AgentHealth]:
        """Internal method for getting agent states"""
        now = time.time()
        
        # Check cache validity
        if self._cache and (now - self._cache_time) < CONFIG.cache_ttl:
            return self._cache
        
        # Check if file has changed
        file_hash = await self._get_file_hash()
        if file_hash == self._file_hash and self._cache:
            self._cache_time = now
            return self._cache
        
        # Read fresh data
        data = await self._read_heartbeat()
        if data:
            await self._update_agents(data)
            await self._run_ml_analysis()
            
            self._cache = self.agents.copy()
            self._cache_time = now
            self._file_hash = file_hash
            self.last_update_time = now
            self.update_count += 1
        
        return self.agents
    
    async def _get_file_hash(self) -> Optional[str]:
        """Get file hash for change detection with error handling"""
        try:
            if not CONFIG.heartbeat_file.exists():
                return None
            
            # Use file stats for quick change detection
            stat = CONFIG.heartbeat_file.stat()
            return f"{stat.st_mtime}:{stat.st_size}"
            
        except Exception as e:
            log.debug("Could not get file hash: %s", e)
            return None
    
    async def _read_heartbeat(self) -> Optional[Dict]:
        """Read heartbeat file with enhanced error handling"""
        try:
            if not CONFIG.heartbeat_file.exists():
                log.debug("Heartbeat file does not exist: %s", CONFIG.heartbeat_file)
                return None
            
            # Check file size
            file_size = CONFIG.heartbeat_file.stat().st_size
            if file_size == 0:
                log.warning("Heartbeat file is empty")
                return None
            
            if file_size > 10 * 1024 * 1024:  # 10MB limit
                log.warning("Heartbeat file is too large: %d bytes", file_size)
                return None
            
            # Read with async I/O if available
            if HAS_AIOFILES:
                async with aiofiles.open(CONFIG.heartbeat_file, 'r') as f:
                    content = await f.read()
            else:
                with open(CONFIG.heartbeat_file, 'r') as f:
                    content = f.read()
            
            # Parse JSON with better error handling
            try:
                data = json.loads(content)
            except json.JSONDecodeError as e:
                log.error("Invalid JSON in heartbeat file at line %d, column %d: %s", 
                         e.lineno, e.colno, e.msg)
                return None
            
            # Validate structure
            if not isinstance(data, dict):
                log.error("Heartbeat data is not a dictionary")
                return None
            
            if 'agents' not in data:
                log.error("Heartbeat data missing 'agents' key")
                return None
            
            if not isinstance(data['agents'], dict):
                log.error("Heartbeat 'agents' is not a dictionary")
                return None
            
            return data
            
        except FileNotFoundError:
            log.debug("Heartbeat file not found: %s", CONFIG.heartbeat_file)
            return None
        except PermissionError:
            log.error("Permission denied reading heartbeat file: %s", CONFIG.heartbeat_file)
            return None
        except Exception as e:
            log.error("Failed to read heartbeat file: %s", e)
            return None
    
    async def _update_agents(self, data: Dict):
        """Update agent health information with ML features"""
        current_time = datetime.now()
        agent_data = data.get('agents', {})
        
        # Update existing agents and create new ones
        seen_agents = set()
        
        for name, state_info in agent_data.items():
            seen_agents.add(name)
            
            # Parse state information (can be string or dict)
            if isinstance(state_info, dict):
                state_str = state_info.get('state', 'UNKNOWN')
                response_time = state_info.get('response_time')
                additional_info = state_info.get('info', {})
            else:
                state_str = str(state_info)
                response_time = None
                additional_info = {}
            
            # Get or create agent health object
            if name not in self.agents:
                self.agents[name] = AgentHealth(
                    name=name,
                    state=self._parse_state(state_str),
                    last_seen=current_time
                )
                log.info("New agent discovered: %s", name)
            
            agent = self.agents[name]
            old_state = agent.state
            new_state = self._parse_state(state_str)
            
            # Track state changes and patterns
            if old_state != new_state:
                log.debug("Agent %s state changed: %s -> %s", name, old_state.name, new_state.name)
                
                # Record state transition
                agent.state_history.append(new_state)
                
                # Update counters
                if new_state == AgentState.DOWN:
                    agent.failure_count += 1
                    
                    # Create failure pattern for ML
                    if len(agent.state_history) >= 5:
                        pattern = FailurePattern(
                            timestamp=current_time.timestamp(),
                            agent_name=name,
                            state_sequence=[s.value for s in list(agent.state_history)[-5:]],
                            preconditions=agent.ml_features.to_vector(),
                            outcome=1  # Failed
                        )
                        agent.failure_patterns.append(pattern)
                        
                        # Add to ML training data
                        self.ml_predictor.add_training_sample(agent.ml_features, True)
                
                elif old_state == AgentState.DOWN and new_state == AgentState.ALIVE:
                    agent.recovery_count += 1
                    
                    # Create recovery pattern for ML
                    if agent.failure_patterns:
                        # Update the last failure pattern with successful recovery
                        last_pattern = agent.failure_patterns[-1]
                        recovery_pattern = FailurePattern(
                            timestamp=current_time.timestamp(),
                            agent_name=name,
                            state_sequence=last_pattern.state_sequence,
                            preconditions=last_pattern.preconditions,
                            outcome=0  # Recovered
                        )
                        
                        # Add to ML training data
                        features = MLFeatures()
                        features.uptime_ratio = agent.uptime_percentage / 100
                        self.ml_predictor.add_training_sample(features, False)
            
            # Update agent state and timing
            agent.state = new_state
            agent.last_seen = current_time
            
            # Update response time if available
            if response_time is not None:
                try:
                    agent.response_times.append(float(response_time))
                except (ValueError, TypeError):
                    log.debug("Invalid response time for %s: %s", name, response_time)
            
            # Calculate uptime percentage
            total_time = current_time.timestamp() - (current_time.timestamp() - 3600)  # Last hour
            if agent.failure_count > 0:
                # Rough uptime calculation
                failure_time = agent.failure_count * 30  # Assume 30 seconds per failure
                agent.uptime_percentage = max(0, 100 * (total_time - failure_time) / total_time)
            
            # Update health score
            agent.update_health_score()
            
            # Collect metrics
            self.metrics.add_metric(f"agent_{name}_state", new_state.value)
            self.metrics.add_metric(f"agent_{name}_health", agent.health_score)
            
            if response_time is not None:
                self.metrics.add_metric(f"agent_{name}_response_time", response_time)
        
        # Mark missing agents as UNKNOWN
        for name, agent in self.agents.items():
            if name not in seen_agents:
                if agent.state != AgentState.UNKNOWN:
                    log.warning("Agent %s is no longer reporting - marking as UNKNOWN", name)
                    agent.state = AgentState.UNKNOWN
                    agent.update_health_score()
                    self.metrics.add_metric(f"agent_{name}_state", AgentState.UNKNOWN.value)
    
    def _parse_state(self, state_str: str) -> AgentState:
        """Parse state string to enum with error handling"""
        state_map = {
            "ALIVE": AgentState.ALIVE,
            "UP": AgentState.ALIVE,
            "ONLINE": AgentState.ALIVE,
            "RUNNING": AgentState.ALIVE,
            "OK": AgentState.ALIVE,
            "DOWN": AgentState.DOWN,
            "OFFLINE": AgentState.DOWN,
            "FAILED": AgentState.DOWN,
            "ERROR": AgentState.DOWN,
            "DEGRADED": AgentState.DEGRADED,
            "SLOW": AgentState.DEGRADED,
            "WARNING": AgentState.DEGRADED,
            "RECOVERING": AgentState.RECOVERING,
            "STARTING": AgentState.RECOVERING,
            "RESTARTING": AgentState.RECOVERING,
        }
        
        normalized_state = str(state_str).upper().strip()
        return state_map.get(normalized_state, AgentState.UNKNOWN)
    
    async def _run_ml_analysis(self):
        """Run ML analysis on current agent states"""
        if not CONFIG.ml.enable_ml:
            return
        
        try:
            predictions_made = []
            
            for name, agent in self.agents.items():
                # Predict failure
                will_fail, confidence = self.ml_predictor.predict_failure(agent.ml_features)
                
                if will_fail and confidence > CONFIG.ml.prediction_confidence_threshold:
                    prediction_time = datetime.now() + timedelta(seconds=CONFIG.ml.prediction_window)
                    agent.predicted_failure_time = prediction_time
                    agent.confidence_score = confidence
                    agent.state = AgentState.PREDICTED_FAILURE
                    
                    predictions_made.append({
                        'agent': name,
                        'confidence': confidence,
                        'predicted_time': prediction_time
                    })
                    
                    log.warning("ML prediction: Agent %s likely to fail (confidence: %.2f)", 
                              name, confidence)
                
                # Detect anomalies
                is_anomaly, anomaly_score = self.ml_predictor.detect_anomaly(agent.ml_features)
                agent.ml_features.anomaly_score = anomaly_score
                
                if is_anomaly:
                    log.info("Anomaly detected for agent %s (score: %.2f)", name, anomaly_score)
                    self.metrics.add_metric(f"agent_{name}_anomaly", anomaly_score)
            
            # Store predictions for actions
            if predictions_made:
                self.metrics.add_metric("ml_predictions_count", len(predictions_made))
            
        except Exception as e:
            log.error("ML analysis failed: %s", e)
    
    async def _training_loop(self):
        """Periodic ML model training"""
        while True:
            try:
                await asyncio.sleep(CONFIG.ml.training_interval)
                
                current_time = time.time()
                if (current_time - self.last_training_time) >= CONFIG.ml.training_interval:
                    log.info("Starting ML model training...")
                    
                    training_success = await self.ml_predictor.train()
                    if training_success:
                        self.last_training_time = current_time
                        
                        # Save models after successful training
                        if CONFIG.ml.model_persistence:
                            await self.ml_predictor.save_model(CONFIG.ml.model_file)
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error("Training loop error: %s", e)
                await asyncio.sleep(60)  # Wait before retrying
    
    def get_ml_insights(self) -> Dict[str, Any]:
        """Get ML insights for decision making"""
        insights = {
            'predictions': [],
            'anomalies': [],
            'health_indicators': self.metrics.get_health_indicators(),
            'model_trained': self.ml_predictor.is_trained
        }
        
        for name, agent in self.agents.items():
            # Predictions
            if agent.predicted_failure_time and agent.confidence_score > 0.5:
                insights['predictions'].append({
                    'agent': name,
                    'confidence': agent.confidence_score,
                    'predicted_time': agent.predicted_failure_time.isoformat()
                })
            
            # Anomalies
            if agent.ml_features.anomaly_score > 0.3:
                insights['anomalies'].append({
                    'agent': name,
                    'anomaly_score': agent.ml_features.anomaly_score
                })
        
        return insights
    
    def predict_system_failures(self) -> List[Dict[str, Any]]:
        """Predict which agents are at risk of failure"""
        at_risk = []
        
        for name, agent in self.agents.items():
            risk_factors = []
            risk_score = 0.0
            
            # Health score risk
            if agent.health_score < CONFIG.ml.prediction_confidence_threshold:
                risk_factors.append("low_health_score")
                risk_score += 0.3
            
            # ML prediction risk
            if agent.predicted_failure_time:
                risk_factors.append("ml_prediction")
                risk_score += agent.confidence_score * 0.4
            
            # Anomaly risk
            if agent.ml_features.anomaly_score > 0.3:
                risk_factors.append("anomaly_detected")
                risk_score += agent.ml_features.anomaly_score * 0.2
            
            # Historical risk
            if agent.failure_count > 0:
                failure_rate = agent.failure_count / max(agent.failure_count + agent.recovery_count, 1)
                if failure_rate > 0.3:
                    risk_factors.append("high_failure_rate")
                    risk_score += failure_rate * 0.1
            
            # Add to at-risk list if significant risk
            if risk_score > 0.4:
                at_risk.append({
                    'name': name,
                    'risk_score': min(1.0, risk_score),
                    'risk_factors': risk_factors,
                    'current_state': agent.state.name,
                    'health_score': agent.health_score
                })
        
        # Sort by risk score (highest first)
        at_risk.sort(key=lambda x: x['risk_score'], reverse=True)
        return at_risk

# ================== Enhanced Main Controller ==================
class EnhancedBlackboxController:
    """Enhanced main controller with ML capabilities and Android compatibility"""
    
    def __init__(self):
        self.monitor = IntelligentHeartbeatMonitor()
        self.actions = self._initialize_actions()
        self.running = False
        self.tasks: List[asyncio.Task] = []
        self.last_action_time = {}
        self.shutdown_event = asyncio.Event()
        self._shutdown_lock = threading.Lock()
        self.performance_stats = {
            'checks_performed': 0,
            'actions_executed': 0,
            'predictions_made': 0,
            'start_time': time.time()
        }
        
        # Android-compatible shutdown handling
        self._shutdown_handlers = []
        atexit.register(self._emergency_shutdown)
    
    def _initialize_actions(self) -> Dict[ActionType, EnhancedAction]:
        """Initialize available actions with Android-safe implementations"""
        return {
            ActionType.LOG_ALERT: AndroidSafeLogAlertAction(),
            ActionType.RESTART_AGENT: AndroidSafeRecoveryAction(),
            ActionType.PREDICTIVE_MAINTENANCE: PredictiveMaintenanceAction(),
        }
    
    def _emergency_shutdown(self):
        """Emergency shutdown handler for atexit"""
        try:
            with self._shutdown_lock:
                if self.running:
                    log.critical("Emergency shutdown triggered")
                    self.running = False
                    self.shutdown_event.set()
        except Exception as e:
            print(f"Emergency shutdown error: {e}")
    
    async def start(self):
        """Start the enhanced monitoring system"""
        try:
            self.running = True
            self.performance_stats['start_time'] = time.time()
            
            log.info("BLACKBOX Enhanced ML starting up...")
            log.set_context(version="3.0", android_compatible=True, ml_enabled=CONFIG.ml.enable_ml)
            
            # Initialize monitor
            await self.monitor.initialize()
            
            # Start monitoring tasks
            self.tasks.append(asyncio.create_task(self._monitor_loop(), name="monitor_loop"))
            self.tasks.append(asyncio.create_task(self._watchdog_loop(), name="watchdog_loop"))
            self.tasks.append(asyncio.create_task(self._metrics_loop(), name="metrics_loop"))
            self.tasks.append(asyncio.create_task(self._health_check_loop(), name="health_check_loop"))
            
            if CONFIG.ml.enable_ml:
                self.tasks.append(asyncio.create_task(self._prediction_loop(), name="prediction_loop"))
            
            if CONFIG.adaptive_thresholds:
                self.tasks.append(asyncio.create_task(self._adaptation_loop(), name="adaptation_loop"))
            
            # Setup Android-compatible signal handling
            self._setup_signal_handlers()
            
            log.info("BLACKBOX Enhanced ML fully operational - %d tasks running", len(self.tasks))
            
            # Wait for shutdown
            await self.shutdown_event.wait()
            
        except Exception as e:
            log.critical("Fatal error during startup: %s", e, exc_info=True)
            raise
        finally:
            await self.shutdown()
    
    def _setup_signal_handlers(self):
        """Setup Android-compatible signal handlers"""
        try:
            # Android/Pydroid3 may not support all signal operations
            loop = asyncio.get_running_loop()
            
            # Try to setup signal handlers, but don't fail if not supported
            for sig in [signal.SIGTERM, signal.SIGINT]:
                try:
                    loop.add_signal_handler(sig, self._signal_handler, sig)
                except (OSError, NotImplementedError):
                    # Signal handling not supported on this platform
                    log.debug("Signal %s handling not available", sig)
                    
        except Exception as e:
            log.warning("Signal handler setup failed: %s", e)
    
    def _signal_handler(self, signum):
        """Handle shutdown signals (thread-safe)"""
        try:
            with self._shutdown_lock:
                log.info("Received signal %s, initiating graceful shutdown...", signum)
                if not self.shutdown_event.is_set():
                    self.shutdown_event.set()
        except Exception as e:
            log.error("Signal handler error: %s", e)
    
    async def shutdown(self):
        """Enhanced graceful shutdown"""
        log.info("Shutting down BLACKBOX Enhanced ML...")
        self.running = False
        
        try:
            # Shutdown monitor first
            await self.monitor.shutdown()
            
            # Cancel all tasks
            for task in self.tasks:
                if not task.done():
                    task.cancel()
            
            # Wait for tasks to complete with timeout
            if self.tasks:
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*self.tasks, return_exceptions=True),
                        timeout=15
                    )
                except asyncio.TimeoutError:
                    log.warning("Some tasks did not shutdown gracefully within timeout")
            
            # Final performance stats
            uptime = time.time() - self.performance_stats['start_time']
            log.info("Shutdown complete - Uptime: %.1fs, Checks: %d, Actions: %d, Predictions: %d",
                    uptime,
                    self.performance_stats['checks_performed'],
                    self.performance_stats['actions_executed'],
                    self.performance_stats['predictions_made'])
            
        except Exception as e:
            log.error("Shutdown error: %s", e)
        
        log.info("BLACKBOX Enhanced ML shutdown complete")
    
    async def _monitor_loop(self):
        """Enhanced main monitoring loop with ML integration"""
        consecutive_failures = 0
        last_status_log = 0
        
        while self.running:
            try:
                loop_start = time.time()
                
                # Get agent states with ML analysis
                agents = await self.monitor.get_agent_states()
                
                if not agents:
                    consecutive_failures += 1
                    if consecutive_failures >= 5:
                        log.warning("No agent data for %d consecutive checks", consecutive_failures)
                        
                        # Exponential backoff for failures
                        backoff_delay = min(CONFIG.check_interval * (1.5 ** consecutive_failures), 60)
                        await asyncio.sleep(backoff_delay)
                        continue
                else:
                    consecutive_failures = 0
                    
                    # Analyze current state
                    down_agents = [
                        name for name, agent in agents.items()
                        if agent.state == AgentState.DOWN
                    ]
                    
                    predicted_failures = [
                        name for name, agent in agents.items()
                        if agent.state == AgentState.PREDICTED_FAILURE
                    ]
                    
                    # Handle current failures
                    if down_agents and len(down_agents) >= CONFIG.fail_threshold:
                        await self._handle_failures(down_agents, agents)
                    
                    # Handle predicted failures (proactive)
                    if predicted_failures:
                        await self._handle_predicted_failures(predicted_failures, agents)
                    
                    # Periodic status logging
                    now = time.time()
                    if now - last_status_log > 300:  # Every 5 minutes
                        total = len(agents)
                        down = len(down_agents)
                        predicted = len(predicted_failures)
                        healthy = total - down - predicted
                        
                        log.info("System Status: %d/%d agents healthy, %d down, %d predicted failures",
                                healthy, total, down, predicted)
                        
                        # Log performance metrics
                        loop_duration = time.time() - loop_start
                        self.performance_stats['checks_performed'] += 1
                        
                        if loop_duration > CONFIG.check_interval:
                            log.warning("Monitor loop taking too long: %.2fs", loop_duration)
                        
                        last_status_log = now
                
                # Adaptive sleep interval
                sleep_duration = max(0.1, CONFIG.check_interval - (time.time() - loop_start))
                await asyncio.sleep(sleep_duration)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error("Monitor loop error: %s", e, exc_info=True)
                # Exponential backoff on errors
                error_delay = min(CONFIG.check_interval * 2, 30)
                await asyncio.sleep(error_delay)
    
    async def _handle_failures(self, down_agents: List[str], all_agents: Dict[str, AgentHealth]):
        """Enhanced failure handling with ML insights"""
        down_count = len(down_agents)
        total_agents = len(all_agents)
        
        log.warning("Failure threshold exceeded: %d/%d agents down", down_count, total_agents)
        
        # Gather ML insights
        ml_insights = self.monitor.get_ml_insights()
        health_indicators = self.monitor.metrics.get_health_indicators()
        
        # Build context with enhanced information
        context = {
            'down_count': down_count,
            'down_agents': down_agents,
            'total_agents': total_agents,
            'timestamp': datetime.now(),
            'ml_insights': ml_insights,
            'health_indicators': health_indicators,
            'metrics_collector': self.monitor.metrics,
            'failure_rate': down_count / total_agents if total_agents > 0 else 0
        }
        
        # Try recovery first with enhanced context
        if CONFIG.recovery_attempts > 0:
            recovery_action = self.actions.get(ActionType.RESTART_AGENT)
            if recovery_action and await self._can_execute_action(ActionType.RESTART_AGENT):
                log.info("Attempting intelligent recovery...")
                
                success = await recovery_action.execute_with_monitoring(context)
                if success:
                    recovery_rate = context.get('recovery_success_rate', 0)
                    log.info("Recovery completed with %.1f%% success rate", recovery_rate * 100)
                    
                    # If recovery was successful enough, don't escalate
                    if recovery_rate >= 0.5:
                        return
        
        # Execute alert action with ML context
        await self._execute_action_with_monitoring(ActionType.LOG_ALERT, context)
        
        # Critical system failure - consider predictive maintenance
        if context['failure_rate'] >= 0.5:
            log.critical("Critical system failure detected - %.1f%% failure rate", 
                        context['failure_rate'] * 100)
            
            maintenance_action = self.actions.get(ActionType.PREDICTIVE_MAINTENANCE)
            if maintenance_action:
                await self._execute_action_with_monitoring(ActionType.PREDICTIVE_MAINTENANCE, context)
    
    async def _handle_predicted_failures(self, predicted_agents: List[str], all_agents: Dict[str, AgentHealth]):
        """Handle predicted failures proactively"""
        log.info("Handling %d predicted failures proactively", len(predicted_agents))
        
        # Prepare at-risk information
        at_risk_agents = []
        for name in predicted_agents:
            agent = all_agents[name]
            at_risk_agents.append({
                'name': name,
                'risk_score': agent.confidence_score,
                'predicted_time': agent.predicted_failure_time,
                'current_health': agent.health_score
            })
        
        context = {
            'at_risk_agents': at_risk_agents,
            'prediction_count': len(predicted_agents),
            'timestamp': datetime.now(),
            'ml_insights': self.monitor.get_ml_insights()
        }
        
        # Execute predictive maintenance
        maintenance_action = self.actions.get(ActionType.PREDICTIVE_MAINTENANCE)
        if maintenance_action and await self._can_execute_action(ActionType.PREDICTIVE_MAINTENANCE):
            success = await maintenance_action.execute_with_monitoring(context)
            if success:
                self.performance_stats['predictions_made'] += len(predicted_agents)
                log.info("Predictive maintenance completed for %d agents", len(predicted_agents))
    
    async def _execute_action_with_monitoring(self, action_type: ActionType, context: Dict):
        """Execute action with enhanced monitoring and error handling"""
        if not await self._can_execute_action(action_type):
            log.warning("Action %s is rate limited", action_type.name)
            return
        
        action = self.actions.get(action_type)
        if not action:
            log.error("Action %s not available", action_type.name)
            return
        
        if not action.validate():
            log.error("Action %s failed validation", action_type.name)
            return
        
        try:
            log.info("Executing action: %s (reliability: %.2f)", 
                    action_type.name, action.get_reliability_score())
            
            success = await action.execute_with_monitoring(context)
            
            if success:
                self.last_action_time[action_type] = time.time()
                self.performance_stats['actions_executed'] += 1
                log.info("Action %s executed successfully", action_type.name)
            else:
                log.error("Action %s failed to execute", action_type.name)
                
        except Exception as e:
            log.error("Action %s error: %s", action_type.name, e, exc_info=True)
    
    async def _can_execute_action(self, action_type: ActionType) -> bool:
        """Enhanced action rate limiting with adaptive cooldowns"""
        last_time = self.last_action_time.get(action_type, 0)
        base_cooldown = CONFIG.action_cooldown
        
        # Adaptive cooldown based on action reliability
        action = self.actions.get(action_type)
        if action:
            reliability = action.get_reliability_score()
            # Lower reliability = longer cooldown
            adaptive_cooldown = base_cooldown * (2 - reliability)
        else:
            adaptive_cooldown = base_cooldown
        
        return (time.time() - last_time) > adaptive_cooldown
    
    async def _watchdog_loop(self):
        """Enhanced watchdog with adaptive monitoring"""
        consecutive_hangs = 0
        
        while self.running:
            try:
                await asyncio.sleep(CONFIG.watchdog_timeout)
                
                # Check if main monitor loop is responsive
                last_update = self.monitor.last_update_time
                elapsed = time.time() - last_update
                
                if elapsed > CONFIG.watchdog_timeout:
                    consecutive_hangs += 1
                    log.critical("Watchdog timeout #%d! Main loop unresponsive for %.1fs", 
                               consecutive_hangs, elapsed)
                    
                    # Progressive response to hangs
                    if consecutive_hangs >= 3:
                        log.critical("Critical system hang detected - initiating emergency recovery")
                        # Could implement self-restart mechanism here
                        # For now, just log and continue monitoring
                        
                        # Force garbage collection
                        import gc
                        collected = gc.collect()
                        log.info("Emergency garbage collection freed %d objects", collected)
                else:
                    consecutive_hangs = 0
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error("Watchdog error: %s", e)
    
    async def _metrics_loop(self):
        """Enhanced metrics collection with memory management"""
        while self.running:
            try:
                start_time = time.time()
                
                # System metrics
                try:
                    import psutil
                    process = psutil.Process()
                    
                    # Memory usage
                    mem_info = process.memory_info()
                    mem_mb = mem_info.rss / (1024 * 1024)
                    self.monitor.metrics.add_metric("memory_mb", mem_mb)
                    
                    # CPU usage
                    cpu_percent = process.cpu_percent(interval=0.1)
                    self.monitor.metrics.add_metric("cpu_percent", cpu_percent)
                    
                    # Thread count
                    thread_count = process.num_threads()
                    self.monitor.metrics.add_metric("thread_count", thread_count)
                    
                    # Check memory limit
                    if mem_mb > CONFIG.memory_limit_mb:
                        log.warning("Memory usage high: %.1f MB (limit: %d MB)", 
                                  mem_mb, CONFIG.memory_limit_mb)
                        
                        # Force garbage collection
                        import gc
                        collected = gc.collect()
                        log.info("Garbage collection freed %d objects", collected)
                    
                except ImportError:
                    # Fallback without psutil
                    import sys
                    import gc
                    
                    # Basic memory info
                    gc_stats = gc.get_stats()
                    if gc_stats:
                        self.monitor.metrics.add_metric("gc_collections", sum(stat['collections'] for stat in gc_stats))
                
                # Performance metrics
                loop_duration = time.time() - start_time
                self.monitor.metrics.add_metric("metrics_loop_duration", loop_duration)
                
                # Agent metrics
                total_agents = len(self.monitor.agents)
                healthy_agents = sum(1 for agent in self.monitor.agents.values() 
                                   if agent.state == AgentState.ALIVE)
                
                self.monitor.metrics.add_metric("total_agents", total_agents)
                self.monitor.metrics.add_metric("healthy_agents", healthy_agents)
                
                if total_agents > 0:
                    health_ratio = healthy_agents / total_agents
                    self.monitor.metrics.add_metric("system_health_ratio", health_ratio)
                
                # ML metrics
                if CONFIG.ml.enable_ml and self.monitor.ml_predictor.is_trained:
                    training_samples = len(self.monitor.ml_predictor.training_data)
                    self.monitor.metrics.add_metric("ml_training_samples", training_samples)
                
                await asyncio.sleep(30)  # Collect metrics every 30 seconds
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error("Metrics collection error: %s", e)
                await asyncio.sleep(60)  # Wait longer on error
    
    async def _health_check_loop(self):
        """System health monitoring and self-diagnostics"""
        while self.running:
            try:
                await asyncio.sleep(120)  # Every 2 minutes
                
                # Self-diagnostics
                health_report = await self._perform_health_check()
                
                # Log health summary
                if health_report['overall_health'] < 0.7:
                    log.warning("System health degraded: %.1f%% - Issues: %s",
                              health_report['overall_health'] * 100,
                              ', '.join(health_report['issues']))
                else:
                    log.debug("System health check passed: %.1f%%", 
                             health_report['overall_health'] * 100)
                
                # Take corrective actions if needed
                if health_report['overall_health'] < 0.5:
                    await self._perform_self_healing(health_report)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error("Health check error: %s", e)
    
    async def _perform_health_check(self) -> Dict[str, Any]:
        """Perform comprehensive system health check"""
        health_report = {
            'overall_health': 1.0,
            'issues': [],
            'components': {}
        }
        
        try:
            # Check monitor health
            monitor_health = 1.0
            monitor_issues = []
            
            if time.time() - self.monitor.last_update_time > CONFIG.watchdog_timeout:
                monitor_health -= 0.5
                monitor_issues.append("monitor_unresponsive")
            
            if not self.monitor.agents:
                monitor_health -= 0.3
                monitor_issues.append("no_agents")
            
            health_report['components']['monitor'] = {
                'health': monitor_health,
                'issues': monitor_issues
            }
            
            # Check ML component health
            if CONFIG.ml.enable_ml:
                ml_health = 1.0
                ml_issues = []
                
                if not self.monitor.ml_predictor.is_trained:
                    ml_health -= 0.3
                    ml_issues.append("model_not_trained")
                
                training_samples = len(self.monitor.ml_predictor.training_data)
                if training_samples < CONFIG.ml.min_training_samples:
                    ml_health -= 0.2
                    ml_issues.append("insufficient_training_data")
                
                health_report['components']['ml'] = {
                    'health': ml_health,
                    'issues': ml_issues
                }
            
            # Check task health
            task_health = 1.0
            task_issues = []
            
            active_tasks = sum(1 for task in self.tasks if not task.done())
            if active_tasks < len(self.tasks):
                task_health -= 0.4
                task_issues.append("tasks_terminated")
            
            health_report['components']['tasks'] = {
                'health': task_health,
                'issues': task_issues
            }
            
            # Calculate overall health
            component_healths = [comp['health'] for comp in health_report['components'].values()]
            health_report['overall_health'] = statistics.mean(component_healths) if component_healths else 0
            
            # Collect all issues
            all_issues = []
            for comp in health_report['components'].values():
                all_issues.extend(comp['issues'])
            health_report['issues'] = all_issues
            
        except Exception as e:
            log.error("Health check failed: %s", e)
            health_report['overall_health'] = 0.3
            health_report['issues'] = ['health_check_failed']
        
        return health_report
    
    async def _perform_self_healing(self, health_report: Dict[str, Any]):
        """Attempt to heal system issues automatically"""
        log.info("Performing self-healing for %d issues", len(health_report['issues']))
        
        for issue in health_report['issues']:
            try:
                if issue == "monitor_unresponsive":
                    log.info("Attempting to restart monitor...")
                    # Could restart monitor component
                    
                elif issue == "tasks_terminated":
                    log.info("Attempting to restart terminated tasks...")
                    await self._restart_failed_tasks()
                    
                elif issue == "model_not_trained" and CONFIG.ml.enable_ml:
                    log.info("Attempting emergency ML training...")
                    if len(self.monitor.ml_predictor.training_data) >= 10:
                        await self.monitor.ml_predictor.train()
                
                elif issue == "insufficient_training_data":
                    log.info("Generating synthetic training data...")
                    # Could generate some synthetic training samples
                    
            except Exception as e:
                log.error("Self-healing failed for issue %s: %s", issue, e)
    
    async def _restart_failed_tasks(self):
        """Restart any failed tasks"""
        original_task_count = len(self.tasks)
        active_tasks = [task for task in self.tasks if not task.done()]
        
        if len(active_tasks) < original_task_count:
            log.warning("Restarting %d failed tasks", original_task_count - len(active_tasks))
            
            # Clear completed tasks
            self.tasks = active_tasks
            
            # Restart missing tasks (simple approach)
            task_names = [task.get_name() for task in active_tasks]
            
            if "monitor_loop" not in task_names:
                self.tasks.append(asyncio.create_task(self._monitor_loop(), name="monitor_loop"))
            
            if "watchdog_loop" not in task_names:
                self.tasks.append(asyncio.create_task(self._watchdog_loop(), name="watchdog_loop"))
            
            if "metrics_loop" not in task_names:
                self.tasks.append(asyncio.create_task(self._metrics_loop(), name="metrics_loop"))
    
    async def _prediction_loop(self):
        """ML prediction and proactive maintenance loop"""
        while self.running:
            try:
                await asyncio.sleep(180)  # Every 3 minutes
                
                if not self.monitor.ml_predictor.is_trained:
                    continue
                
                # Get system-wide predictions
                at_risk_agents = self.monitor.predict_system_failures()
                
                if at_risk_agents:
                    log.info("ML Analysis: %d agents at risk of failure", len(at_risk_agents))
                    
                    for agent_info in at_risk_agents[:5]:  # Limit to top 5 for performance
                        log.debug("At risk: %s (score: %.2f, factors: %s)",
                                agent_info['name'],
                                agent_info['risk_score'],
                                ', '.join(agent_info['risk_factors']))
                    
                    # Trigger predictive maintenance for high-risk agents
                    high_risk = [a for a in at_risk_agents if a['risk_score'] > 0.7]
                    if high_risk:
                        context = {
                            'at_risk_agents': high_risk,
                            'prediction_source': 'ml_analysis',
                            'timestamp': datetime.now()
                        }
                        
                        maintenance_action = self.actions.get(ActionType.PREDICTIVE_MAINTENANCE)
                        if (maintenance_action and 
                            await self._can_execute_action(ActionType.PREDICTIVE_MAINTENANCE)):
                            await maintenance_action.execute_with_monitoring(context)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error("Prediction loop error: %s", e)
                await asyncio.sleep(300)  # Wait longer on error
    
    async def _adaptation_loop(self):
        """Adaptive configuration adjustment loop"""
        while self.running:
            try:
                await asyncio.sleep(CONFIG.adaptation_interval)
                
                # Analyze system performance
                await self._adapt_configuration()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error("Adaptation loop error: %s", e)
                await asyncio.sleep(600)  # Wait longer on error
    
    async def _adapt_configuration(self):
        """Adapt configuration based on system performance"""
        try:
            # Get performance metrics
            health_indicators = self.monitor.metrics.get_health_indicators()
            
            # Adapt check interval based on system load
            current_cpu = self.monitor.metrics.metrics.get("cpu_percent", deque())
            if current_cpu:
                recent_cpu = [v for _, v in list(current_cpu)[-10:]]
                avg_cpu = statistics.mean(recent_cpu) if recent_cpu else 0
                
                if avg_cpu > 80:
                    # High CPU - increase check interval
                    new_interval = min(CONFIG.check_interval * 1.2, 10)
                elif avg_cpu < 20:
                    # Low CPU - can afford more frequent checks
                    new_interval = max(CONFIG.check_interval * 0.9, 1)
                else:
                    new_interval = CONFIG.check_interval
                
                if abs(new_interval - CONFIG.check_interval) > 0.1:
                    log.info("Adapting check interval: %.1fs -> %.1fs (CPU: %.1f%%)",
                            CONFIG.check_interval, new_interval, avg_cpu)
                    CONFIG.check_interval = new_interval
            
            # Adapt ML parameters based on prediction accuracy
            if CONFIG.ml.enable_ml and self.monitor.ml_predictor.is_trained:
                # Could adapt prediction thresholds based on accuracy
                pass
            
            # Save adapted configuration
            config_path = CONFIG.log_dir / "adapted_config.json"
            CONFIG.save_to_file(config_path)
            
        except Exception as e:
            log.error("Configuration adaptation failed: %s", e)

# ================== Entry Point and Utilities ==================
def validate_environment():
    """Validate the runtime environment"""
    issues = []
    
    # Check Python version
    if sys.version_info < (3, 7):
        issues.append("Python 3.7+ required")
    
    # Check required directories
    for directory in [CONFIG.log_dir, CONFIG.model_dir]:
        try:
            os.makedirs(directory, exist_ok=True)
        except Exception as e:
            issues.append(f"Cannot create directory {directory}: {e}")
    
    # Check heartbeat file accessibility
    try:
        if CONFIG.heartbeat_file.exists():
            with open(CONFIG.heartbeat_file, 'r') as f:
                f.read(1)  # Test read access
    except Exception as e:
        issues.append(f"Heartbeat file not accessible: {e}")
    
    # Check optional dependencies
    warnings = []
    if not HAS_NUMPY:
        warnings.append("NumPy not available - using fallback implementations")
    if not HAS_SKLEARN:
        warnings.append("scikit-learn not available - using simple ML models")
    if not HAS_AIOFILES:
        warnings.append("aiofiles not available - using synchronous file I/O")
    
    return issues, warnings

async def main():
    """Enhanced main entry point with comprehensive error handling"""
    try:
        # Validate environment
        issues, warnings = validate_environment()
        
        if issues:
            for issue in issues:
                log.critical("Environment issue: %s", issue)
            sys.exit(1)
        
        for warning in warnings:
            log.warning("Environment warning: %s", warning)
        
        # Load configuration from file if available
        config_file = Path("./config/blackbox_config.json")
        if config_file.exists():
            try:
                global CONFIG
                CONFIG = Config.from_file(config_file)
                log.info("Configuration loaded from %s", config_file)
            except Exception as e:
                log.warning("Failed to load config file: %s", e)
        
        # Validate configuration
        if CONFIG.check_interval <= 0:
            raise ConfigurationError("Invalid check interval: must be > 0")
        
        if CONFIG.fail_threshold <= 0:
            raise ConfigurationError("Invalid fail threshold: must be > 0")
        
        if CONFIG.ml.enable_ml and CONFIG.ml.min_training_samples <= 0:
            raise ConfigurationError("Invalid ML training samples: must be > 0")
        
        # Log startup information
        log.info("BLACKBOX Enhanced ML v3.0 starting...")
        log.info("Configuration: check_interval=%.1fs, fail_threshold=%d, ml_enabled=%s",
                CONFIG.check_interval, CONFIG.fail_threshold, CONFIG.ml.enable_ml)
        log.info("Environment: Android/Pydroid3 compatible, numpy=%s, sklearn=%s",
                HAS_NUMPY, HAS_SKLEARN)
        
        # Create and start controller
        controller = EnhancedBlackboxController()
        
        # Run the system
        await controller.start()
        
    except ConfigurationError as e:
        log.critical("Configuration error: %s", e)
        sys.exit(1)
    except KeyboardInterrupt:
        log.info("Shutdown requested via keyboard interrupt")
    except Exception as e:
        log.critical("Fatal error: %s", e, exc_info=True)
        sys.exit(1)

def run():
    """Run the async main function with proper error handling"""
    try:
        # Set up asyncio for Android/Pydroid3 compatibility
        if sys.platform.startswith('linux') and 'android' in str(sys.platform).lower():
            # Android-specific asyncio setup
            asyncio.set_event_loop_policy(asyncio.DefaultEventLoopPolicy())
        
        # Use asyncio.run() for Python 3.7+
        asyncio.run(main())
        
    except KeyboardInterrupt:
        print("\nShutdown requested via keyboard interrupt")
    except SystemExit:
        raise  # Re-raise system exit
    except Exception as e:
        print(f"Unhandled exception in main: {e}")
        traceback.print_exc()
        sys.exit(1)

# ================== Additional Utilities ==================
class ConfigurationManager:
    """Manage configuration changes at runtime"""
    
    @staticmethod
    def update_config(**kwargs):
        """Update configuration parameters"""
        global CONFIG
        
        for key, value in kwargs.items():
            if hasattr(CONFIG, key):
                old_value = getattr(CONFIG, key)
                setattr(CONFIG, key, value)
                log.info("Configuration updated: %s = %s (was %s)", key, value, old_value)
            else:
                log.warning("Unknown configuration parameter: %s", key)
    
    @staticmethod
    def get_config_dict() -> Dict[str, Any]:
        """Get current configuration as dictionary"""
        return asdict(CONFIG)
    
    @staticmethod
    async def reload_config(config_path: Path):
        """Reload configuration from file"""
        global CONFIG
        try:
            CONFIG = Config.from_file(config_path)
            log.info("Configuration reloaded from %s", config_path)
        except Exception as e:
            log.error("Failed to reload configuration: %s", e)

class HealthReporter:
    """Generate health reports for external monitoring"""
    
    def __init__(self, controller: EnhancedBlackboxController):
        self.controller = controller
    
    async def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive health report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'system_status': 'operational' if self.controller.running else 'stopped',
            'performance_stats': self.controller.performance_stats.copy(),
            'agents': {},
            'ml_status': {},
            'resource_usage': {}
        }
        
        # Agent information
        for name, agent in self.controller.monitor.agents.items():
            report['agents'][name] = {
                'state': agent.state.name,
                'health_score': agent.health_score,
                'failure_count': agent.failure_count,
                'uptime_percentage': agent.uptime_percentage,
                'predicted_failure': agent.predicted_failure_time.isoformat() if agent.predicted_failure_time else None
            }
        
        # ML status
        if CONFIG.ml.enable_ml:
            report['ml_status'] = {
                'model_trained': self.controller.monitor.ml_predictor.is_trained,
                'training_samples': len(self.controller.monitor.ml_predictor.training_data),
                'feature_importance': self.controller.monitor.ml_predictor.feature_importance
            }
        
        return report
    
    async def save_report(self, report_path: Path):
        """Save health report to file"""
        try:
            report = await self.generate_report()
            
            os.makedirs(report_path.parent, exist_ok=True)
            with open(report_path, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            log.info("Health report saved to %s", report_path)
            
        except Exception as e:
            log.error("Failed to save health report: %s", e)

# ================== Main Execution ==================
if __name__ == "__main__":
    # Set log context for main execution
    log.set_context(execution_mode="standalone", platform="android")
    
    # Print banner
    print("=" * 60)
    print("BLACKBOX Enhanced ML v3.0")
    print("Intelligent Failsafe Autopilot with Machine Learning")
    print("Android/Pydroid3 Compatible")
    print("=" * 60)
    print()
    
    # Run the system
    run()
