#!/usr/bin/env python3
"""
AGENT_AGESIS_C.py - Advanced ML-Enhanced Network Scanner
Nexus-compatible modular agent with enhanced machine learning capabilities
Version: 2.0 - Hardened and Optimized
"""

import asyncio
import subprocess
import socket
import os
import sys
import time
import json
import logging
import signal
import hashlib
import threading
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Dict, Set, List, Tuple, Optional, Any, Union
from dataclasses import dataclass, asdict
from contextlib import asynccontextmanager
import pickle
import warnings
import traceback

# Suppress warnings for cleaner output
warnings.filterwarnings('ignore')

# External imports with fallbacks
try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    from sklearn.cluster import DBSCAN
    ML_AVAILABLE = True
except ImportError:
    print("[WARNING] Advanced ML libraries not available. Using basic ML capabilities.")
    import math
    ML_AVAILABLE = False
    # Fallback numpy-like operations
    class np:
        @staticmethod
        def array(data): return data
        @staticmethod
        def mean(data): return sum(data) / len(data) if data else 0
        @staticmethod
        def std(data): 
            if not data: return 0
            mean_val = sum(data) / len(data)
            return math.sqrt(sum((x - mean_val) ** 2 for x in data) / len(data))
        @staticmethod
        def zeros(size): return [0] * size

# Configuration with validation
@dataclass
class AgentConfig:
    """Configuration class with validation"""
    log_file: str = "~/agesis_lite.log"
    baseline_file: str = "~/agesis_baseline.json"
    ml_model_file: str = "~/agesis_ml_model.pkl"
    device_db_file: str = "~/agesis_devices.json"
    scan_interval: int = 60
    concurrent_limit: int = 100
    learning_window: int = 168  # Hours
    anomaly_threshold: float = 0.7
    pattern_history_size: int = 200
    min_data_points: int = 15
    max_response_time: float = 5000.0  # ms
    ping_timeout: float = 2.0
    adaptive_scanning: bool = True
    security_mode: bool = True
    nexus_compatible: bool = True
    
    def __post_init__(self):
        """Validate configuration parameters"""
        self.log_file = os.path.expanduser(self.log_file)
        self.baseline_file = os.path.expanduser(self.baseline_file)
        self.ml_model_file = os.path.expanduser(self.ml_model_file)
        self.device_db_file = os.path.expanduser(self.device_db_file)
        
        # Validation
        if not (10 <= self.scan_interval <= 3600):
            raise ValueError("scan_interval must be between 10-3600 seconds")
        if not (10 <= self.concurrent_limit <= 500):
            raise ValueError("concurrent_limit must be between 10-500")
        if not (0.1 <= self.anomaly_threshold <= 1.0):
            raise ValueError("anomaly_threshold must be between 0.1-1.0")

# Global configuration
config = AgentConfig()

# Enhanced logging setup with rotation
def setup_logging():
    """Setup enhanced logging with rotation and security"""
    try:
        from logging.handlers import RotatingFileHandler
        
        # Create logs directory if needed
        log_dir = os.path.dirname(config.log_file)
        os.makedirs(log_dir, exist_ok=True)
        
        # Setup rotating file handler
        handler = RotatingFileHandler(
            config.log_file, 
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - [%(funcName)s:%(lineno)d] - %(message)s'
        )
        handler.setFormatter(formatter)
        
        logger = logging.getLogger('agesis')
        logger.setLevel(logging.INFO)
        logger.addHandler(handler)
        
        # Console handler for critical messages
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.WARNING)
        console_handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
        logger.addHandler(console_handler)
        
        return logger
        
    except Exception as e:
        # Fallback to basic logging
        logging.basicConfig(
            filename=config.log_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        return logging.getLogger('agesis')

logger = setup_logging()

class SecurityManager:
    """Enhanced security manager for network operations"""
    
    def __init__(self):
        self.rate_limiter = defaultdict(deque)
        self.blocked_ips = set()
        self.max_requests_per_minute = 60
        
    def is_rate_limited(self, ip: str) -> bool:
        """Check if IP is rate limited"""
        now = time.time()
        minute_ago = now - 60
        
        # Clean old entries
        while self.rate_limiter[ip] and self.rate_limiter[ip][0] < minute_ago:
            self.rate_limiter[ip].popleft()
        
        if len(self.rate_limiter[ip]) >= self.max_requests_per_minute:
            return True
        
        self.rate_limiter[ip].append(now)
        return False
    
    def validate_ip(self, ip: str) -> bool:
        """Validate IP address format and range"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            
            for part in parts:
                num = int(part)
                if not 0 <= num <= 255:
                    return False
            
            # Block certain ranges for security
            if ip.startswith(('127.', '169.254.', '224.', '240.')):
                return False
                
            return True
        except (ValueError, AttributeError):
            return False
    
    def sanitize_input(self, data: str) -> str:
        """Sanitize input data"""
        if not isinstance(data, str):
            return str(data)
        
        # Remove potentially dangerous characters
        dangerous_chars = ['`', '$', '(', ')', ';', '|', '&', '<', '>']
        for char in dangerous_chars:
            data = data.replace(char, '')
        
        return data.strip()

security_manager = SecurityManager()

class AdvancedMLEngine:
    """Enhanced ML engine with multiple algorithms and feature engineering"""
    
    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.feature_importance = {}
        self.model_performance = {}
        self.ensemble_weights = {}
        
        # Initialize models based on availability
        if ML_AVAILABLE:
            self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
            self.scaler = StandardScaler()
            self.clusterer = DBSCAN(eps=0.5, min_samples=3)
        else:
            self.isolation_forest = None
            self.scaler = None
            self.clusterer = None
        
        self.trained = False
        
    def extract_features(self, device_data: Dict) -> List[float]:
        """Extract comprehensive features from device data"""
        features = []
        
        # Basic availability features
        total_scans = device_data.get('total_scans', 0)
        online_count = device_data.get('online_count', 0)
        availability_rate = online_count / max(total_scans, 1)
        features.extend([availability_rate, total_scans, online_count])
        
        # Response time features
        avg_response = device_data.get('avg_response_time', 0)
        response_variance = device_data.get('response_variance', 0)
        features.extend([avg_response, response_variance])
        
        # Temporal features
        now = datetime.now()
        last_seen = device_data.get('last_seen')
        if last_seen and isinstance(last_seen, datetime):
            hours_since_seen = (now - last_seen).total_seconds() / 3600
        else:
            hours_since_seen = 999999  # Very large number for never seen
        features.append(min(hours_since_seen, 168))  # Cap at 1 week
        
        # Pattern features
        hourly_entropy = self._calculate_entropy(device_data.get('hourly_pattern', []))
        weekly_entropy = self._calculate_entropy(device_data.get('weekly_pattern', []))
        features.extend([hourly_entropy, weekly_entropy])
        
        # Network behavior features
        response_stability = 1.0 / (1.0 + response_variance / max(avg_response, 1))
        scan_frequency = total_scans / max((now - device_data.get('first_seen', now)).days, 1)
        features.extend([response_stability, scan_frequency])
        
        return features
    
    def _calculate_entropy(self, pattern: List[float]) -> float:
        """Calculate entropy of a pattern"""
        if not pattern or sum(pattern) == 0:
            return 0.0
        
        total = sum(pattern)
        probabilities = [p / total for p in pattern if p > 0]
        
        entropy = 0.0
        for p in probabilities:
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy
    
    def train_models(self, device_profiles: Dict):
        """Train multiple ML models on device data"""
        if len(device_profiles) < config.min_data_points:
            logger.warning("Insufficient data for ML training")
            return False
        
        try:
            # Extract features for all devices
            feature_matrix = []
            device_ips = []
            
            for ip, profile in device_profiles.items():
                if profile.get('total_scans', 0) >= config.min_data_points:
                    features = self.extract_features(profile)
                    feature_matrix.append(features)
                    device_ips.append(ip)
            
            if not feature_matrix:
                return False
            
            feature_matrix = np.array(feature_matrix) if ML_AVAILABLE else feature_matrix
            
            # Train isolation forest for anomaly detection
            if ML_AVAILABLE and self.isolation_forest:
                # Scale features
                scaled_features = self.scaler.fit_transform(feature_matrix)
                
                # Train isolation forest
                self.isolation_forest.fit(scaled_features)
                
                # Train clustering model
                clusters = self.clusterer.fit_predict(scaled_features)
                
                # Store cluster information
                self.device_clusters = dict(zip(device_ips, clusters))
                
            self.trained = True
            logger.info(f"ML models trained on {len(feature_matrix)} devices")
            return True
            
        except Exception as e:
            logger.error(f"ML training failed: {e}")
            return False
    
    def predict_anomaly(self, device_profile: Dict) -> Tuple[float, Dict]:
        """Predict anomaly score and provide explanation"""
        try:
            features = self.extract_features(device_profile)
            
            if ML_AVAILABLE and self.trained and self.isolation_forest:
                scaled_features = self.scaler.transform([features])
                anomaly_score = self.isolation_forest.decision_function(scaled_features)[0]
                # Convert to 0-1 scale (higher = more anomalous)
                anomaly_score = max(0, min(1, (anomaly_score + 0.5) * -1))
            else:
                # Fallback scoring
                anomaly_score = self._calculate_fallback_anomaly(features)
            
            # Generate explanation
            explanation = self._explain_anomaly(features, anomaly_score)
            
            return anomaly_score, explanation
            
        except Exception as e:
            logger.error(f"Anomaly prediction failed: {e}")
            return 0.5, {"error": str(e)}
    
    def _calculate_fallback_anomaly(self, features: List[float]) -> float:
        """Fallback anomaly calculation when sklearn is not available"""
        # Simple statistical approach
        scores = []
        
        # Availability anomaly
        availability = features[0] if features else 0.5
        if availability < 0.1 or availability > 0.99:
            scores.append(0.8)
        else:
            scores.append(abs(availability - 0.5) * 2)
        
        # Response time anomaly
        if len(features) > 3:
            response_time = features[3]
            if response_time > 1000:  # > 1 second
                scores.append(min(response_time / 5000, 1.0))
            else:
                scores.append(0.1)
        
        return sum(scores) / len(scores) if scores else 0.5
    
    def _explain_anomaly(self, features: List[float], score: float) -> Dict:
        """Generate human-readable anomaly explanation"""
        explanation = {
            "anomaly_score": score,
            "severity": "LOW" if score < 0.3 else "MEDIUM" if score < 0.7 else "HIGH",
            "factors": []
        }
        
        if len(features) >= 5:
            availability = features[0]
            response_time = features[3]
            response_variance = features[4]
            
            if availability < 0.1:
                explanation["factors"].append("Very low availability")
            elif availability > 0.99:
                explanation["factors"].append("Unusually high availability")
            
            if response_time > 1000:
                explanation["factors"].append("High response times")
            
            if response_variance > 500:
                explanation["factors"].append("Unstable response times")
        
        return explanation

class EnhancedDeviceProfiler:
    """Enhanced device profiler with advanced ML capabilities"""
    
    def __init__(self):
        self.profiles = {}
        self.ml_engine = AdvancedMLEngine()
        self.response_patterns = defaultdict(list)
        self.hourly_patterns = defaultdict(lambda: np.zeros(24))
        self.weekly_patterns = defaultdict(lambda: np.zeros(7))
        self.device_fingerprints = {}
        self.network_topology = defaultdict(set)
        
    def generate_device_fingerprint(self, ip: str, response_data: Dict) -> str:
        """Generate unique device fingerprint"""
        fingerprint_data = {
            'ip': ip,
            'avg_response': response_data.get('avg_response_time', 0),
            'response_pattern': response_data.get('response_variance', 0),
            'availability_pattern': response_data.get('online_count', 0) / max(response_data.get('total_scans', 1), 1)
        }
        
        # Create hash-based fingerprint
        fingerprint_str = json.dumps(fingerprint_data, sort_keys=True)
        return hashlib.md5(fingerprint_str.encode()).hexdigest()[:16]
    
    def update_profile(self, ip: str, online: bool, response_time: float = 0, 
                      additional_data: Dict = None):
        """Enhanced profile update with comprehensive data collection"""
        now = datetime.now()
        hour = now.hour
        weekday = now.weekday()
        
        # Initialize profile if new
        if ip not in self.profiles:
            self.profiles[ip] = {
                'first_seen': now,
                'last_seen': now if online else None,
                'total_scans': 0,
                'online_count': 0,
                'offline_count': 0,
                'avg_response_time': 0,
                'response_variance': 0,
                'min_response_time': float('inf') if online else 0,
                'max_response_time': 0,
                'anomaly_score': 0,
                'predicted_availability': 0.5,
                'hourly_pattern': np.zeros(24).tolist(),
                'weekly_pattern': np.zeros(7).tolist(),
                'consecutive_offline': 0,
                'consecutive_online': 0,
                'last_state': None,
                'state_changes': 0,
                'fingerprint': None,
                'additional_metadata': {}
            }
        
        profile = self.profiles[ip]
        profile['total_scans'] += 1
        
        # Track state changes
        if profile['last_state'] is not None and profile['last_state'] != online:
            profile['state_changes'] += 1
            profile['consecutive_offline'] = 0
            profile['consecutive_online'] = 0
        
        profile['last_state'] = online
        
        if online:
            profile['online_count'] += 1
            profile['consecutive_online'] += 1
            profile['consecutive_offline'] = 0
            profile['last_seen'] = now
            
            # Update response time statistics
            if response_time > 0:
                old_avg = profile['avg_response_time']
                n = profile['online_count']
                profile['avg_response_time'] = (old_avg * (n-1) + response_time) / n
                
                # Update variance using online algorithm
                if n > 1:
                    delta = response_time - old_avg
                    delta2 = response_time - profile['avg_response_time']
                    profile['response_variance'] = (
                        (n-2) * profile['response_variance'] + delta * delta2
                    ) / (n-1) if n > 2 else abs(delta2)
                
                # Update min/max
                profile['min_response_time'] = min(profile['min_response_time'], response_time)
                profile['max_response_time'] = max(profile['max_response_time'], response_time)
                
                # Store response pattern
                self.response_patterns[ip].append({
                    'timestamp': now,
                    'response_time': response_time
                })
                
                # Keep only recent patterns
                if len(self.response_patterns[ip]) > config.pattern_history_size:
                    self.response_patterns[ip].pop(0)
            
            # Update temporal patterns
            self.hourly_patterns[ip][hour] += 1
            self.weekly_patterns[ip][weekday] += 1
            
            # Store patterns in profile for ML
            profile['hourly_pattern'] = self.hourly_patterns[ip].tolist() if hasattr(self.hourly_patterns[ip], 'tolist') else list(self.hourly_patterns[ip])
            profile['weekly_pattern'] = self.weekly_patterns[ip].tolist() if hasattr(self.weekly_patterns[ip], 'tolist') else list(self.weekly_patterns[ip])
            
        else:
            profile['offline_count'] += 1
            profile['consecutive_offline'] += 1
            profile['consecutive_online'] = 0
        
        # Generate/update fingerprint
        profile['fingerprint'] = self.generate_device_fingerprint(ip, profile)
        
        # Store additional metadata
        if additional_data:
            profile['additional_metadata'].update(additional_data)
        
        # Calculate anomaly score using ML engine
        profile['anomaly_score'], anomaly_explanation = self.ml_engine.predict_anomaly(profile)
        profile['anomaly_explanation'] = anomaly_explanation
        
        # Update predicted availability
        profile['predicted_availability'] = self._predict_availability(ip, hour, weekday)
        
        # Retrain ML models periodically
        if profile['total_scans'] % 100 == 0:
            self.ml_engine.train_models(self.profiles)
    
    def _predict_availability(self, ip: str, hour: int, weekday: int) -> float:
        """Enhanced availability prediction using multiple factors"""
        if ip not in self.profiles or self.profiles[ip]['total_scans'] < config.min_data_points:
            return 0.5
        
        profile = self.profiles[ip]
        
        # Base availability
        base_prob = profile['online_count'] / profile['total_scans']
        
        # Temporal patterns
        hourly_total = sum(self.hourly_patterns[ip])
        weekly_total = sum(self.weekly_patterns[ip])
        
        hour_prob = self.hourly_patterns[ip][hour] / max(hourly_total, 1)
        week_prob = self.weekly_patterns[ip][weekday] / max(weekly_total, 1)
        
        # Recent state consideration
        recent_weight = 0.1
        if profile['last_seen']:
            hours_since = (datetime.now() - profile['last_seen']).total_seconds() / 3600
            if hours_since < 1:
                recent_weight = 0.3
            elif hours_since < 24:
                recent_weight = 0.2
        
        # Stability factor
        state_stability = 1.0 / (1.0 + profile['state_changes'] / max(profile['total_scans'], 1))
        
        # Weighted combination
        predicted = (
            0.4 * base_prob +
            0.2 * hour_prob +
            0.2 * week_prob +
            recent_weight * (1.0 if profile['consecutive_online'] > 0 else 0.0) +
            0.1 * state_stability
        )
        
        return max(0.0, min(1.0, predicted))
    
    def get_network_insights(self) -> Dict:
        """Generate comprehensive network insights"""
        insights = {
            'total_devices': len(self.profiles),
            'active_devices': sum(1 for p in self.profiles.values() if p.get('last_seen') and 
                                (datetime.now() - p['last_seen']).total_seconds() < 3600),
            'anomalous_devices': len(self.get_suspicious_devices()),
            'network_stability': self._calculate_network_stability(),
            'peak_hours': self._identify_peak_hours(),
            'device_clusters': self._analyze_device_clusters()
        }
        
        return insights
    
    def _calculate_network_stability(self) -> float:
        """Calculate overall network stability score"""
        if not self.profiles:
            return 0.5
        
        stability_scores = []
        for profile in self.profiles.values():
            if profile['total_scans'] >= config.min_data_points:
                # Lower state changes = higher stability
                stability = 1.0 / (1.0 + profile['state_changes'] / profile['total_scans'])
                stability_scores.append(stability)
        
        return sum(stability_scores) / len(stability_scores) if stability_scores else 0.5
    
    def _identify_peak_hours(self) -> List[int]:
        """Identify peak network activity hours"""
        hourly_totals = [0] * 24
        
        for hourly_pattern in self.hourly_patterns.values():
            for hour, count in enumerate(hourly_pattern):
                hourly_totals[hour] += count
        
        if not any(hourly_totals):
            return []
        
        max_activity = max(hourly_totals)
        threshold = max_activity * 0.8
        
        return [hour for hour, activity in enumerate(hourly_totals) if activity >= threshold]
    
    def _analyze_device_clusters(self) -> Dict:
        """Analyze device clustering patterns"""
        clusters = defaultdict(list)
        
        if hasattr(self.ml_engine, 'device_clusters'):
            for device, cluster in self.ml_engine.device_clusters.items():
                clusters[cluster].append(device)
        
        return {
            'cluster_count': len(clusters),
            'largest_cluster': max(len(devices) for devices in clusters.values()) if clusters else 0,
            'outliers': clusters.get(-1, [])  # DBSCAN uses -1 for outliers
        }
    
    def get_suspicious_devices(self, threshold: float = None) -> List[Tuple[str, float, Dict]]:
        """Get devices with high anomaly scores and explanations"""
        if threshold is None:
            threshold = config.anomaly_threshold
        
        suspicious = []
        for ip, profile in self.profiles.items():
            if profile['total_scans'] >= config.min_data_points:
                score = profile.get('anomaly_score', 0)
                if score >= threshold:
                    explanation = profile.get('anomaly_explanation', {})
                    suspicious.append((ip, score, explanation))
        
        return sorted(suspicious, key=lambda x: x[1], reverse=True)
    
    def save(self, filepath: str):
        """Save enhanced profiler with error handling"""
        try:
            # Create backup of existing file
            if os.path.exists(filepath):
                backup_path = f"{filepath}.backup"
                os.rename(filepath, backup_path)
            
            # Prepare data for serialization
            save_data = {
                'profiles': self.profiles,
                'device_fingerprints': self.device_fingerprints,
                'response_patterns': dict(self.response_patterns),
                'hourly_patterns': {k: v.tolist() if hasattr(v, 'tolist') else list(v) 
                                  for k, v in self.hourly_patterns.items()},
                'weekly_patterns': {k: v.tolist() if hasattr(v, 'tolist') else list(v) 
                                  for k, v in self.weekly_patterns.items()},
                'metadata': {
                    'save_time': datetime.now().isoformat(),
                    'version': '2.0',
                    'ml_available': ML_AVAILABLE
                }
            }
            
            with open(filepath, 'wb') as f:
                pickle.dump(save_data, f, protocol=pickle.HIGHEST_PROTOCOL)
            
            logger.info(f"Profiler saved successfully to {filepath}")
            
        except Exception as e:
            logger.error(f"Failed to save profiler: {e}")
            # Restore backup if available
            backup_path = f"{filepath}.backup"
            if os.path.exists(backup_path):
                os.rename(backup_path, filepath)
                logger.info("Backup restored due to save failure")
    
    @classmethod
    def load(cls, filepath: str) -> 'EnhancedDeviceProfiler':
        """Load enhanced profiler with migration support"""
        profiler = cls()
        
        if not os.path.exists(filepath):
            logger.info("No existing profiler found, creating new one")
            return profiler
        
        try:
            with open(filepath, 'rb') as f:
                data = pickle.load(f)
            
            # Handle different data formats
            if isinstance(data, dict) and 'profiles' in data:
                # New format
                profiler.profiles = data['profiles']
                profiler.device_fingerprints = data.get('device_fingerprints', {})
                profiler.response_patterns = defaultdict(list, data.get('response_patterns', {}))
                
                # Reconstruct numpy arrays
                for ip, pattern in data.get('hourly_patterns', {}).items():
                    profiler.hourly_patterns[ip] = np.array(pattern) if ML_AVAILABLE else pattern
                
                for ip, pattern in data.get('weekly_patterns', {}).items():
                    profiler.weekly_patterns[ip] = np.array(pattern) if ML_AVAILABLE else pattern
                
                logger.info(f"Loaded profiler with {len(profiler.profiles)} devices")
                
            else:
                # Legacy format - migrate
                if hasattr(data, 'profiles'):
                    profiler.profiles = data.profiles
                    profiler.response_patterns = data.response_patterns if hasattr(data, 'response_patterns') else defaultdict(list)
                    profiler.hourly_patterns = data.hourly_patterns if hasattr(data, 'hourly_patterns') else defaultdict(lambda: np.zeros(24))
                    profiler.weekly_patterns = data.weekly_patterns if hasattr(data, 'weekly_patterns') else defaultdict(lambda: np.zeros(7))
                
                logger.info("Migrated legacy profiler format")
            
            # Retrain ML models
            profiler.ml_engine.train_models(profiler.profiles)
            
        except Exception as e:
            logger.error(f"Failed to load profiler: {e}")
            logger.info("Starting with fresh profiler")
        
        return profiler

class NetworkScanner:
    """Enhanced network scanner with security and performance optimizations"""
    
    def __init__(self, profiler: EnhancedDeviceProfiler):
        self.profiler = profiler
        self.scan_stats = defaultdict(int)
        self.performance_metrics = deque(maxlen=100)
        
    async def enhanced_ping(self, ip: str, timeout: float = None) -> Tuple[bool, float, Dict]:
        """Enhanced ping with additional metrics and security checks"""
        if timeout is None:
            timeout = config.ping_timeout
        
        # Security validation
        if not security_manager.validate_ip(ip):
            logger.warning(f"Invalid IP address: {ip}")
            return False, 0, {"error": "invalid_ip"}
        
        if security_manager.is_rate_limited(ip):
            return False, 0, {"error": "rate_limited"}
        
        start_time = time.perf_counter()
        additional_metrics = {}
        
        try:
            # Use subprocess for better control
            proc = await asyncio.create_subprocess_exec(
                'ping', '-c', '1', '-W', str(int(timeout * 1000)), ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), 
                timeout=timeout + 1.0
            )
            
            response_time = (time.perf_counter() - start_time) * 1000
            
            # Parse additional information from ping output
            if proc.returncode == 0 and stdout:
                output = stdout.decode('utf-8', errors='ignore')
                additional_metrics = self._parse_ping_output(output)
            
            success = proc.returncode == 0
            self.scan_stats['successful_pings' if success else 'failed_pings'] += 1
            
            return success, response_time, additional_metrics
            
        except asyncio.TimeoutError:
            self.scan_stats['timeout_pings'] += 1
            return False, 0, {"error": "timeout"}
        except Exception as e:
            logger.error(f"Ping error for {ip}: {e}")
            self.scan_stats['error_pings'] += 1
            return False, 0, {"error": str(e)}
    
    def _parse_ping_output(self, output: str) -> Dict:
        """Parse additional metrics from ping output"""
        metrics = {}
        try:
            lines = output.split('\n')
            for line in lines:
                if 'time=' in line:
                    # Extract TTL and other info
                    if 'ttl=' in line:
                        ttl_start = line.find('ttl=') + 4
                        ttl_end = line.find(' ', ttl_start)
                        if ttl_end == -1:
                            ttl_end = len(line)
                        metrics['ttl'] = int(line[ttl_start:ttl_end])
                    
                    # Extract packet size
                    if 'bytes from' in line:
                        bytes_start = line.find('bytes from') - 10
                        bytes_end = line.find(' bytes from')
                        if bytes_start >= 0:
                            bytes_str = line[max(0, bytes_start):bytes_end].strip()
                            if bytes_str.isdigit():
                                metrics['packet_size'] = int(bytes_str)
        except Exception as e:
            logger.debug(f"Failed to parse ping output: {e}")
        
        return metrics

    async def intelligent_subnet_scan(self, subnet: str) -> Dict[str, Dict]:
        """Perform intelligent subnet scan with adaptive prioritization"""
        scan_start = time.perf_counter()
        results = {}
        
        logger.info(f"Starting intelligent scan of {subnet}.0/24")
        
        # Generate IP priority list
        ip_priorities = self._calculate_scan_priorities(subnet)
        
        # Adaptive batch sizing based on network conditions
        batch_size = min(config.concurrent_limit, max(10, len(ip_priorities) // 4))
        semaphore = asyncio.Semaphore(batch_size)
        
        async def scan_single_ip(ip_data: Tuple[str, float]):
            ip, priority = ip_data
            async with semaphore:
                try:
                    online, response_time, metrics = await self.enhanced_ping(ip)
                    
                    if online:
                        device_data = {
                            'timestamp': datetime.now().isoformat(),
                            'response_time': response_time,
                            'priority_score': priority,
                            'metrics': metrics
                        }
                        
                        # Update profiler
                        self.profiler.update_profile(ip, True, response_time, metrics)
                        
                        return ip, device_data
                    else:
                        # Still update profiler for offline devices
                        self.profiler.update_profile(ip, False, 0, metrics)
                        return None, None
                        
                except Exception as e:
                    logger.error(f"Error scanning {ip}: {e}")
                    return None, None
        
        # Execute scans in batches for better resource management
        tasks = []
        for ip_data in ip_priorities:
            if ip_data[1] >= self._get_scan_threshold():  # Priority threshold
                task = scan_single_ip(ip_data)
                tasks.append(task)
        
        # Process results
        scan_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in scan_results:
            if isinstance(result, Exception):
                logger.error(f"Scan task failed: {result}")
                continue
            
            ip, data = result
            if ip and data:
                results[ip] = data
        
        # Record performance metrics
        scan_duration = time.perf_counter() - scan_start
        self.performance_metrics.append({
            'timestamp': datetime.now(),
            'duration': scan_duration,
            'devices_found': len(results),
            'total_scanned': len(tasks)
        })
        
        logger.info(f"Scan completed: {len(results)} devices found in {scan_duration:.2f}s")
        return results
    
    def _calculate_scan_priorities(self, subnet: str) -> List[Tuple[str, float]]:
        """Calculate scanning priorities based on historical data and ML predictions"""
        priorities = []
        now = datetime.now()
        
        for i in range(1, 255):
            ip = f"{subnet}.{i}"
            
            # Base priority
            priority = 0.5
            
            # Historical availability
            if ip in self.profiler.profiles:
                profile = self.profiler.profiles[ip]
                
                # Recent activity boost
                if profile.get('last_seen'):
                    hours_since = (now - profile['last_seen']).total_seconds() / 3600
                    if hours_since < 24:
                        priority += 0.3 * (1 - hours_since / 24)
                
                # Predicted availability
                predicted = self.profiler._predict_availability(ip, now.hour, now.weekday())
                priority = 0.6 * priority + 0.4 * predicted
                
                # Anomaly score consideration (higher anomaly = higher priority for monitoring)
                anomaly_score = profile.get('anomaly_score', 0)
                if anomaly_score > 0.5:
                    priority += 0.2 * anomaly_score
            
            # Common device IP patterns (routers, printers, etc.)
            if i in [1, 254, 100, 101, 102]:  # Common router/gateway IPs
                priority += 0.1
            
            priorities.append((ip, priority))
        
        # Sort by priority (highest first)
        return sorted(priorities, key=lambda x: x[1], reverse=True)
    
    def _get_scan_threshold(self) -> float:
        """Dynamic scan threshold based on network size and performance"""
        if config.adaptive_scanning:
            # Lower threshold for smaller networks or when performance is good
            avg_duration = np.mean([m['duration'] for m in self.performance_metrics]) if self.performance_metrics else 30
            
            if avg_duration < 10:  # Fast network
                return 0.01
            elif avg_duration < 30:  # Normal network
                return 0.05
            else:  # Slow network
                return 0.15
        
        return 0.05  # Default threshold

class NexusInterface:
    """Nexus system compatibility interface"""
    
    def __init__(self, profiler: EnhancedDeviceProfiler, scanner: NetworkScanner):
        self.profiler = profiler
        self.scanner = scanner
        self.status = "inactive"
        self.last_report = None
        
    def get_agent_status(self) -> Dict:
        """Return agent status for Nexus system"""
        return {
            'agent_id': 'agesis_lite',
            'status': self.status,
            'version': '2.0',
            'capabilities': [
                'network_scanning',
                'anomaly_detection',
                'device_profiling',
                'ml_analytics',
                'threat_detection'
            ],
            'metrics': {
                'devices_tracked': len(self.profiler.profiles),
                'anomalies_detected': len(self.profiler.get_suspicious_devices()),
                'uptime': self._get_uptime(),
                'last_scan': self.last_report.isoformat() if self.last_report else None
            }
        }
    
    def _get_uptime(self) -> float:
        """Calculate agent uptime in hours"""
        # This would be implemented with actual start time tracking
        return 0.0
    
    def generate_nexus_report(self) -> Dict:
        """Generate comprehensive report for Nexus system"""
        insights = self.profiler.get_network_insights()
        suspicious_devices = self.profiler.get_suspicious_devices()
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'agent_id': 'agesis_lite',
            'report_type': 'network_security_analysis',
            'summary': {
                'total_devices': insights['total_devices'],
                'active_devices': insights['active_devices'],
                'anomalous_devices': insights['anomalous_devices'],
                'network_stability': insights['network_stability'],
                'threat_level': self._assess_threat_level(suspicious_devices)
            },
            'details': {
                'suspicious_devices': [
                    {
                        'ip': ip,
                        'anomaly_score': score,
                        'explanation': explanation,
                        'risk_level': self._categorize_risk(score)
                    }
                    for ip, score, explanation in suspicious_devices[:10]
                ],
                'network_patterns': {
                    'peak_hours': insights['peak_hours'],
                    'device_clusters': insights['device_clusters']
                },
                'performance_metrics': {
                    'scan_success_rate': self._calculate_scan_success_rate(),
                    'average_response_time': self._get_average_response_time()
                }
            },
            'recommendations': self._generate_recommendations(suspicious_devices, insights)
        }
        
        self.last_report = datetime.now()
        return report
    
    def _assess_threat_level(self, suspicious_devices: List) -> str:
        """Assess overall network threat level"""
        if not suspicious_devices:
            return "LOW"
        
        high_risk_count = sum(1 for _, score, _ in suspicious_devices if score > 0.8)
        medium_risk_count = sum(1 for _, score, _ in suspicious_devices if 0.5 <= score <= 0.8)
        
        if high_risk_count > 2:
            return "HIGH"
        elif high_risk_count > 0 or medium_risk_count > 5:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _categorize_risk(self, score: float) -> str:
        """Categorize individual device risk"""
        if score >= 0.8:
            return "HIGH"
        elif score >= 0.5:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _calculate_scan_success_rate(self) -> float:
        """Calculate scan success rate"""
        total = sum(self.scanner.scan_stats.values())
        if total == 0:
            return 1.0
        
        successful = self.scanner.scan_stats.get('successful_pings', 0)
        return successful / total
    
    def _get_average_response_time(self) -> float:
        """Get average response time from recent scans"""
        if not self.scanner.performance_metrics:
            return 0.0
        
        return np.mean([m['duration'] for m in self.scanner.performance_metrics])
    
    def _generate_recommendations(self, suspicious_devices: List, insights: Dict) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if len(suspicious_devices) > 5:
            recommendations.append("High number of anomalous devices detected. Consider detailed investigation.")
        
        if insights['network_stability'] < 0.5:
            recommendations.append("Network stability is low. Check for infrastructure issues.")
        
        high_anomaly_devices = [d for d in suspicious_devices if d[1] > 0.8]
        if high_anomaly_devices:
            recommendations.append(f"Immediate attention required for {len(high_anomaly_devices)} high-risk devices.")
        
        if not recommendations:
            recommendations.append("Network appears stable. Continue monitoring.")
        
        return recommendations

class AgentController:
    """Main agent controller with enhanced error handling and monitoring"""
    
    def __init__(self):
        self.profiler = None
        self.scanner = None
        self.nexus_interface = None
        self.running = False
        self.scan_task = None
        self.shutdown_event = asyncio.Event()
        
        # Signal handling for graceful shutdown
        if hasattr(signal, 'SIGTERM'):
            signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        logger.info(f"Received signal {signum}, initiating graceful shutdown...")
        self.shutdown_event.set()
    
    async def initialize(self):
        """Initialize all components"""
        try:
            logger.info("Initializing AGESIS-LITE components...")
            
            # Initialize profiler
            self.profiler = EnhancedDeviceProfiler.load(config.ml_model_file)
            
            # Initialize scanner
            self.scanner = NetworkScanner(self.profiler)
            
            # Initialize Nexus interface
            if config.nexus_compatible:
                self.nexus_interface = NexusInterface(self.profiler, self.scanner)
            
            logger.info("AGESIS-LITE initialized successfully")
            
        except Exception as e:
            logger.error(f"Initialization failed: {e}")
            raise
    
    async def start_monitoring(self):
        """Start continuous monitoring"""
        if self.running:
            logger.warning("Monitoring already active")
            return
        
        self.running = True
        
        if self.nexus_interface:
            self.nexus_interface.status = "active"
        
        logger.info("Starting adaptive continuous monitoring...")
        
        try:
            await self._monitoring_loop()
        except Exception as e:
            logger.error(f"Monitoring loop failed: {e}")
        finally:
            await self.stop_monitoring()
    
    async def _monitoring_loop(self):
        """Main monitoring loop with adaptive intervals"""
        subnet = self._detect_network_subnet()
        
        while self.running and not self.shutdown_event.is_set():
            try:
                scan_start = time.time()
                
                logger.info(f"Starting adaptive scan of {subnet}.0/24")
                
                # Perform intelligent scan
                current_devices = await self.scanner.intelligent_subnet_scan(subnet)
                
                # Load baseline and detect anomalies
                baseline = self._load_baseline()
                self._detect_and_report_anomalies(current_devices, baseline)
                
                # Save profiler state
                self.profiler.save(config.ml_model_file)
                
                # Generate Nexus report if needed
                if self.nexus_interface and len(current_devices) > 0:
                    report = self.nexus_interface.generate_nexus_report()
                    self._handle_nexus_report(report)
                
                # Adaptive interval calculation
                scan_duration = time.time() - scan_start
                next_interval = self._calculate_adaptive_interval(scan_duration, current_devices)
                
                logger.info(f"Scan completed in {scan_duration:.1f}s. Next scan in {next_interval}s")
                
                # Wait for next scan or shutdown signal
                try:
                    await asyncio.wait_for(self.shutdown_event.wait(), timeout=next_interval)
                    break  # Shutdown signal received
                except asyncio.TimeoutError:
                    continue  # Normal timeout, continue monitoring
                    
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                logger.debug(traceback.format_exc())
                await asyncio.sleep(30)  # Wait before retrying
    
    def _detect_network_subnet(self) -> str:
        """Enhanced network subnet detection with multiple fallbacks"""
        try:
            # Method 1: Get default route
            result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if 'dev' in line:
                        parts = line.split()
                        if 'via' in parts:
                            gateway_ip = parts[parts.index('via') + 1]
                            return '.'.join(gateway_ip.split('.')[:-1])
        except Exception:
            pass
        
        try:
            # Method 2: Socket connection method
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            return '.'.join(local_ip.split('.')[:-1])
        except Exception:
            pass
        
        try:
            # Method 3: Connect to external service
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                return '.'.join(local_ip.split('.')[:-1])
        except Exception:
            pass
        
        # Fallback
        logger.warning("Could not detect network subnet, using fallback")
        return "192.168.1"
    
    def _calculate_adaptive_interval(self, scan_duration: float, devices: Dict) -> int:
        """Calculate adaptive scan interval based on network conditions"""
        base_interval = config.scan_interval
        
        # Factor in scan performance
        if scan_duration > 60:
            base_interval = int(base_interval * 1.5)  # Slow network
        elif scan_duration < 10:
            base_interval = max(10, int(base_interval * 0.8))  # Fast network
        
        # Factor in anomaly detection
        suspicious_count = len(self.profiler.get_suspicious_devices())
        if suspicious_count > 3:
            base_interval = max(10, base_interval // 2)  # More frequent monitoring
        elif suspicious_count == 0:
            base_interval = min(300, int(base_interval * 1.2))  # Less frequent monitoring
        
        # Factor in network activity
        if len(devices) > 20:
            base_interval = max(30, int(base_interval * 0.9))  # Busy network
        
        return base_interval
    
    def _detect_and_report_anomalies(self, current: Dict, baseline: Dict):
        """Enhanced anomaly detection and reporting"""
        new_devices = set(current) - set(baseline)
        missing_devices = set(baseline) - set(current)
        suspicious = self.profiler.get_suspicious_devices()
        
        if new_devices or missing_devices or suspicious:
            print("\n" + "="*60)
            print("    🔍 NETWORK ANOMALY DETECTION REPORT")
            print("="*60)
            
            if new_devices:
                print(f"\n[+] NEW DEVICES DETECTED ({len(new_devices)}):")
                for ip in sorted(new_devices):
                    profile = self.profiler.profiles.get(ip, {})
                    score = profile.get('anomaly_score', 1.0)
                    explanation = profile.get('anomaly_explanation', {})
                    severity = explanation.get('severity', 'UNKNOWN')
                    
                    print(f"  📍 {ip}")
                    print(f"     Severity: {severity} | Anomaly Score: {score:.3f}")
                    
                    if explanation.get('factors'):
                        print(f"     Factors: {', '.join(explanation['factors'])}")
                    
                    logger.warning(f"New device detected: {ip} (Anomaly: {score:.3f})")
            
            if missing_devices:
                print(f"\n[-] MISSING DEVICES ({len(missing_devices)}):")
                for ip in sorted(missing_devices):
                    profile = self.profiler.profiles.get(ip, {})
                    last_seen = profile.get('last_seen', 'Unknown')
                    if isinstance(last_seen, datetime):
                        hours_ago = (datetime.now() - last_seen).total_seconds() / 3600
                        last_seen_str = f"{hours_ago:.1f} hours ago"
                    else:
                        last_seen_str = str(last_seen)
                    
                    predicted_availability = profile.get('predicted_availability', 0)
                    
                    print(f"  📍 {ip}")
                    print(f"     Last seen: {last_seen_str}")
                    print(f"     Expected availability: {predicted_availability:.1%}")
                    
                    logger.info(f"Missing device: {ip} (last seen: {last_seen_str})")
            
            if suspicious:
                high_risk = [d for d in suspicious if d[1] > 0.8]
                medium_risk = [d for d in suspicious if 0.5 <= d[1] <= 0.8]
                
                if high_risk:
                    print(f"\n[🚨] HIGH RISK DEVICES ({len(high_risk)}):")
                    for ip, score, explanation in high_risk[:5]:
                        print(f"  📍 {ip}")
                        print(f"     Anomaly Score: {score:.3f}")
                        print(f"     Risk Factors: {', '.join(explanation.get('factors', ['Unknown']))}")
                
                if medium_risk and len(medium_risk) > len(high_risk):
                    print(f"\n[⚠️] MEDIUM RISK DEVICES ({len(medium_risk)}):")
                    for ip, score, explanation in medium_risk[:3]:
                        print(f"  📍 {ip} | Score: {score:.3f}")
            
            # Network insights summary
            insights = self.profiler.get_network_insights()
            print(f"\n[📊] NETWORK HEALTH:")
            print(f"     Stability Score: {insights['network_stability']:.2f}")
            print(f"     Active Devices: {insights['active_devices']}/{insights['total_devices']}")
            print(f"     Peak Hours: {insights['peak_hours']}")
            
        else:
            print("\n[✅] Network scan completed - No anomalies detected")
            logger.info("Network scan normal - no anomalies detected")
    
    def _load_baseline(self) -> Dict:
        """Load network baseline with error handling"""
        try:
            if os.path.exists(config.baseline_file):
                with open(config.baseline_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load baseline: {e}")
        return {}
    
    def _save_baseline(self, devices: Dict):
        """Save network baseline with backup"""
        try:
            # Create backup
            if os.path.exists(config.baseline_file):
                backup_file = f"{config.baseline_file}.backup"
                os.rename(config.baseline_file, backup_file)
            
            # Save new baseline
            baseline_data = {ip: data['timestamp'] for ip, data in devices.items()}
            with open(config.baseline_file, 'w') as f:
                json.dump(baseline_data, f, indent=2)
            
            logger.info(f"Baseline saved with {len(baseline_data)} devices")
            
        except Exception as e:
            logger.error(f"Failed to save baseline: {e}")
    
    def _handle_nexus_report(self, report: Dict):
        """Handle Nexus system integration"""
        # This would integrate with the actual Nexus system
        # For now, we'll log the report
        logger.info("Nexus report generated")
        
        # Could implement:
        # - Send report to Nexus API endpoint
        # - Write to shared message queue
        # - Update shared database
        pass
    
    async def stop_monitoring(self):
        """Stop monitoring gracefully"""
        if not self.running:
            return
        
        logger.info("Stopping monitoring...")
        self.running = False
        
        if self.scan_task and not self.scan_task.done():
            self.scan_task.cancel()
            try:
                await self.scan_task
            except asyncio.CancelledError:
                pass
        
        # Save final state
        if self.profiler:
            self.profiler.save(config.ml_model_file)
        
        if self.nexus_interface:
            self.nexus_interface.status = "inactive"
        
        logger.info("Monitoring stopped successfully")
    
    async def perform_single_scan(self):
        """Perform a single network scan"""
        subnet = self._detect_network_subnet()
        print(f"\n[🔍] Performing intelligent scan of {subnet}.0/24...")
        
        devices = await self.scanner.intelligent_subnet_scan(subnet)
        baseline = self._load_baseline()
        
        self._detect_and_report_anomalies(devices, baseline)
        
        # Save updated profiler
        self.profiler.save(config.ml_model_file)
        
        return devices
    
    def display_device_insights(self):
        """Display comprehensive device insights"""
        if not self.profiler.profiles:
            print("\n[ℹ️] No device data available yet. Run a scan first.")
            return
        
        insights = self.profiler.get_network_insights()
        
        print("\n" + "="*70)
        print("    🧠 ADVANCED DEVICE INTELLIGENCE REPORT")
        print("="*70)
        
        # Network Overview
        print(f"\n[📊] NETWORK OVERVIEW:")
        print(f"     Total devices tracked: {insights['total_devices']}")
        print(f"     Currently active: {insights['active_devices']}")
        print(f"     Anomalous devices: {insights['anomalous_devices']}")
        print(f"     Network stability: {insights['network_stability']:.2f}")
        
        # Most reliable devices
        reliable_devices = sorted(
            [(ip, p['online_count']/p['total_scans']) 
             for ip, p in self.profiler.profiles.items() 
             if p['total_scans'] >= config.min_data_points],
            key=lambda x: x[1], reverse=True
        )[:5]
        
        if reliable_devices:
            print(f"\n[⭐] MOST RELIABLE DEVICES:")
            for i, (ip, reliability) in enumerate(reliable_devices, 1):
                profile = self.profiler.profiles[ip]
                response_time = profile['avg_response_time']
                print(f"     {i}. {ip}")
                print(f"        Uptime: {reliability:.1%} | Avg Response: {response_time:.1f}ms")
        
        # Suspicious devices
        suspicious = self.profiler.get_suspicious_devices()[:5]
        if suspicious:
            print(f"\n[⚠️] SUSPICIOUS DEVICES:")
            for i, (ip, score, explanation) in enumerate(suspicious, 1):
                profile = self.profiler.profiles[ip]
                last_seen = profile.get('last_seen', 'Never')
                if isinstance(last_seen, datetime):
                    last_seen = last_seen.strftime('%Y-%m-%d %H:%M:%S')
                
                print(f"     {i}. {ip}")
                print(f"        Anomaly Score: {score:.3f} | Last Seen: {last_seen}")
                if explanation.get('factors'):
                    print(f"        Risk Factors: {', '.join(explanation['factors'])}")
        
        # Network patterns
        print(f"\n[🕐] NETWORK ACTIVITY PATTERNS:")
        if insights['peak_hours']:
            peak_hours_str = ', '.join(f"{h}:00" for h in insights['peak_hours'])
            print(f"     Peak activity hours: {peak_hours_str}")
        else:
            print("     Peak activity hours: Not enough data")
        
        # Device clusters
        cluster_info = insights['device_clusters']
        print(f"     Device clusters: {cluster_info['cluster_count']}")
        print(f"     Largest cluster: {cluster_info['largest_cluster']} devices")
        if cluster_info['outliers']:
            print(f"     Outlier devices: {len(cluster_info['outliers'])}")
        
        # ML Training Status
        training_data_points = sum(p['total_scans'] for p in self.profiler.profiles.values())
        print(f"\n[🤖] MACHINE LEARNING STATUS:")
        print(f"     ML Libraries: {'Available' if ML_AVAILABLE else 'Basic mode'}")
        print(f"     Training data points: {training_data_points}")
        print(f"     Model trained: {'Yes' if self.profiler.ml_engine.trained else 'No'}")

async def main():
    """Enhanced main function with comprehensive error handling"""
    controller = None
    
    try:
        # Initialize controller
        controller = AgentController()
        await controller.initialize()
        
        print("\n" + "="*70)
        print("    🚀 AGENT_AGESIS_C v2.0 - Advanced ML Network Scanner")
        print("    🔬 Intelligent Anomaly Detection & Security Analysis")
        print("    🌐 Nexus-Compatible Modular Agent")
        print("="*70)
        
        # Main interaction loop
        while True:
            print("\n[📋] COMMAND MENU:")
            print("  1. 🔍 Quick Intelligent Scan")
            print("  2. 🔄 Start Adaptive Monitoring")
            print("  3. ⏹️  Stop Monitoring")
            print("  4. 🧠 View Device Intelligence")
            print("  5. ⚙️  Configure Settings")
            print("  6. 📊 Reset Network Baseline")
            print("  7. 🔧 System Diagnostics")
            print("  8. 📈 Performance Metrics")
            print("  9. 🚪 Exit")
            
            try:
                choice = input("\n💭 Select option (1-9): ").strip()
                
                if choice == '1':
                    await controller.perform_single_scan()
                    
                elif choice == '2':
                    if not controller.running:
                        controller.scan_task = asyncio.create_task(controller.start_monitoring())
                        print("\n[✅] Adaptive monitoring started successfully")
                    else:
                        print("\n[⚠️] Monitoring is already active")
                        
                elif choice == '3':
                    await controller.stop_monitoring()
                    print("\n[✅] Monitoring stopped successfully")
                    
                elif choice == '4':
                    controller.display_device_insights()
                    
                elif choice == '5':
                    await _configure_settings()
                    
                elif choice == '6':
                    subnet = controller._detect_network_subnet()
                    print(f"\n[📊] Capturing new baseline for {subnet}.0/24...")
                    devices = await controller.perform_single_scan()
                    controller._save_baseline(devices)
                    print(f"[✅] Baseline saved with {len(devices)} devices")
                    
                elif choice == '7':
                    _display_system_diagnostics(controller)
                    
                elif choice == '8':
                    _display_performance_metrics(controller)
                    
                elif choice == '9':
                    await controller.stop_monitoring()
                    print("\n[✅] AGESIS-LITE shutdown complete. Stay secure! 🛡️")
                    break
                    
                else:
                    print("\n[❌] Invalid choice. Please select 1-9.")
                    
            except KeyboardInterrupt:
                print("\n\n[⚠️] Interrupt received. Use option 9 to exit gracefully.")
                continue
            except Exception as e:
                logger.error(f"Menu error: {e}")
                print(f"\n[❌] An error occurred: {e}")
                
    except Exception as e:
        logger.error(f"Critical error in main: {e}")
        logger.debug(traceback.format_exc())
        print(f"\n[💥] Critical error: {e}")
        
    finally:
        # Ensure cleanup
        if controller:
            await controller.stop_monitoring()

async def _configure_settings():
    """Interactive settings configuration"""
    global config
    
    print("\n" + "="*50)
    print("    ⚙️ CONFIGURATION SETTINGS")
    print("="*50)
    
    print(f"\nCurrent Settings:")
    print(f"  Scan Interval: {config.scan_interval}s")
    print(f"  Concurrent Limit: {config.concurrent_limit}")
    print(f"  Anomaly Threshold: {config.anomaly_threshold}")
    print(f"  Adaptive Scanning: {config.adaptive_scanning}")
    print(f"  Security Mode: {config.security_mode}")
    print(f"  Nexus Compatible: {config.nexus_compatible}")
    
    print(f"\n[📝] Configuration Options:")
    print("  1. Scan Interval (10-3600 seconds)")
    print("  2. Concurrent Limit (10-500)")
    print("  3. Anomaly Threshold (0.1-1.0)")
    print("  4. Toggle Adaptive Scanning")
    print("  5. Toggle Security Mode")
    print("  6. Toggle Nexus Compatibility")
    print("  7. Reset to Defaults")
    print("  8. Return to Main Menu")
    
    try:
        choice = input("\n💭 Select setting to modify (1-8): ").strip()
        
        if choice == '1':
            interval = int(input("Enter new scan interval (10-3600): "))
            if 10 <= interval <= 3600:
                config.scan_interval = interval
                print(f"[✅] Scan interval set to {interval} seconds")
            else:
                print("[❌] Invalid interval. Must be between 10-3600 seconds")
                
        elif choice == '2':
            limit = int(input("Enter concurrent limit (10-500): "))
            if 10 <= limit <= 500:
                config.concurrent_limit = limit
                print(f"[✅] Concurrent limit set to {limit}")
            else:
                print("[❌] Invalid limit. Must be between 10-500")
                
        elif choice == '3':
            threshold = float(input("Enter anomaly threshold (0.1-1.0): "))
            if 0.1 <= threshold <= 1.0:
                config.anomaly_threshold = threshold
                print(f"[✅] Anomaly threshold set to {threshold}")
            else:
                print("[❌] Invalid threshold. Must be between 0.1-1.0")
                
        elif choice == '4':
            config.adaptive_scanning = not config.adaptive_scanning
            print(f"[✅] Adaptive scanning {'enabled' if config.adaptive_scanning else 'disabled'}")
            
        elif choice == '5':
            config.security_mode = not config.security_mode
            print(f"[✅] Security mode {'enabled' if config.security_mode else 'disabled'}")
            
        elif choice == '6':
            config.nexus_compatible = not config.nexus_compatible
            print(f"[✅] Nexus compatibility {'enabled' if config.nexus_compatible else 'disabled'}")
            
        elif choice == '7':
            config = AgentConfig()  # Reset to defaults
            print("[✅] Configuration reset to defaults")
            
        elif choice == '8':
            return
        else:
            print("[❌] Invalid choice")
            
    except ValueError:
        print("[❌] Invalid input format")
    except Exception as e:
        print(f"[❌] Configuration error: {e}")

def _display_system_diagnostics(controller: AgentController):
    """Display comprehensive system diagnostics"""
    print("\n" + "="*60)
    print("    🔧 SYSTEM DIAGNOSTICS")
    print("="*60)
    
    # Agent Status
    if controller.nexus_interface:
        status = controller.nexus_interface.get_agent_status()
        print(f"\n[🤖] AGENT STATUS:")
        print(f"     Agent ID: {status['agent_id']}")
        print(f"     Version: {status['version']}")
        print(f"     Status: {status['status']}")
        print(f"     Capabilities: {', '.join(status['capabilities'])}")
    
    # System Resources
    print(f"\n[💻] SYSTEM RESOURCES:")
    try:
        import psutil
        cpu_percent = psutil.cpu_percent()
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        print(f"     CPU Usage: {cpu_percent}%")
        print(f"     Memory Usage: {memory.percent}% ({memory.used // (1024**2)}MB / {memory.total // (1024**2)}MB)")
        print(f"     Disk Usage: {disk.percent}% ({disk.used // (1024**3)}GB / {disk.total // (1024**3)}GB)")
    except ImportError:
        print("     Resource monitoring requires psutil package")
    except Exception as e:
        print(f"     Resource monitoring error: {e}")
    
    # File System Status
    print(f"\n[📁] FILE SYSTEM:")
    files_to_check = [
        ("Log File", config.log_file),
        ("Baseline File", config.baseline_file),
        ("ML Model File", config.ml_model_file),
        ("Device DB File", config.device_db_file)
    ]
    
    for name, path in files_to_check:
        if os.path.exists(path):
            size = os.path.getsize(path)
            mtime = datetime.fromtimestamp(os.path.getmtime(path))
            print(f"     {name}: ✅ {size} bytes (Modified: {mtime.strftime('%Y-%m-%d %H:%M')})")
        else:
            print(f"     {name}: ❌ Not found")
    
    # ML Engine Status
    if controller.profiler:
        print(f"\n[🧠] MACHINE LEARNING:")
        print(f"     ML Libraries Available: {'✅' if ML_AVAILABLE else '❌'}")
        print(f"     Model Trained: {'✅' if controller.profiler.ml_engine.trained else '❌'}")
        print(f"     Profiles Loaded: {len(controller.profiler.profiles)}")
        print(f"     Feature Engineering: ✅ Advanced")
        
        if ML_AVAILABLE:
            print(f"     Algorithms: Isolation Forest, DBSCAN Clustering")
        else:
            print(f"     Algorithms: Statistical fallback methods")
    
    # Network Connectivity
    print(f"\n[🌐] NETWORK CONNECTIVITY:")
    try:
        subnet = controller._detect_network_subnet()
        print(f"     Detected Subnet: {subnet}.0/24")
        
        # Test connectivity to common services
        test_hosts = [
            ("Gateway", f"{subnet}.1"),
            ("DNS", "8.8.8.8"),
            ("Local Network", f"{subnet}.254")
        ]
        
        for name, host in test_hosts:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(2)
                    result = s.connect_ex((host, 80))
                    status = "✅" if result == 0 else "❌"
                    print(f"     {name} ({host}): {status}")
            except Exception:
                print(f"     {name} ({host}): ❌")
                
    except Exception as e:
        print(f"     Network test error: {e}")
    
    # Security Status
    print(f"\n[🛡️] SECURITY STATUS:")
    print(f"     Security Mode: {'✅ Enabled' if config.security_mode else '❌ Disabled'}")
    print(f"     Input Sanitization: ✅ Active")
    print(f"     Rate Limiting: ✅ Active")
    print(f"     IP Validation: ✅ Active")
    
    blocked_count = len(security_manager.blocked_ips)
    rate_limited_count = len(security_manager.rate_limiter)
    print(f"     Blocked IPs: {blocked_count}")
    print(f"     Rate Limited IPs: {rate_limited_count}")

def _display_performance_metrics(controller: AgentController):
    """Display detailed performance metrics"""
    print("\n" + "="*60)
    print("    📈 PERFORMANCE METRICS")
    print("="*60)
    
    if not controller.scanner:
        print("\n[⚠️] Scanner not initialized")
        return
    
    # Scan Statistics
    stats = controller.scanner.scan_stats
    total_pings = sum(stats.values())
    
    print(f"\n[📊] SCAN STATISTICS:")
    print(f"     Total Ping Attempts: {total_pings}")
    if total_pings > 0:
        success_rate = (stats.get('successful_pings', 0) / total_pings) * 100
        print(f"     Success Rate: {success_rate:.1f}%")
        print(f"     Successful Pings: {stats.get('successful_pings', 0)}")
        print(f"     Failed Pings: {stats.get('failed_pings', 0)}")
        print(f"     Timeout Pings: {stats.get('timeout_pings', 0)}")
        print(f"     Error Pings: {stats.get('error_pings', 0)}")
    
    # Performance History
    metrics = controller.scanner.performance_metrics
    if metrics:
        print(f"\n[⏱️] PERFORMANCE HISTORY:")
        
        recent_scans = list(metrics)[-10:]  # Last 10 scans
        avg_duration = np.mean([m['duration'] for m in recent_scans])
        avg_devices = np.mean([m['devices_found'] for m in recent_scans])
        avg_scanned = np.mean([m['total_scanned'] for m in recent_scans])
        
        print(f"     Average Scan Duration: {avg_duration:.2f}s")
        print(f"     Average Devices Found: {avg_devices:.1f}")
        print(f"     Average IPs Scanned: {avg_scanned:.1f}")
        
        if len(recent_scans) > 1:
            durations = [m['duration'] for m in recent_scans]
            trend = "📈 Increasing" if durations[-1] > durations[0] else "📉 Decreasing"
            print(f"     Performance Trend: {trend}")
        
        print(f"\n[📋] RECENT SCAN HISTORY:")
        for i, metric in enumerate(recent_scans[-5:], 1):
            timestamp = metric['timestamp'].strftime('%H:%M:%S')
            print(f"     {i}. {timestamp} - {metric['duration']:.1f}s - {metric['devices_found']} devices")
    
    # Memory Usage Estimation
    if controller.profiler:
        profile_count = len(controller.profiler.profiles)
        estimated_memory = profile_count * 0.001  # Rough estimate in MB
        
        print(f"\n[💾] MEMORY USAGE:")
        print(f"     Device Profiles: {profile_count}")
        print(f"     Estimated Memory: {estimated_memory:.1f} MB")
        
        # Pattern storage
        pattern_count = sum(len(patterns) for patterns in controller.profiler.response_patterns.values())
        print(f"     Response Patterns: {pattern_count} entries")
    
    # ML Performance
    if controller.profiler and controller.profiler.ml_engine:
        print(f"\n[🤖] ML PERFORMANCE:")
        training_status = "✅ Trained" if controller.profiler.ml_engine.trained else "❌ Not Trained"
        print(f"     Model Status: {training_status}")
        
        if hasattr(controller.profiler.ml_engine, 'model_performance'):
            performance = controller.profiler.ml_engine.model_performance
            if performance:
                for model_name, perf_data in performance.items():
                    print(f"     {model_name}: {perf_data}")

def _create_sample_config():
    """Create a sample configuration file"""
    sample_config = {
        "scan_interval": 60,
        "concurrent_limit": 100,
        "anomaly_threshold": 0.7,
        "adaptive_scanning": True,
        "security_mode": True,
        "nexus_compatible": True,
        "ml_settings": {
            "learning_window": 168,
            "pattern_history_size": 200,
            "min_data_points": 15
        },
        "security_settings": {
            "max_requests_per_minute": 60,
            "blocked_ip_ranges": ["127.0.0.0/8", "169.254.0.0/16"],
            "enable_rate_limiting": True
        }
    }
    
    config_file = os.path.expanduser("~/agesis_config.json")
    try:
        with open(config_file, 'w') as f:
            json.dump(sample_config, f, indent=2)
        print(f"[✅] Sample configuration created at {config_file}")
    except Exception as e:
        print(f"[❌] Failed to create config file: {e}")

def _validate_environment():
    """Validate the runtime environment"""
    issues = []
    
    # Check Python version
    if sys.version_info < (3, 7):
        issues.append("Python 3.7+ required")
    
    # Check required commands
    required_commands = ['ping', 'ip']
    for cmd in required_commands:
        try:
            subprocess.run([cmd, '--help'], capture_output=True, timeout=5)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            issues.append(f"Command '{cmd}' not available")
    
    # Check write permissions
    test_files = [config.log_file, config.baseline_file, config.ml_model_file]
    for filepath in test_files:
        directory = os.path.dirname(filepath)
        if not os.access(directory, os.W_OK):
            issues.append(f"No write permission for {directory}")
    
    # Check network access
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=3)
    except OSError:
        issues.append("No network connectivity")
    
    if issues:
        print(f"\n[⚠️] Environment validation issues:")
        for issue in issues:
            print(f"     • {issue}")
        return False
    
    print(f"[✅] Environment validation passed")
    return True

if __name__ == "__main__":
    try:
        # Validate environment before starting
        print("🔍 Validating runtime environment...")
        if not _validate_environment():
            print("\n[❌] Environment validation failed. Please address the issues above.")
            sys.exit(1)
        
        # Run the main application
        asyncio.run(main())
        
    except KeyboardInterrupt:
        print("\n\n[⚠️] Interrupted by user")
        logger.info("Application interrupted by user")
    except Exception as e:
        print(f"\n[💥] Fatal error: {e}")
        logger.error(f"Fatal error: {e}")
        logger.debug(traceback.format_exc())
        sys.exit(1)
    finally:
        print("\n[👋] Thank you for using AGESIS-LITE v2.0!")
        logger.info("Application shutdown complete")
