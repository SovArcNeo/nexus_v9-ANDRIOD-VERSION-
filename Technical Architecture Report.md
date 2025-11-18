# 📑 NEXUS UNIFIED v9.0 - Technical Architecture Report

Version: 9.0.0-PRODUCTION

Security Level: MAXIMUM

## Classification: Sovereign Network Intelligence & Host Monitoring System

Architect: SovArcNeo

## Executive Summary

NEXUS UNIFIED v9.0 is a production-grade, autonomous cybersecurity platform designed for high-security, air-gapped, and resource-constrained environments (Linux/Android Termux). Unlike traditional security tools that rely on heavy external dependencies (TensorFlow, PyTorch) or cloud APIs, NEXUS operates on a Zero-Dependency Sovereignty philosophy.

The system integrates three core pillars:

Network Intelligence (AGESIS_B): Asynchronous, non-blocking network cartography and risk assessment.

Host Sentinel (Sentinel): Real-time system metric analysis with statistical anomaly detection.

Neural Threat Engine: A custom-engineered, pure-NumPy neural network capable of online learning and predictive threat modeling without external ML libraries.

## System Architecture

The NEXUS architecture follows a Controller-Agent-Monitor pattern, utilizing a hybrid concurrency model that combines asyncio for network operations and threading for UI/monitoring tasks to ensure a non-blocking, 60-FPS console experience.

2.1 Core Components

DashboardController (The Brain): The central orchestration unit. It manages state synchronization, handles user input via non-blocking select calls, and coordinates data flow between subsystems.

AsyncNetworkScanner ( The Scout): An asynchronous engine using Python's asyncio to perform high-speed port scanning and service discovery without freezing the main execution thread.

HostMonitor (The Shield): A dedicated thread that continuously polls system metrics (psutil), extracts feature vectors, and feeds them into the neural network.

2.2 Adaptive Runtime (Fallbacks)

NEXUS features a self-healing import system. It detects the environment capabilities at runtime:

Standard Mode: Utilizes numpy for matrix operations and psutil for kernel metrics.

Sovereign/Fallback Mode: If dependencies are missing, the system hot-swaps in pure-Python implementations for math operations (custom matrix multiplication) and synthetic metric generation, ensuring 100% uptime on non-standard hardware.

## Subsystem Deep Dive

3.1 Custom Neural Network Engine

The crown jewel of v9.0 is the removal of heavy ML libraries in favor of a custom-built engine.

Class: NeuralNetwork & DenseLayer

Architecture: Configurable Multi-Layer Perceptron (MLP). Default: Input(12) -> Dense(64) -> Dense(32) -> Dense(16) -> Output(1).

Math Backend: Implements manual Backpropagation and Gradient Descent.

Activation Functions: Supports ReLU, Sigmoid, Tanh, Softmax, Swish, and Leaky ReLU.

Online Learning: Implements an OnlineLearner with an Experience Replay Buffer (ReplayBuffer). This allows the AI to learn from live system data while it runs, constantly adapting its baseline for "normal" behavior.

3.2 Asynchronous Network Intelligence

Class: AsyncNetworkScanner

Concurrency: Uses asyncio.gather to fire thousands of port checks simultaneously, drastically reducing scan times compared to linear socket connections.

Risk Scoring: Every discovered device is assigned a dynamic risk_score (0.0 - 1.0) based on open ports (e.g., Telnet port 23 triggers high risk), unknown services, and response latency.

3.3 Statistical Anomaly Detection

## Class: AnomalyDetector

Methodology: Uses a sliding window (deque) of historical metrics to calculate real-time Z-scores (Standard Score).

Logic: If a metric (CPU, RAM, Thread Count) deviates by more than ANOMALY_THRESHOLD (default 2.5 standard deviations) from the rolling mean, it triggers an immediate security alert.

## Security & Compliance

NEXUS v9.0 is built with a "Secure by Design" mindset.

Input Sanitization: The InputValidator class uses strict Regex patterns for IPs, Hostnames, and Commands to prevent injection attacks.

Forensic Audit Logging: The AuditLogger creates immutable, timestamped JSON logs of all critical actions (scans, optimization toggles, exports).

Rate Limiting: The RateLimiter prevents API/Command flooding, protecting the controller from resource exhaustion.

Permission Hardening: All generated files (logs, state dumps) are automatically chmod'd to 0o600 (Read/Write Owner Only).

## Data Flow & Persistence

Ingest: SystemMetricsCollector pulls raw kernel data.

Process: FeatureEngineer normalizes data and calculates 1st/2nd order derivatives (Velocity/Acceleration of CPU usage).

Analyze: Data is fed into NeuralNetwork for prediction (0.0-1.0 Threat Score) and AnomalyDetector for statistical outliers.

Persist: System state is serialized to nexus_state.json on shutdown, preserving the known device map.

Export: Data can be dumped to CSV (for spreadsheets) or JSON (for SIEM integration) via the _cmd_export interface.

## Technical Specifications

Feature Specification Language Python 3.8+Lines of Code2,500+DependenciesZero (Standard Lib only) OR numpy, psutil (Optional)Concurrencythreading (UI/Monitor), asyncio (Network)UI FrameworkCustom ANSI VT100 Console RendererML AlgorithmCustom MLP with Backprop & SGDRefresh RateConfigurable (Default: 3.0s)EncryptionReady for Argon2 / ChaCha20 (Architecture Compliant)

## Deployment Guide

Standard Deployment (Pydroid3/Linux/Termux)


# 1. Install optional accelerators (recommended for performance) pip install numpy psutil # 2. Launch System python3 nexus_v9.py 

Sovereign Deployment (No Internet/No Pip)

# NEXUS v9.0 detects missing libraries and automatically switches to internal pure-Python implementations.

# Runs out-of-the-box on any Python 3 environment python3 nexus_v9.py 

"Data is the new ammunition. Logic is the weapon. NEXUS is the fortress."

