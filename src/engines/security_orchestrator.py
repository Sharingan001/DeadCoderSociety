#!/usr/bin/env python3
"""
Integrated Security Analytics Platform for LogSentinel Pro v4.0
Master orchestration engine combining all engines
"""

import json
from typing import Dict, List, Optional
from datetime import datetime
from pathlib import Path


class SecurityAnalyticsPlatform:
    """Master orchestration engine for all LogSentinel security components."""
    
    def __init__(self):
        """Initialize all security engines."""
        self.initialized_at = datetime.now().isoformat()
        self.platform_status = "INITIALIZING"
        self.processed_logs = 0
        self.detected_anomalies = 0
        self.active_alerts = 0
        
        # Import all engines
        try:
            from log_classifier import LogClassifier, LogType, RiskLevel
            from alert_manager import AlertManager, AlertSeverity, AlertStatus
            from attack_replay import AttackReplaySystem, AttackTimeline
            from live_report_generator import LiveReportGenerator
            from anomaly_detector_advanced import AnomalyDetectionOrchestrator
            
            self.log_classifier = LogClassifier()
            self.alert_manager = AlertManager()
            self.attack_replay_system = AttackReplaySystem()
            self.report_generator = LiveReportGenerator()
            self.anomaly_orchestrator = AnomalyDetectionOrchestrator()
            
            self.platform_status = "READY"
        except Exception as e:
            self.platform_status = f"ERROR: {str(e)}"
    
    def process_log_stream(self, log_entries: List[str]) -> Dict:
        """Process incoming log stream through all analytics engines."""
        
        result = {
            "timestamp": datetime.now().isoformat(),
            "total_logs_processed": len(log_entries),
            "classifications": [],
            "anomalies_detected": [],
            "alerts_generated": [],
            "attacks_detected": []
        }
        
        for log_entry in log_entries:
            # Step 1: Classify log
            classification = self.log_classifier.classify_log(log_entry)
            result["classifications"].append(classification)
            self.processed_logs += 1
            
            # Step 2: Run anomaly detection
            if classification["risk_score"] > 0:
                anomaly_params = self._extract_anomaly_parameters(log_entry)
                anomaly_result = self.anomaly_orchestrator.analyze_metric(
                    classification["log_type"],
                    float(classification["risk_score"]),
                    [float(c.get("risk_score", 0)) for c in result["classifications"][-10:]]
                )
                
                if anomaly_result.get("ensemble_anomaly"):
                    result["anomalies_detected"].append(anomaly_result)
                    self.detected_anomalies += 1
            
            # Step 3: Generate alerts if high/critical risk
            if classification["risk_level"] in ["HIGH", "CRITICAL"]:
                from alert_manager import AlertSeverity
                
                alert_severity = AlertSeverity.CRITICAL if classification["risk_level"] == "CRITICAL" else AlertSeverity.HIGH
                alert = self.alert_manager.create_alert(
                    severity=alert_severity,
                    title=f"{classification['log_type']} Threat",
                    description=log_entry[:200],
                    source=classification["log_type"],
                    risk_factors=classification["risk_factors"],
                    context={"classification": classification}
                )
                
                result["alerts_generated"].append(alert.to_dict())
                self.active_alerts += 1
            
            # Step 4: Detect attack sequences
            attack_seq_id = self._detect_attack_sequence(log_entry, classification)
            if attack_seq_id:
                result["attacks_detected"].append({
                    "sequence_id": attack_seq_id,
                    "trigger_log": log_entry[:100]
                })
        
        return result
    
    def _extract_anomaly_parameters(self, log_entry: str) -> Dict:
        """Extract parameters for anomaly detection."""
        return {
            "entry_length": len(log_entry),
            "special_chars_ratio": sum(1 for c in log_entry if not c.isalnum()) / len(log_entry) if log_entry else 0,
            "entropy": self._calculate_entropy(log_entry)
        }
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy."""
        import math
        if not text:
            return 0.0
        
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        
        entropy = 0.0
        for count in freq.values():
            p = count / len(text)
            entropy -= p * math.log2(p)
        
        return entropy
    
    def _detect_attack_sequence(self, log_entry: str, classification: Dict) -> Optional[str]:
        """Detect if log entry is part of attack sequence."""
        high_risk_keywords = ["injection", "exploit", "backdoor", "malware", "brute force"]
        
        if any(keyword in log_entry.lower() for keyword in high_risk_keywords):
            ip = self._extract_ip(log_entry)
            seq_id = self.attack_replay_system.detect_attack_sequence(
                event_type=classification["log_type"],
                source_ip=ip or "unknown",
                destination_ip="tracked_system",
                port=None,
                severity=classification["risk_level"],
                description=log_entry[:100]
            )
            return seq_id
        
        return None
    
    def _extract_ip(self, text: str) -> Optional[str]:
        """Extract IP address from text."""
        import re
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        match = re.search(ip_pattern, text)
        return match.group(0) if match else None
    
    def get_system_health(self) -> Dict:
        """Get overall platform health metrics."""
        return {
            "platform_status": self.platform_status,
            "initialized_at": self.initialized_at,
            "logs_processed": self.processed_logs,
            "anomalies_detected": self.detected_anomalies,
            "alerts_active": self.active_alerts,
            "alert_summary": self.alert_manager.get_alert_summary(),
            "log_stats": self.log_classifier.get_statistics(),
            "attack_stats": self.attack_replay_system.get_attack_statistics()
        }
    
    def generate_comprehensive_report(self) -> Dict:
        """Generate comprehensive security report."""
        return self.report_generator.generate_executive_summary(
            self.alert_manager,
            self.log_classifier,
            self.attack_replay_system,
            hours=24
        )


class RealTimeSecurityDashboard:
    """Real-time security metrics and status dashboard."""
    
    def __init__(self, platform: SecurityAnalyticsPlatform):
        self.platform = platform
        self.dashboard_refresh_interval = 5  # seconds
    
    def get_dashboard_data(self) -> Dict:
        """Get all dashboard data for real-time UI."""
        return {
            "timestamp": datetime.now().isoformat(),
            "health": self.platform.get_system_health(),
            "live_metrics": self._calculate_live_metrics(),
            "top_threats": self._get_top_threats(),
            "recent_events": self._get_recent_events()
        }
    
    def _calculate_live_metrics(self) -> Dict:
        """Calculate live performance metrics."""
        return {
            "throughput_logs_per_second": self.platform.processed_logs / max(1, self.dashboard_refresh_interval),
            "anomaly_rate": self.platform.detected_anomalies / max(1, self.platform.processed_logs),
            "alert_density": self.platform.active_alerts / max(1, self.platform.processed_logs),
            "system_status": "HEALTHY" if self.platform.platform_status == "READY" else "DEGRADED"
        }
    
    def _get_top_threats(self) -> List[Dict]:
        """Get top current threats."""
        critical_alerts = self.platform.alert_manager.get_critical_alerts(hours=1)
        return [
            {
                "alert_id": a.alert_id,
                "title": a.title,
                "severity": a.severity,
                "timestamp": a.timestamp
            }
            for a in critical_alerts[:5]
        ]
    
    def _get_recent_events(self) -> List[Dict]:
        """Get recent security events."""
        active_attacks = self.platform.attack_replay_system.get_active_attacks()
        return [
            {
                "sequence_id": a.sequence_id,
                "name": a.attack_name,
                "type": a.attack_type,
                "events": len(a.events),
                "start_time": a.start_time
            }
            for a in active_attacks[:5]
        ]


class ThreatIntelligenceCorrelator:
    """Correlate events across multiple data sources."""
    
    def __init__(self, platform: SecurityAnalyticsPlatform):
        self.platform = platform
        self.correlation_rules = self._initialize_correlation_rules()
    
    def _initialize_correlation_rules(self) -> List[Dict]:
        """Initialize correlation detection rules."""
        return [
            {
                "name": "coordinated_attack_pattern",
                "events": ["brute_force", "sql_injection", "privilege_escalation"],
                "time_window": 300,  # 5 minutes
                "severity_multiplier": 3
            },
            {
                "name": "data_exfiltration_sequence",
                "events": ["lateral_movement", "data_access", "external_transfer"],
                "time_window": 600,
                "severity_multiplier": 5
            },
            {
                "name": "advanced_persistent_threat",
                "events": ["reconnaissance", "initial_compromise", "c2_communication"],
                "time_window": 86400,  # 24 hours
                "severity_multiplier": 10
            }
        ]
    
    def correlate_events(self, recent_logs: List[Dict]) -> List[Dict]:
        """Correlate recent events for pattern detection."""
        correlated_patterns = []
        
        for rule in self.correlation_rules:
            matching_events = []
            
            for log in recent_logs:
                if any(event_type in log.get("log_type", "") for event_type in rule["events"]):
                    matching_events.append(log)
            
            if len(matching_events) >= len(rule["events"]) * 0.8:
                correlated_patterns.append({
                    "pattern_name": rule["name"],
                    "confidence": len(matching_events) / len(rule["events"]),
                    "severity_boost": rule["severity_multiplier"],
                    "events": matching_events
                })
        
        return correlated_patterns


# Entry point for integration
def initialize_security_platform() -> SecurityAnalyticsPlatform:
    """Initialize complete security analytics platform."""
    platform = SecurityAnalyticsPlatform()
    return platform
