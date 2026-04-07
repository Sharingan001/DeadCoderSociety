#!/usr/bin/env python3
"""
Live Report Generator for LogSentinel Pro v3.0
Real-time threat reporting and analysis
"""

import json
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from pathlib import Path


class LiveReportGenerator:
    """Generate real-time threat and security reports."""
    
    def __init__(self):
        self.reports_history = []
        self.max_history = 100
    
    def generate_executive_summary(self,
                                   alert_manager,
                                   log_classifier,
                                   attack_replay_system,
                                   hours: int = 24) -> Dict:
        """Generate executive-level threat summary."""
        
        time_threshold = datetime.now() - timedelta(hours=hours)
        
        # Get alert statistics
        alert_summary = alert_manager.get_alert_summary()
        critical_alerts = alert_manager.get_critical_alerts(hours=hours)
        
        # Get log statistics
        log_stats = log_classifier.get_statistics()
        
        # Get attack statistics
        attack_stats = attack_replay_system.get_attack_statistics()
        
        report = {
            "report_id": self._generate_report_id(),
            "generated_at": datetime.now().isoformat(),
            "period": f"Last {hours} hours",
            "summary": {
                "total_events_processed": log_stats.get("total_classified", 0),
                "total_alerts": alert_summary["total_alerts"],
                "critical_alerts": alert_summary["by_severity"].get("CRITICAL", 0),
                "high_alerts": alert_summary["by_severity"].get("HIGH", 0),
                "active_attacks": attack_stats.get("active_attacks", 0),
                "recorded_attacks": attack_stats.get("total_attacks", 0),
                "overall_risk_posture": self._calculate_risk_posture(alert_summary, attack_stats)
            },
            "threat_level": self._determine_threat_level(alert_summary, attack_stats),
            "critical_findings": self._extract_critical_findings(critical_alerts),
            "attack_breakdown": attack_stats.get("attack_types", {}),
            "alert_trends": alert_manager.get_alert_trend(hours=hours),
            "recommendations": self._generate_recommendations(alert_summary, attack_stats)
        }
        
        self.reports_history.append(report)
        if len(self.reports_history) > self.max_history:
            self.reports_history.pop(0)
        
        return report
    
    def generate_incident_report(self,
                                 sequence_id: str,
                                 attack_sequence,
                                 additional_context: Optional[Dict] = None) -> Dict:
        """Generate detailed incident report for a specific attack."""
        
        if not attack_sequence:
            return {"error": "Attack sequence not found"}
        
        report = {
            "report_id": self._generate_report_id(),
            "report_type": "incident",
            "generated_at": datetime.now().isoformat(),
            "incident": {
                "sequence_id": sequence_id,
                "name": attack_sequence.attack_name,
                "type": attack_sequence.attack_type,
                "severity": attack_sequence.severity,
                "status": attack_sequence.status,
                "start_time": attack_sequence.start_time,
                "end_time": attack_sequence.end_time,
                "duration_seconds": attack_sequence.duration_seconds()
            },
            "timeline": {
                "source_ips": attack_sequence.source_ips,
                "target_hosts": attack_sequence.target_hosts,
                "total_events": len(attack_sequence.events),
                "event_sequence": [
                    {
                        "timestamp": event.timestamp,
                        "type": event.event_type,
                        "source": event.source_ip,
                        "destination": event.destination_ip,
                        "port": event.port,
                        "severity": event.severity,
                        "description": event.description
                    }
                    for event in attack_sequence.events
                ]
            },
            "impact_assessment": self._assess_impact(attack_sequence),
            "mitre_tactics": attack_sequence.mitre_tactics,
            "remediation_steps": self._generate_remediation_steps(attack_sequence),
            "additional_context": additional_context or {}
        }
        
        self.reports_history.append(report)
        return report
    
    def generate_compliance_report(self,
                                   alerts: List,
                                   framework: str = "sox") -> Dict:
        """Generate compliance-focused report (SOX, PCI-DSS, HIPAA, ISO27001)."""
        
        framework_mappings = {
            "sox": self._sox_mapping,
            "pci_dss": self._pci_dss_mapping,
            "hipaa": self._hipaa_mapping,
            "iso27001": self._iso27001_mapping
        }
        
        mapping_func = framework_mappings.get(framework.lower(), self._sox_mapping)
        
        report = {
            "report_id": self._generate_report_id(),
            "report_type": "compliance",
            "framework": framework,
            "generated_at": datetime.now().isoformat(),
            "compliance_status": {
                "overall_status": "COMPLIANT" if len(alerts) == 0 else "NON_COMPLIANT",
                "violations_found": len(alerts),
                "critical_violations": sum(1 for a in alerts if a.get("severity") == "CRITICAL"),
                "remediation_required": len([a for a in alerts if a.get("status") == "NEW"])
            },
            "controls": mapping_func(alerts),
            "evidence": self._collect_evidence(alerts),
            "audit_trail": [
                {
                    "timestamp": a.get("timestamp"),
                    "event": a.get("title"),
                    "status": a.get("status")
                }
                for a in alerts
            ]
        }
        
        return report
    
    def generate_threat_intelligence_report(self,
                                           threat_intel_data: Dict,
                                           iocs: List[Dict]) -> Dict:
        """Generate threat intelligence briefing."""
        
        report = {
            "report_id": self._generate_report_id(),
            "report_type": "threat_intelligence",
            "generated_at": datetime.now().isoformat(),
            "threat_landscape": {
                "top_attack_types": threat_intel_data.get("top_attack_types", []),
                "top_source_ips": threat_intel_data.get("top_source_ips", []),
                "most_targeted_assets": threat_intel_data.get("top_targets", []),
                "emerging_threats": threat_intel_data.get("emerging_threats", [])
            },
            "indicators_of_compromise": {
                "total_iocs": len(iocs),
                "malicious_ips": [i for i in iocs if i.get("type") == "ip"],
                "malicious_domains": [i for i in iocs if i.get("type") == "domain"],
                "malicious_hashes": [i for i in iocs if i.get("type") == "hash"],
                "detection_rate": self._calculate_detection_rate(iocs)
            }
        }
        
        return report
    
    def generate_real_time_dashboard_data(self,
                                         alert_manager,
                                         log_classifier,
                                         attack_replay_system) -> Dict:
        """Generate live dashboard metrics for real-time UI."""
        
        alert_summary = alert_manager.get_alert_summary()
        active_attacks = attack_replay_system.get_active_attacks()
        log_stats = log_classifier.get_statistics()
        
        return {
            "timestamp": datetime.now().isoformat(),
            "metrics": {
                "active_alerts": alert_summary["by_status"].get("NEW", 0),
                "critical_severity": alert_summary["by_severity"].get("CRITICAL", 0),
                "high_severity": alert_summary["by_severity"].get("HIGH", 0),
                "active_attack_count": len(active_attacks),
                "logs_processed_hour": log_stats.get("total_classified", 0),
                "average_risk_level": log_stats.get("average_risk", 0)
            },
            "trends": {
                "alert_trend_24h": alert_manager.get_alert_trend(hours=24),
                "attack_types": {a.attack_type: 1 for a in active_attacks}
            },
            "top_threats": {
                "critical_alerts": [
                    {
                        "alert_id": a.alert_id,
                        "title": a.title,
                        "source": a.source,
                        "time": a.timestamp
                    }
                    for a in alert_manager.get_critical_alerts(hours=1)[:5]
                ],
                "active_attacks": [
                    {
                        "sequence_id": a.sequence_id,
                        "name": a.attack_name,
                        "type": a.attack_type,
                        "source_ips": a.source_ips
                    }
                    for a in active_attacks[:5]
                ]
            }
        }
    
    def _generate_report_id(self) -> str:
        """Generate unique report ID."""
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        return f"REPORT-{timestamp}"
    
    def _calculate_risk_posture(self, alert_summary: Dict, attack_stats: Dict) -> str:
        """Calculate overall risk posture."""
        critical_count = alert_summary["by_severity"].get("CRITICAL", 0)
        high_count = alert_summary["by_severity"].get("HIGH", 0)
        active_attacks = attack_stats.get("active_attacks", 0)
        
        risk_score = (critical_count * 10) + (high_count * 3) + (active_attacks * 5)
        
        if risk_score >= 50:
            return "CRITICAL"
        elif risk_score >= 30:
            return "HIGH"
        elif risk_score >= 10:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _determine_threat_level(self, alert_summary: Dict, attack_stats: Dict) -> str:
        """Determine overall threat level."""
        posture = self._calculate_risk_posture(alert_summary, attack_stats)
        return f"THREAT_LEVEL_{posture}"
    
    def _extract_critical_findings(self, critical_alerts: List) -> List[str]:
        """Extract key findings from critical alerts."""
        findings = []
        for alert in critical_alerts[:10]:
            findings.append(f"[{alert.severity}] {alert.title}: {alert.description}")
        return findings
    
    def _generate_recommendations(self, alert_summary: Dict, attack_stats: Dict) -> List[str]:
        """Generate actionable recommendations."""
        recommendations = []
        
        if alert_summary["by_severity"].get("CRITICAL", 0) > 0:
            recommendations.append("🚨 URGENT: Address critical alerts immediately")
        
        if attack_stats.get("active_attacks", 0) > 0:
            recommendations.append("⏱️ Monitor active attack sequences in real-time")
        
        if alert_summary["by_status"].get("NEW", 0) > 5:
            recommendations.append("✅ Acknowledge and triage all new alerts")
        
        recommendations.append("📋 Review and update detection rules based on trends")
        recommendations.append("🔐 Ensure MFA is enabled on all critical accounts")
        recommendations.append("🛡️ Patch identified vulnerabilities within SLA")
        
        return recommendations
    
    def _assess_impact(self, attack_sequence) -> Dict:
        """Assess potential business impact of attack."""
        return {
            "severity": attack_sequence.severity,
            "targeted_systems": len(attack_sequence.target_hosts),
            "affected_ips": len(attack_sequence.source_ips),
            "event_count": len(attack_sequence.events),
            "potential_data_loss": "Unknown" if not attack_sequence.events else "Possible"
        }
    
    def _generate_remediation_steps(self, attack_sequence) -> List[str]:
        """Generate remediation steps based on attack type."""
        steps = [
            f"1. Isolate affected hosts: {', '.join(attack_sequence.target_hosts)}",
            f"2. Block source IPs: {', '.join(attack_sequence.source_ips)}",
            "3. Review logs for lateral movement",
            "4. Check for data exfiltration",
            "5. Patch exploitation vectors",
            "6. Reset credentials on affected accounts",
            "7. Monitor for persistence mechanisms",
            "8. Restore from clean backups if compromised"
        ]
        return steps
    
    def _sox_mapping(self, alerts: List) -> Dict:
        """Map alerts to SOX compliance controls."""
        return {
            "IT-4.1": {
                "control": "Access control and authentication",
                "status": "PASS" if len([a for a in alerts if "authentication" in str(a).lower()]) < 3 else "FAIL",
                "evidence_count": len([a for a in alerts if "authentication" in str(a).lower()])
            },
            "IT-5.1": {
                "control": "System monitoring and logging",
                "status": "PASS" if len(alerts) < 10 else "FAIL",
                "evidence_count": len(alerts)
            }
        }
    
    def _pci_dss_mapping(self, alerts: List) -> Dict:
        """Map alerts to PCI-DSS compliance controls."""
        return {
            "1.1": {
                "control": "Firewall configuration standards",
                "status": "PASS" if len([a for a in alerts if "firewall" in str(a).lower()]) == 0 else "FAIL"
            },
            "2.1": {
                "control": "Default passwords changed",
                "status": "PASS" if len([a for a in alerts if "default" in str(a).lower()]) == 0 else "FAIL"
            },
            "7.1": {
                "control": "Restrict access to cardholder data",
                "status": "PASS" if len([a for a in alerts if "unauthorized" in str(a).lower()]) == 0 else "FAIL"
            }
        }
    
    def _hipaa_mapping(self, alerts: List) -> Dict:
        """Map alerts to HIPAA compliance controls."""
        return {
            "Access_Controls": {
                "control": "Unique identification and authentication",
                "violations": len([a for a in alerts if "authentication" in str(a).lower()])
            },
            "Audit_Controls": {
                "control": "Audit controls and logging",
                "violations": len(alerts)
            }
        }
    
    def _iso27001_mapping(self, alerts: List) -> Dict:
        """Map alerts to ISO 27001 compliance controls."""
        return {
            "A.5": {
                "control": "Access control",
                "status": "Compliant" if len([a for a in alerts if "access" in str(a).lower()]) < 2 else "Non-compliant"
            },
            "A.12": {
                "control": "Operations security",
                "status": "Compliant" if len(alerts) < 5 else "Non-compliant"
            }
        }
    
    def _collect_evidence(self, alerts: List) -> List[Dict]:
        """Collect evidence for audit."""
        return [
            {
                "timestamp": a.get("timestamp"),
                "alert_id": a.get("alert_id", "N/A"),
                "description": a.get("title", "N/A"),
                "severity": a.get("severity", "N/A")
            }
            for a in alerts[:50]
        ]
    
    def _calculate_detection_rate(self, iocs: List[Dict]) -> float:
        """Calculate IOC detection rate."""
        if not iocs:
            return 0.0
        detected = sum(1 for ioc in iocs if ioc.get("detected", False))
        return (detected / len(iocs)) * 100 if iocs else 0.0
    
    def export_report(self, report: Dict, format: str = "json") -> str:
        """Export report in specified format."""
        if format == "json":
            return json.dumps(report, indent=2)
        elif format == "html":
            return self._convert_to_html(report)
        elif format == "txt":
            return self._convert_to_txt(report)
        else:
            return str(report)
    
    def _convert_to_html(self, report: Dict) -> str:
        """Convert report to HTML."""
        html = f"""
        <html>
            <head><title>{report.get('report_id', 'Report')}</title></head>
            <body>
                <h1>{report.get('report_id', 'Report')}</h1>
                <p>Generated: {report.get('generated_at')}</p>
                <pre>{json.dumps(report, indent=2)}</pre>
            </body>
        </html>
        """
        return html
    
    def _convert_to_txt(self, report: Dict) -> str:
        """Convert report to plain text."""
        lines = [
            f"{'='*50}",
            f"Report: {report.get('report_id', 'Report')}",
            f"Generated: {report.get('generated_at')}",
            f"{'='*50}",
            json.dumps(report, indent=2)
        ]
        return "\n".join(lines)
