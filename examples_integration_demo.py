#!/usr/bin/env python3
"""
LogSentinel Pro v4.0 - Integration Example & Usage Guide
Demonstrates complete platform usage
"""

import sys
from pathlib import Path

# Add engines to path
sys.path.append(str(Path(__file__).parent / "src/engines"))

def example_complete_workflow():
    """Complete end-to-end workflow example."""
    
    print("="*80)
    print("LogSentinel Pro v4.0 - Complete Integration Example")
    print("="*80)
    
    # Import all engines
    from security_orchestrator import SecurityAnalyticsPlatform, RealTimeSecurityDashboard
    from log_classifier import LogClassifier, RiskLevel
    from alert_manager import AlertManager, AlertSeverity
    from attack_replay import AttackReplaySystem
    from live_report_generator import LiveReportGenerator
    from anomaly_detector_advanced import AnomalyDetectionOrchestrator
    
    # Initialize platform
    print("\n[1] Initializing Security Analytics Platform...")
    platform = SecurityAnalyticsPlatform()
    print(f"    Status: {platform.platform_status}")
    
    # Example log entries
    print("\n[2] Processing log stream...")
    log_entries = [
        "[SSH] Failed password for invalid user from 192.168.1.100 port 22 ssh2",
        "[HTTPD] 192.168.1.100 - - [06/Apr/2026:10:15:30] GET /admin.php HTTP/1.1 403 1234",
        "[SECURITY] SQL injection attempt detected in query parameter: ' OR '1'='1",
        "[NETWORK] Connection refused from 10.0.0.50 port 4444",
        "[SYSTEM] Kernel panic - not syncing: out of memory",
        "[AUTH] Failed sudo attempt by user 'apache' for command '/bin/rm'",
        "[FIREWALL] 185.220.101.182 TCP connection BLOCKED port 22",
        "[DATABASE] MySQL error 1064: You have an error in your SQL syntax",
        "[SECURITY] Malware hash detected: 5d41402abc4b2a76b9719d911017c592 (Emotet trojan)",
        "[NETWORK] Port scan detected: 1.2.3.4 scanning ports 20-65535"
    ]
    
    result = platform.process_log_stream(log_entries)
    
    print(f"    ├─ Total logs processed: {result['total_logs_processed']}")
    print(f"    ├─ Classifications: {len(result['classifications'])}")
    print(f"    ├─ Anomalies detected: {len(result['anomalies_detected'])}")
    print(f"    ├─ Alerts generated: {len(result['alerts_generated'])}")
    print(f"    └─ Attacks detected: {len(result['attacks_detected'])}")
    
    # Display sample classifications
    print("\n[3] Sample Log Classifications:")
    for i, classification in enumerate(result['classifications'][:3]):
        print(f"    [{i+1}] {classification['log_type']} (Risk: {classification['risk_level']})")
        print(f"        └─ Risk Factors: {', '.join(classification['risk_factors']) if classification['risk_factors'] else 'None'}")
    
    # Display anomalies detected
    print("\n[4] Anomalies Detected:")
    for i, anomaly in enumerate(result['anomalies_detected'][:2]):
        print(f"    [{i+1}] {anomaly['metric']} = {anomaly['value']}")
        print(f"        └─ Consensus: {anomaly['consensus']['anomaly_votes']}/{anomaly['consensus']['total_algorithms']} algorithms flagged")
        print(f"        └─ Confidence: {anomaly['ensemble_confidence']:.2%}")
    
    # Display generated alerts
    print("\n[5] Security Alerts Generated:")
    for i, alert in enumerate(result['alerts_generated'][:3]):
        print(f"    [{i+1}] [{alert['severity']}] {alert['title']}")
        print(f"        └─ Source: {alert['source']}")
        print(f"        └─ Risk Factors: {', '.join(alert['risk_factors'])}")
    
    # Get system health
    print("\n[6] Platform Health Metrics:")
    health = platform.get_system_health()
    print(f"    ├─ Status: {health['platform_status']}")
    print(f"    ├─ Total Logs Processed: {health['logs_processed']}")
    print(f"    ├─ Total Anomalies: {health['anomalies_detected']}")
    print(f"    ├─ Active Alerts: {health['alerts_active']}")
    print(f"    ├─ Attack Statistics:")
    
    if health['attack_stats']:
        print(f"    │   ├─ Total Recorded: {health['attack_stats'].get('total_attacks', 0)}")
        print(f"    │   ├─ Active Attacks: {health['attack_stats'].get('active_attacks', 0)}")
        print(f"    │   └─ Event Types: {list(health['attack_stats'].get('attack_types', {}).keys())}")
    
    # Generate live dashboard data
    print("\n[7] Real-Time Dashboard Data:")
    dashboard = RealTimeSecurityDashboard(platform)
    dashboard_data = dashboard.get_dashboard_data()
    
    metrics = dashboard_data['live_metrics']
    print(f"    ├─ System Status: {metrics['system_status']}")
    print(f"    ├─ Anomaly Rate: {metrics['anomaly_rate']:.2%}")
    print(f"    ├─ Alert Density: {metrics['alert_density']:.4f}")
    
    if dashboard_data['top_threats']:
        print(f"    └─ Top Threats: {len(dashboard_data['top_threats'])} active")
        for threat in dashboard_data['top_threats'][:2]:
            print(f"        └─ {threat['title']} [{threat['severity']}]")
    
    # Generate executive summary report
    print("\n[8] Executive Summary Report:")
    report = platform.generate_comprehensive_report()
    
    print(f"    ├─ Report ID: {report['report_id']}")
    print(f"    ├─ Period: {report['period']}")
    print(f"    ├─ Overall Risk Posture: {report['summary']['overall_risk_posture']}")
    print(f"    ├─ Threat Level: {report['threat_level']}")
    print(f"    ├─ Total Events: {report['summary']['total_events_processed']}")
    print(f"    ├─ Critical Alerts: {report['summary']['critical_alerts']}")
    print(f"    ├─ Active Attacks: {report['summary']['active_attack_count']}")
    
    if report.get('critical_findings'):
        print(f"    └─ Critical Findings ({len(report['critical_findings'])}): ")
        for finding in report['critical_findings'][:2]:
            print(f"        └─ {finding}")
    
    # Display recommendations
    if report.get('recommendations'):
        print(f"\n[9] Recommendations ({len(report['recommendations'])}):")
        for i, rec in enumerate(report['recommendations'][:3], 1):
            print(f"    [{i}] {rec}")
    
    print("\n" + "="*80)
    print("Integration Example Complete")
    print("="*80)


def example_anomaly_detection_details():
    """Show detailed anomaly detection workflow."""
    
    print("\n" + "="*80)
    print("Example: Advanced Anomaly Detection Pipeline")
    print("="*80)
    
    from anomaly_detector_advanced import AnomalyDetectionOrchestrator
    
    orchestrator = AnomalyDetectionOrchestrator()
    
    # Simulate metric values
    baseline_values = [50, 52, 48, 51, 49, 50, 52, 48, 51, 49]
    anomalous_value = 150  # Clear anomaly
    
    print("\n[1] Analyzing Metric: 'request_latency_ms'")
    print(f"    Baseline (10 samples): {baseline_values}")
    print(f"    Current Value: {anomalous_value}ms")
    
    # Run analysis
    result = orchestrator.analyze_metric("request_latency_ms", anomalous_value, baseline_values)
    
    # Display results from each algorithm
    print("\n[2] Algorithm Consensus Results:")
    
    for algo_name, algo_result in result['algorithms'].items():
        print(f"\n    {algo_name.upper()}:")
        print(f"    ├─ Anomaly: {algo_result.get('anomaly', False)}")
        print(f"    ├─ Confidence: {algo_result.get('confidence', 0):.2%}")
        
        if algo_name == "z_score":
            print(f"    ├─ Z-Score: {algo_result.get('z_score', 0):.2f}")
            print(f"    ├─ Threshold: {algo_result.get('threshold', 0):.2f}")
            print(f"    └─ Mean: {algo_result.get('mean', 0):.2f}")
        
        elif algo_name == "iqr":
            print(f"    ├─ Lower Bound: {algo_result.get('lower_bound', 0):.2f}")
            print(f"    ├─ Upper Bound: {algo_result.get('upper_bound', 0):.2f}")
            print(f"    └─ IQR: {algo_result.get('iqr', 0):.2f}")
        
        elif algo_name == "mad":
            print(f"    ├─ Median: {algo_result.get('median', 0):.2f}")
            print(f"    ├─ MAD: {algo_result.get('mad', 0):.2f}")
            print(f"    └─ Modified Z-Score: {algo_result.get('modified_z_score', 0):.2f}")
    
    # Display consensus
    print(f"\n[3] Ensemble Consensus:")
    consensus = result['consensus']
    print(f"    ├─ Votes for Anomaly: {consensus['anomaly_votes']}/{consensus['total_algorithms']}")
    print(f"    ├─ Consensus %: {consensus['consensus_percentage']:.1f}%")
    print(f"    ├─ Final Verdict: {'ANOMALY DETECTED' if result['ensemble_anomaly'] else 'NORMAL'}")
    print(f"    └─ Overall Confidence: {result['ensemble_confidence']:.2%}")
    
    if result['consensus'].get('algorithms_flagged'):
        print(f"\n    Algorithms that flagged anomaly:")
        for algo in result['consensus']['algorithms_flagged']:
            print(f"    └─ {algo.upper()}")
    
    print("\n" + "="*80)


def example_alert_management():
    """Show alert management workflow."""
    
    print("\n" + "="*80)
    print("Example: Alert Management & Response")
    print("="*80)
    
    from alert_manager import AlertManager, AlertSeverity, AlertStatus
    
    alert_manager = AlertManager()
    
    print("\n[1] Creating Critical Security Alerts...")
    
    # Create multiple alerts
    alerts = []
    
    alert1 = alert_manager.create_alert(
        severity=AlertSeverity.CRITICAL,
        title="SQL Injection Attack Detected",
        description="Malicious SQL payload detected in HTTP request parameter",
        source="WEB_SERVER",
        affected_host="web-server-01",
        risk_factors=["SQL Injection", "Web Application Attack", "Database Access"]
    )
    alerts.append(alert1)
    
    alert2 = alert_manager.create_alert(
        severity=AlertSeverity.HIGH,
        title="Brute Force Attack in Progress",
        description="Multiple failed login attempts from 192.168.1.100",
        source="AUTHENTICATION",
        affected_host="prod-auth-01",
        risk_factors=["Brute Force", "Failed Login Attempts"]
    )
    alerts.append(alert2)
    
    alert3 = alert_manager.create_alert(
        severity=AlertSeverity.MEDIUM,
        title="Privilege Escalation Attempt",
        description="User apache attempted sudo command execution",
        source="SYSTEM",
        affected_host="app-server-02",
        risk_factors=["Privilege Escalation", "Sudo Access"]
    )
    alerts.append(alert3)
    
    print(f"    Created {len(alerts)} alerts")
    
    # Get alert summary
    print("\n[2] Alert Summary:")
    summary = alert_manager.get_alert_summary()
    
    print(f"    Total Alerts: {summary['total_alerts']}")
    print(f"    ├─ By Severity:")
    for severity, count in summary['by_severity'].items():
        print(f"    │   ├─ {severity}: {count}")
    print(f"    └─ By Status:")
    for status, count in summary['by_status'].items():
        print(f"        └─ {status}: {count}")
    
    # Acknowledge first alert
    print("\n[3] Alert Response Actions:")
    alert_manager.acknowledge_alert(alert1.alert_id, "analyst_john")
    print(f"    ├─ Acknowledged: {alert1.alert_id}")
    
    # Escalate second alert
    alert_manager.escalate_alert(alert2.alert_id)
    print(f"    ├─ Escalated: {alert2.alert_id}")
    
    # Resolve third alert
    alert_manager.resolve_alert(alert3.alert_id)
    print(f"    └─ Resolved: {alert3.alert_id}")
    
    # Get critical alerts
    print("\n[4] Critical Alerts (Last 24 hours):")
    critical_alerts = alert_manager.get_critical_alerts(hours=24)
    for i, alert in enumerate(critical_alerts[:2], 1):
        print(f"    [{i}] {alert.title}")
        print(f"        ├─ Severity: {alert.severity}")
        print(f"        ├─ Host: {alert.affected_host}")
        print(f"        └─ Status: {alert.status}")
    
    print("\n" + "="*80)


def example_attack_replay():
    """Show attack sequence detection and replay."""
    
    print("\n" + "="*80)
    print("Example: Attack Sequence Detection & Live Replay")
    print("="*80)
    
    from attack_replay import AttackReplaySystem
    
    replay_system = AttackReplaySystem()
    
    print("\n[1] Simulating Attack Sequence Events...")
    
    # Event 1: Reconnaissance
    seq1 = replay_system.detect_attack_sequence(
        event_type="port_scan",
        source_ip="1.2.3.4",
        destination_ip="prod-web-01",
        port=22,
        severity="MEDIUM",
        description="Port 22 discovered during reconnaissance scan"
    )
    print(f"    ├─ Event 1: Port Scan -> Sequence {seq1}")
    
    # Event 2: Credential attack
    seq2 = replay_system.detect_attack_sequence(
        event_type="brute_force",
        source_ip="1.2.3.4",
        destination_ip="prod-web-01",
        port=22,
        severity="HIGH",
        description="SSH brute force attempt (50 failed logins in 5 minutes)",
        payload={"attempts": 50, "protocol": "SSH"}
    )
    print(f"    ├─ Event 2: Brute Force -> Sequence {seq2}")
    
    # Event 3: Exploitation
    seq3 = replay_system.detect_attack_sequence(
        event_type="privilege_escalation",
        source_ip="1.2.3.4",
        destination_ip="prod-web-01",
        port=22,
        severity="CRITICAL",
        description="Successful privilege escalation via sudo vulnerability"
    )
    print(f"    ├─ Event 3: Privilege Escalation -> Sequence {seq3}")
    
    # Event 4: Data exfiltration
    seq4 = replay_system.detect_attack_sequence(
        event_type="data_exfiltration",
        source_ip="1.2.3.4",
        destination_ip="prod-web-01",
        port=443,
        severity="CRITICAL",
        description="Large data transfer to external IP 198.51.100.1"
    )
    print(f"    └─ Event 4: Data Exfiltration -> Sequence {seq4}")
    
    # Get active attacks
    print("\n[2] Active Attack Sequences:")
    active_attacks = replay_system.get_active_attacks()
    
    for attack in active_attacks:
        print(f"\n    Attack: {attack.attack_name}")
        print(f"    ├─ ID: {attack.sequence_id}")
        print(f"    ├─ Type: {attack.attack_type}")
        print(f"    ├─ Severity: {attack.severity}")
        print(f"    ├─ Start Time: {attack.start_time}")
        print(f"    ├─ Events: {len(attack.events)}")
        print(f"    ├─ Sources: {', '.join(attack.source_ips)}")
        print(f"    └─ Targets: {', '.join(attack.target_hosts)}")
    
    # Conclude attack
    if active_attacks:
        attack_id = active_attacks[0].sequence_id
        replay_system.conclude_sequence(attack_id, status="contained")
        print(f"\n    Concluded attack sequence: {attack_id}")
    
    # Get statistics
    print("\n[3] Attack Statistics:")
    stats = replay_system.get_attack_statistics()
    print(f"    ├─ Total Attacks: {stats['total_attacks']}")
    print(f"    ├─ Active: {stats['active_attacks']}")
    print(f"    ├─ Concluded: {stats['concluded_attacks']}")
    print(f"    ├─ Total Events: {stats['total_events_recorded']}")
    print(f"    ├─ Avg Events/Attack: {stats['avg_events_per_attack']:.1f}")
    print(f"    └─ Attack Types: {stats['attack_types']}")
    
    print("\n" + "="*80)


def main():
    """Run all examples."""
    print("\n")
    print("╔" + "="*78 + "╗")
    print("║" + " "*78 + "║")
    print("║" + "LogSentinel Pro v4.0 - Complete Platform Demonstration".center(78) + "║")
    print("║" + "Enterprise SIEM with Advanced Anomaly Detection".center(78) + "║")
    print("║" + " "*78 + "║")
    print("╚" + "="*78 + "╝")
    
    try:
        example_complete_workflow()
        example_anomaly_detection_details()
        example_alert_management()
        example_attack_replay()
        
        print("\n" + "="*80)
        print("All Examples Completed Successfully!")
        print("="*80 + "\n")
        
    except Exception as e:
        print(f"\nError during example execution: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
