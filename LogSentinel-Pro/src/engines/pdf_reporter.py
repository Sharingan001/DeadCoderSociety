#!/usr/bin/env python3
"""
PDF Report Generator for LogSentinel Pro v3.0
Generate comprehensive threat analysis reports with charts and visualizations
"""

import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import base64
import io

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
    from reportlab.platypus import Image as RLImage
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.graphics.shapes import Drawing, Rect, String
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    from reportlab.graphics.charts.linecharts import HorizontalLineChart
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

try:
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
    from matplotlib.patches import Wedge
    import numpy as np
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False


class ThreatAnalysisReporter:
    """Generate comprehensive PDF reports for threat analysis."""
    
    def __init__(self):
        self.styles = getSampleStyleSheet() if REPORTLAB_AVAILABLE else None
        self.custom_styles = self._create_custom_styles() if REPORTLAB_AVAILABLE else None
    
    def _create_custom_styles(self):
        """Create custom paragraph styles."""
        if not REPORTLAB_AVAILABLE:
            return None
        
        styles = {}
        
        # Title style
        styles['CustomTitle'] = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Title'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.darkblue,
            alignment=1  # Center
        )
        
        # Heading styles
        styles['CustomHeading1'] = ParagraphStyle(
            'CustomHeading1',
            parent=self.styles['Heading1'],
            fontSize=16,
            spaceAfter=12,
            textColor=colors.darkred,
            borderWidth=1,
            borderColor=colors.lightgrey,
            borderPadding=5
        )
        
        styles['CustomHeading2'] = ParagraphStyle(
            'CustomHeading2',
            parent=self.styles['Heading2'],
            fontSize=14,
            spaceAfter=10,
            textColor=colors.darkblue
        )
        
        # Executive summary style
        styles['ExecutiveSummary'] = ParagraphStyle(
            'ExecutiveSummary',
            parent=self.styles['Normal'],
            fontSize=12,
            leftIndent=20,
            rightIndent=20,
            spaceAfter=12,
            backColor=colors.lightblue,
            borderWidth=1,
            borderColor=colors.blue,
            borderPadding=10
        )
        
        # Alert style for high-risk items
        styles['HighRiskAlert'] = ParagraphStyle(
            'HighRiskAlert',
            parent=self.styles['Normal'],
            fontSize=11,
            textColor=colors.darkred,
            backColor=colors.mistyrose,
            borderWidth=2,
            borderColor=colors.red,
            borderPadding=8
        )
        
        return styles
    
    def generate_threat_report(self, analysis_results: Dict, scan_metadata: Dict, 
                             output_path: str = None) -> str:
        """Generate comprehensive threat analysis PDF report."""
        if not REPORTLAB_AVAILABLE:
            return self._generate_text_report(analysis_results, scan_metadata, output_path)
        
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"threat_analysis_report_{timestamp}.pdf"
        
        # Create PDF document
        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            rightMargin=inch,
            leftMargin=inch,
            topMargin=inch,
            bottomMargin=inch
        )
        
        # Build report content
        story = []
        
        # Title page
        story.extend(self._create_title_page(analysis_results, scan_metadata))
        story.append(PageBreak())
        
        # Executive summary
        story.extend(self._create_executive_summary(analysis_results))
        story.append(PageBreak())
        
        # Threat intelligence findings
        story.extend(self._create_threat_intel_section(analysis_results))
        
        # Anomaly detection results
        story.extend(self._create_anomaly_section(analysis_results))
        
        # Attack chain analysis
        story.extend(self._create_attack_chain_section(analysis_results))
        
        # Risk assessment and recommendations
        story.extend(self._create_recommendations_section(analysis_results))
        
        # Technical appendix
        story.append(PageBreak())
        story.extend(self._create_technical_appendix(analysis_results, scan_metadata))
        
        # Build PDF
        doc.build(story)
        
        return output_path
    
    def _create_title_page(self, results: Dict, metadata: Dict) -> List:
        """Create report title page."""
        story = []
        
        # Main title
        title = Paragraph("LogSentinel Pro v3.0<br/>Threat Analysis Report", 
                         self.custom_styles['CustomTitle'])
        story.append(title)
        story.append(Spacer(1, 0.5*inch))
        
        # Report metadata table
        report_data = [
            ['Report Generated:', datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")],
            ['Analysis Period:', metadata.get('scan_time', 'Unknown')],
            ['Scanned Files:', str(metadata.get('files_scanned', 'Unknown'))],
            ['Events Analyzed:', str(metadata.get('events_analyzed', 'Unknown'))],
            ['Risk Score:', f"{results.get('risk_score', 0)}/100"],
            ['Classification:', self._get_risk_classification(results.get('risk_score', 0))]
        ]
        
        report_table = Table(report_data, colWidths=[2*inch, 3*inch])
        report_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(report_table)
        story.append(Spacer(1, 0.5*inch))
        
        # Risk score visualization
        if MATPLOTLIB_AVAILABLE:
            risk_chart = self._create_risk_gauge(results.get('risk_score', 0))
            story.append(risk_chart)
        
        return story
    
    def _create_executive_summary(self, results: Dict) -> List:
        """Create executive summary section."""
        story = []
        
        story.append(Paragraph("Executive Summary", self.custom_styles['CustomHeading1']))
        
        # Summary statistics
        total_threats = len(results.get('intelligence_matches', []))
        total_anomalies = len(results.get('anomalies', []))
        total_chains = len(results.get('attack_chains', []))
        risk_score = results.get('risk_score', 0)
        
        summary_text = f"""
        This automated threat analysis identified <b>{total_threats}</b> threat intelligence matches, 
        <b>{total_anomalies}</b> behavioral anomalies, and <b>{total_chains}</b> potential attack chains.
        
        The overall risk score of <b>{risk_score}/100</b> indicates a 
        <b>{self._get_risk_classification(risk_score).upper()}</b> security posture requiring 
        {self._get_response_urgency(risk_score)} attention.
        """
        
        if risk_score >= 80:
            summary_text += """
            
            <b>CRITICAL FINDINGS:</b> Immediate security response required. Multiple high-confidence 
            threats detected with evidence of coordinated attack activity.
            """
        
        story.append(Paragraph(summary_text, self.custom_styles['ExecutiveSummary']))
        story.append(Spacer(1, 0.3*inch))
        
        # Key findings summary table
        if total_threats > 0 or total_anomalies > 0 or total_chains > 0:
            findings_data = [['Finding Type', 'Count', 'Highest Severity']]
            
            if total_threats > 0:
                highest_threat_severity = max(
                    [match.get('threat_data', {}).get('severity', 'low') 
                     for match in results.get('intelligence_matches', [])],
                    key=lambda x: {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}.get(x, 0)
                )
                findings_data.append(['Threat Intelligence', str(total_threats), highest_threat_severity.title()])
            
            if total_anomalies > 0:
                highest_anomaly_severity = max(
                    [anomaly.get('severity', 'low') for anomaly in results.get('anomalies', [])],
                    key=lambda x: {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}.get(x, 0)
                )
                findings_data.append(['Behavioral Anomalies', str(total_anomalies), highest_anomaly_severity.title()])
            
            if total_chains > 0:
                highest_chain_severity = max(
                    [chain.get('severity', 'low') for chain in results.get('attack_chains', [])],
                    key=lambda x: {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}.get(x, 0)
                )
                findings_data.append(['Attack Chains', str(total_chains), highest_chain_severity.title()])
            
            findings_table = Table(findings_data, colWidths=[2*inch, 1*inch, 1.5*inch])
            findings_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkgrey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(findings_table)
        
        return story
    
    def _create_threat_intel_section(self, results: Dict) -> List:
        """Create threat intelligence findings section."""
        story = []
        
        story.append(Paragraph("Threat Intelligence Findings", self.custom_styles['CustomHeading1']))
        
        intel_matches = results.get('intelligence_matches', [])
        
        if not intel_matches:
            story.append(Paragraph("No threat intelligence matches identified.", self.styles['Normal']))
            story.append(Spacer(1, 0.2*inch))
            return story
        
        # Group by severity
        by_severity = {'critical': [], 'high': [], 'medium': [], 'low': []}
        for match in intel_matches:
            severity = match.get('threat_data', {}).get('severity', 'low')
            by_severity[severity].append(match)
        
        for severity in ['critical', 'high', 'medium', 'low']:
            if by_severity[severity]:
                story.append(Paragraph(f"{severity.title()} Severity Threats", 
                                     self.custom_styles['CustomHeading2']))
                
                for match in by_severity[severity]:
                    indicator = match['indicator']
                    threat_data = match['threat_data']
                    
                    threat_text = f"""
                    <b>Indicator:</b> {indicator} ({match['indicator_type']})<br/>
                    <b>Threat Type:</b> {threat_data.get('type', 'Unknown')}<br/>
                    <b>Source:</b> {threat_data.get('source', 'Unknown')}<br/>
                    <b>Context:</b> {threat_data.get('description', 'No additional context')}
                    """
                    
                    if severity in ['critical', 'high']:
                        story.append(Paragraph(threat_text, self.custom_styles['HighRiskAlert']))
                    else:
                        story.append(Paragraph(threat_text, self.styles['Normal']))
                    
                    story.append(Spacer(1, 0.1*inch))
        
        return story
    
    def _create_anomaly_section(self, results: Dict) -> List:
        """Create anomaly detection section."""
        story = []
        
        story.append(Paragraph("Behavioral Anomaly Analysis", self.custom_styles['CustomHeading1']))
        
        anomalies = results.get('anomalies', [])
        
        if not anomalies:
            story.append(Paragraph("No significant behavioral anomalies detected.", self.styles['Normal']))
            story.append(Spacer(1, 0.2*inch))
            return story
        
        # Anomalies summary table
        anomaly_data = [['Type', 'Description', 'Severity', 'Confidence', 'MITRE Technique']]
        
        for anomaly in anomalies:
            anomaly_data.append([
                anomaly.get('type', 'Unknown').replace('_', ' ').title(),
                anomaly.get('description', 'No description')[:50] + '...' if len(anomaly.get('description', '')) > 50 else anomaly.get('description', 'No description'),
                anomaly.get('severity', 'low').title(),
                f"{anomaly.get('confidence', 0)*100:.0f}%",
                anomaly.get('mitre_technique', 'N/A')
            ])
        
        anomaly_table = Table(anomaly_data, colWidths=[1.5*inch, 2.5*inch, 0.8*inch, 0.8*inch, 1*inch])
        anomaly_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkred),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightpink),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP')
        ]))
        
        story.append(anomaly_table)
        story.append(Spacer(1, 0.3*inch))
        
        return story
    
    def _create_attack_chain_section(self, results: Dict) -> List:
        """Create attack chain analysis section."""
        story = []
        
        story.append(Paragraph("Attack Chain Analysis", self.custom_styles['CustomHeading1']))
        
        attack_chains = results.get('attack_chains', [])
        
        if not attack_chains:
            story.append(Paragraph("No coordinated attack chains identified.", self.styles['Normal']))
            story.append(Spacer(1, 0.2*inch))
            return story
        
        for i, chain in enumerate(attack_chains, 1):
            story.append(Paragraph(f"Attack Chain #{i}: {chain.get('attack_type', 'Unknown').replace('_', ' ').title()}", 
                                 self.custom_styles['CustomHeading2']))
            
            # Chain summary
            chain_summary = f"""
            <b>Attacker:</b> {chain.get('attacker', 'Unknown')}<br/>
            <b>Severity:</b> {chain.get('severity', 'low').title()}<br/>
            <b>Duration:</b> {chain.get('duration', 'Unknown')}<br/>
            <b>Confidence:</b> {chain.get('confidence', 0)*100:.0f}%<br/>
            <b>Phases:</b> {len(chain.get('phases', []))}
            """
            
            if chain.get('severity') in ['critical', 'high']:
                story.append(Paragraph(chain_summary, self.custom_styles['HighRiskAlert']))
            else:
                story.append(Paragraph(chain_summary, self.styles['Normal']))
            
            # Phases table
            phases = chain.get('phases', [])
            if phases:
                phase_data = [['Phase', 'Start Time', 'End Time', 'Events', 'Techniques']]
                
                for phase in phases:
                    techniques = ', '.join(set(phase.get('techniques', []))) or 'N/A'
                    phase_data.append([
                        phase.get('phase', 'Unknown').replace('_', ' ').title(),
                        phase.get('start_time', 'N/A'),
                        phase.get('end_time', 'N/A'), 
                        str(len(phase.get('events', []))),
                        techniques[:30] + '...' if len(techniques) > 30 else techniques
                    ])
                
                phase_table = Table(phase_data, colWidths=[1.2*inch, 1.2*inch, 1.2*inch, 0.6*inch, 1.5*inch])
                phase_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.navy),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.lightblue),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                
                story.append(phase_table)
            
            story.append(Spacer(1, 0.2*inch))
        
        return story
    
    def _create_recommendations_section(self, results: Dict) -> List:
        """Create recommendations and next steps section."""
        story = []
        
        story.append(Paragraph("Risk Assessment & Recommendations", self.custom_styles['CustomHeading1']))
        
        risk_score = results.get('risk_score', 0)
        recommendations = self._generate_recommendations(results)
        
        # Risk assessment
        risk_assessment = f"""
        <b>Current Risk Level:</b> {self._get_risk_classification(risk_score).upper()}<br/>
        <b>Risk Score:</b> {risk_score}/100<br/>
        <b>Recommended Response Time:</b> {self._get_response_urgency(risk_score)}
        """
        
        story.append(Paragraph(risk_assessment, self.custom_styles['ExecutiveSummary']))
        story.append(Spacer(1, 0.2*inch))
        
        # Recommendations
        story.append(Paragraph("Immediate Actions Required:", self.custom_styles['CustomHeading2']))
        
        for i, rec in enumerate(recommendations['immediate'], 1):
            story.append(Paragraph(f"{i}. {rec}", self.styles['Normal']))
        
        story.append(Spacer(1, 0.2*inch))
        story.append(Paragraph("Strategic Improvements:", self.custom_styles['CustomHeading2']))
        
        for i, rec in enumerate(recommendations['strategic'], 1):
            story.append(Paragraph(f"{i}. {rec}", self.styles['Normal']))
        
        return story
    
    def _create_technical_appendix(self, results: Dict, metadata: Dict) -> List:
        """Create technical appendix with detailed data."""
        story = []
        
        story.append(Paragraph("Technical Appendix", self.custom_styles['CustomHeading1']))
        
        # Analysis metadata
        story.append(Paragraph("Analysis Configuration", self.custom_styles['CustomHeading2']))
        
        config_data = [
            ['Parameter', 'Value'],
            ['Analysis Engine', 'LogSentinel Pro Advanced Detection v3.0'],
            ['ML Models', 'Behavioral Analysis, Anomaly Detection'],
            ['Threat Intelligence', 'Internal IOC Database + Behavioral Heuristics'],
            ['Correlation Window', '24 hours'],
            ['Events Buffer Size', '10,000 events'],
            ['Confidence Threshold', '0.7 (70%)']
        ]
        
        config_table = Table(config_data, colWidths=[2*inch, 3*inch])
        config_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(config_table)
        story.append(Spacer(1, 0.3*inch))
        
        # Raw analysis results (truncated)
        story.append(Paragraph("Raw Analysis Data (Sample)", self.custom_styles['CustomHeading2']))
        raw_data = json.dumps(results, indent=2)[:2000] + "\n\n... (truncated for readability)"
        story.append(Paragraph(f"<pre>{raw_data}</pre>", self.styles['Code']))
        
        return story
    
    def _create_risk_gauge(self, risk_score: int):
        """Create risk score gauge chart."""
        if not MATPLOTLIB_AVAILABLE:
            return Spacer(1, 0.1*inch)
        
        # Create matplotlib figure
        fig, ax = plt.subplots(figsize=(6, 3))
        
        # Create gauge segments
        colors_list = ['green', 'yellow', 'orange', 'red']
        segments = [25, 25, 25, 25]
        
        # Draw gauge
        wedges = []
        start_angle = 180
        for i, (segment, color) in enumerate(zip(segments, colors_list)):
            wedge = Wedge((0, 0), 1, start_angle, start_angle + segment * 1.8, 
                         facecolor=color, alpha=0.7)
            ax.add_patch(wedge)
            start_angle += segment * 1.8
        
        # Add needle for current risk score
        angle = 180 + (risk_score / 100) * 180
        needle_x = 0.8 * np.cos(np.radians(angle))
        needle_y = 0.8 * np.sin(np.radians(angle))
        ax.arrow(0, 0, needle_x, needle_y, head_width=0.05, head_length=0.1, 
                fc='black', ec='black', linewidth=3)
        
        # Labels
        ax.text(0, -0.3, f"Risk Score: {risk_score}/100", ha='center', fontsize=14, fontweight='bold')
        ax.text(-0.9, 0, "0", ha='center', fontsize=10)
        ax.text(0, 1.1, "50", ha='center', fontsize=10)
        ax.text(0.9, 0, "100", ha='center', fontsize=10)
        
        ax.set_xlim(-1.2, 1.2)
        ax.set_ylim(-0.5, 1.2)
        ax.set_aspect('equal')
        ax.axis('off')
        
        plt.title('Risk Assessment Gauge', fontsize=16, fontweight='bold')
        
        # Save to memory and convert to ReportLab Image
        img_buffer = io.BytesIO()
        plt.savefig(img_buffer, format='png', bbox_inches='tight', dpi=150)
        img_buffer.seek(0)
        plt.close()
        
        # Convert to ReportLab Image
        img = RLImage(img_buffer, width=4*inch, height=2*inch)
        return img
    
    def _generate_text_report(self, results: Dict, metadata: Dict, output_path: str = None) -> str:
        """Generate text-based report when PDF libraries unavailable."""
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"threat_analysis_report_{timestamp}.txt"
        
        report_lines = []
        report_lines.append("="*80)
        report_lines.append("LogSentinel Pro v3.0 - Threat Analysis Report")
        report_lines.append("="*80)
        report_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        report_lines.append(f"Risk Score: {results.get('risk_score', 0)}/100")
        report_lines.append(f"Classification: {self._get_risk_classification(results.get('risk_score', 0))}")
        report_lines.append("")
        
        # Executive Summary
        report_lines.append("EXECUTIVE SUMMARY")
        report_lines.append("-" * 40)
        total_threats = len(results.get('intelligence_matches', []))
        total_anomalies = len(results.get('anomalies', []))
        total_chains = len(results.get('attack_chains', []))
        
        report_lines.append(f"Threat Intelligence Matches: {total_threats}")
        report_lines.append(f"Behavioral Anomalies: {total_anomalies}")
        report_lines.append(f"Attack Chains: {total_chains}")
        report_lines.append("")
        
        # Threat Intelligence
        if results.get('intelligence_matches'):
            report_lines.append("THREAT INTELLIGENCE FINDINGS")
            report_lines.append("-" * 40)
            for match in results['intelligence_matches']:
                report_lines.append(f"Indicator: {match['indicator']} ({match['indicator_type']})")
                threat_data = match['threat_data']
                report_lines.append(f"  Type: {threat_data.get('type', 'Unknown')}")
                report_lines.append(f"  Severity: {threat_data.get('severity', 'low')}")
                report_lines.append(f"  Source: {threat_data.get('source', 'Unknown')}")
                report_lines.append("")
        
        # Anomalies
        if results.get('anomalies'):
            report_lines.append("BEHAVIORAL ANOMALIES")
            report_lines.append("-" * 40)
            for anomaly in results['anomalies']:
                report_lines.append(f"Type: {anomaly.get('type', 'Unknown')}")
                report_lines.append(f"  Description: {anomaly.get('description', 'No description')}")
                report_lines.append(f"  Severity: {anomaly.get('severity', 'low')}")
                report_lines.append(f"  Confidence: {anomaly.get('confidence', 0)*100:.0f}%")
                if 'mitre_technique' in anomaly:
                    report_lines.append(f"  MITRE Technique: {anomaly['mitre_technique']}")
                report_lines.append("")
        
        # Attack Chains
        if results.get('attack_chains'):
            report_lines.append("ATTACK CHAIN ANALYSIS")
            report_lines.append("-" * 40)
            for i, chain in enumerate(results['attack_chains'], 1):
                report_lines.append(f"Chain #{i}: {chain.get('attack_type', 'Unknown')}")
                report_lines.append(f"  Attacker: {chain.get('attacker', 'Unknown')}")
                report_lines.append(f"  Severity: {chain.get('severity', 'low')}")
                report_lines.append(f"  Duration: {chain.get('duration', 'Unknown')}")
                report_lines.append(f"  Confidence: {chain.get('confidence', 0)*100:.0f}%")
                report_lines.append(f"  Phases: {len(chain.get('phases', []))}")
                report_lines.append("")
        
        with open(output_path, 'w') as f:
            f.write('\n'.join(report_lines))
        
        return output_path
    
    def _get_risk_classification(self, risk_score: int) -> str:
        """Get risk classification from score."""
        if risk_score >= 80:
            return "critical"
        elif risk_score >= 60:
            return "high"
        elif risk_score >= 40:
            return "medium"
        elif risk_score >= 20:
            return "low"
        else:
            return "minimal"
    
    def _get_response_urgency(self, risk_score: int) -> str:
        """Get recommended response urgency."""
        if risk_score >= 80:
            return "IMMEDIATE (within 1 hour)"
        elif risk_score >= 60:
            return "urgent (within 4 hours)"
        elif risk_score >= 40:
            return "standard (within 24 hours)"
        else:
            return "routine (within 1 week)"
    
    def _generate_recommendations(self, results: Dict) -> Dict:
        """Generate actionable recommendations."""
        recommendations = {
            'immediate': [],
            'strategic': []
        }
        
        risk_score = results.get('risk_score', 0)
        intel_matches = results.get('intelligence_matches', [])
        anomalies = results.get('anomalies', [])
        attack_chains = results.get('attack_chains', [])
        
        # Immediate actions based on findings
        if intel_matches:
            recommendations['immediate'].append(
                "Block or quarantine all identified malicious indicators (IPs, domains, hashes)"
            )
        
        if attack_chains:
            recommendations['immediate'].append(
                "Initiate incident response procedures for identified attack chains"
            )
            recommendations['immediate'].append(
                "Isolate affected systems from network to prevent lateral movement"
            )
        
        if any(anomaly.get('severity') in ['critical', 'high'] for anomaly in anomalies):
            recommendations['immediate'].append(
                "Investigate high-severity behavioral anomalies for potential compromise"
            )
        
        if risk_score >= 80:
            recommendations['immediate'].append(
                "Activate emergency response team and consider external security assistance"
            )
        
        # Strategic improvements
        recommendations['strategic'].extend([
            "Implement continuous monitoring and real-time alerting for threat indicators",
            "Enhance user awareness training focusing on identified attack vectors",
            "Review and update incident response procedures based on attack chain analysis",
            "Consider implementing additional network segmentation and access controls",
            "Establish threat intelligence feeds for proactive indicator updates",
            "Regular security assessments and penetration testing",
            "Implement behavioral analytics for advanced persistent threat detection"
        ])
        
        return recommendations


def generate_compliance_report(results: Dict, compliance_framework: str = "SOX") -> str:
    """Generate compliance-specific reports."""
    frameworks = {
        "SOX": {
            "title": "Sarbanes-Oxley Compliance Report",
            "requirements": ["Access Controls", "Data Integrity", "Audit Trail", "Change Management"]
        },
        "PCI-DSS": {
            "title": "PCI-DSS Compliance Report", 
            "requirements": ["Network Security", "Data Protection", "Access Controls", "Monitoring"]
        },
        "HIPAA": {
            "title": "HIPAA Security Compliance Report",
            "requirements": ["Access Controls", "Data Encryption", "Audit Logs", "Risk Assessment"]
        },
        "ISO27001": {
            "title": "ISO 27001 Compliance Report",
            "requirements": ["ISMS", "Risk Management", "Security Controls", "Continuous Improvement"]
        }
    }
    
    if compliance_framework not in frameworks:
        return f"Unsupported compliance framework: {compliance_framework}"
    
    framework = frameworks[compliance_framework]
    
    report = []
    report.append("=" * 80)
    report.append(framework["title"])
    report.append("=" * 80)
    report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    report.append(f"Risk Score: {results.get('risk_score', 0)}/100")
    report.append("")
    
    # Compliance assessment for each requirement
    for requirement in framework["requirements"]:
        report.append(f"{requirement.upper()}")
        report.append("-" * len(requirement))
        
        # Map findings to compliance requirements
        compliance_issues = []
        
        for anomaly in results.get('anomalies', []):
            if requirement.lower() in anomaly.get('type', '').lower():
                compliance_issues.append(f"Anomaly: {anomaly.get('description', 'N/A')}")
        
        for match in results.get('intelligence_matches', []):
            if requirement.lower() in match.get('threat_data', {}).get('type', '').lower():
                compliance_issues.append(f"Threat: {match['indicator']}")
        
        if compliance_issues:
            report.append("ISSUES FOUND:")
            for issue in compliance_issues:
                report.append(f"  - {issue}")
        else:
            report.append("No significant issues identified for this requirement.")
        
        report.append("")
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{compliance_framework.lower()}_compliance_report_{timestamp}.txt"
    
    with open(filename, 'w') as f:
        f.write('\n'.join(report))
    
    return filename


if __name__ == "__main__":
    # Test report generation
    sample_results = {
        "risk_score": 75,
        "intelligence_matches": [
            {
                "indicator": "192.168.1.100",
                "indicator_type": "ip",
                "threat_data": {
                    "type": "botnet",
                    "severity": "high",
                    "source": "internal_honeypot"
                }
            }
        ],
        "anomalies": [
            {
                "type": "unusual_login_time",
                "description": "Login at unusual time: 3:00 AM",
                "severity": "medium",
                "confidence": 0.8,
                "mitre_technique": "T1078"
            }
        ],
        "attack_chains": [],
        "analysis_timestamp": datetime.now().isoformat()
    }
    
    sample_metadata = {
        "scan_time": "2024-04-06 10:00:00",
        "files_scanned": 5,
        "events_analyzed": 150
    }
    
    reporter = ThreatAnalysisReporter()
    
    if REPORTLAB_AVAILABLE:
        print("Generating PDF report...")
        pdf_path = reporter.generate_threat_report(sample_results, sample_metadata)
        print(f"PDF report generated: {pdf_path}")
    else:
        print("ReportLab not available, generating text report...")
        txt_path = reporter.generate_threat_report(sample_results, sample_metadata)
        print(f"Text report generated: {txt_path}")
    
    # Generate compliance report
    compliance_path = generate_compliance_report(sample_results, "SOX")
    print(f"Compliance report generated: {compliance_path}")