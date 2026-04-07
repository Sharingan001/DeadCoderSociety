#!/usr/bin/env python3
"""
Professional PDF Report Generator for LogSentinel Pro v3.0
Enterprise-grade threat analysis reports with advanced formatting and visualizations
"""

import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import base64
import io

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import (SimpleDocTemplate, Table, TableStyle, Paragraph, 
                                   Spacer, PageBreak, KeepTogether, Image as RLImage)
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch, cm
    from reportlab.graphics.shapes import Drawing, Rect, String, Circle
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    from reportlab.graphics.charts.linecharts import HorizontalLineChart
    from reportlab.graphics import renderPDF
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

try:
    import matplotlib.pyplot as plt
    import matplotlib.patches as patches
    from matplotlib.patches import Wedge
    import numpy as np
    plt.style.use('default')  # Professional style
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False


class ProfessionalPDFReporter:
    """Enterprise-grade PDF report generator with professional formatting."""
    
    def __init__(self):
        """Initialize the PDF reporter with professional styling."""
        if not REPORTLAB_AVAILABLE:
            raise ImportError("ReportLab is required for PDF generation. Install with: pip install reportlab")
        
        self.pagesize = A4
        self.styles = getSampleStyleSheet()
        self.custom_styles = self._create_enterprise_styles()
        self.colors = self._define_color_palette()
        
        # Report metadata
        self.report_metadata = {
            "title": "LogSentinel Pro - Threat Analysis Report",
            "version": "3.0.0",
            "classification": "CONFIDENTIAL",
            "company": "Dead Coder Society",
            "generated_by": "LogSentinel Pro SIEM Platform"
        }
    
    def _define_color_palette(self) -> Dict:
        """Define professional color palette for reports."""
        return {
            # Primary colors
            'primary_dark': colors.Color(0.12, 0.20, 0.39),      # Dark blue
            'primary_light': colors.Color(0.85, 0.90, 0.98),     # Light blue
            'accent': colors.Color(0.90, 0.30, 0.30),            # Red
            
            # Severity colors
            'critical': colors.Color(0.80, 0.00, 0.00),          # Dark red
            'high': colors.Color(1.00, 0.40, 0.00),              # Orange
            'medium': colors.Color(1.00, 0.80, 0.00),            # Yellow
            'low': colors.Color(0.20, 0.60, 0.20),               # Green
            
            # Neutral colors
            'dark_grey': colors.Color(0.20, 0.20, 0.20),
            'light_grey': colors.Color(0.95, 0.95, 0.95),
            'border_grey': colors.Color(0.80, 0.80, 0.80),
        }
    
    def _create_enterprise_styles(self) -> Dict:
        """Create professional paragraph styles for enterprise reporting."""
        styles = {}
        
        # Document title
        styles['DocumentTitle'] = ParagraphStyle(
            'DocumentTitle',
            parent=self.styles['Title'],
            fontSize=28,
            spaceAfter=30,
            textColor=self.colors['primary_dark'] if hasattr(self, 'colors') else colors.darkblue,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )
        
        # Classification header
        styles['Classification'] = ParagraphStyle(
            'Classification',
            parent=self.styles['Normal'],
            fontSize=14,
            textColor=colors.red,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold',
            spaceAfter=20
        )
        
        # Section headings
        styles['SectionHeading'] = ParagraphStyle(
            'SectionHeading',
            parent=self.styles['Heading1'],
            fontSize=18,
            spaceAfter=15,
            spaceBefore=25,
            textColor=self.colors['primary_dark'] if hasattr(self, 'colors') else colors.darkblue,
            fontName='Helvetica-Bold',
            borderWidth=2,
            borderColor=self.colors['primary_dark'] if hasattr(self, 'colors') else colors.darkblue,
            borderPadding=8,
            backColor=self.colors['primary_light'] if hasattr(self, 'colors') else colors.lightblue
        )
        
        styles['SubHeading'] = ParagraphStyle(
            'SubHeading',
            parent=self.styles['Heading2'],
            fontSize=14,
            spaceAfter=12,
            spaceBefore=15,
            textColor=self.colors['primary_dark'] if hasattr(self, 'colors') else colors.darkblue,
            fontName='Helvetica-Bold'
        )
        
        # Body text styles
        styles['ExecutiveSummary'] = ParagraphStyle(
            'ExecutiveSummary',
            parent=self.styles['Normal'],
            fontSize=12,
            alignment=TA_JUSTIFY,
            leftIndent=20,
            rightIndent=20,
            spaceAfter=15,
            leading=18,
            backColor=self.colors['light_grey'] if hasattr(self, 'colors') else colors.lightgrey,
            borderWidth=1,
            borderColor=self.colors['border_grey'] if hasattr(self, 'colors') else colors.grey,
            borderPadding=15
        )
        
        styles['BodyText'] = ParagraphStyle(
            'BodyText',
            parent=self.styles['Normal'],
            fontSize=11,
            alignment=TA_JUSTIFY,
            spaceAfter=12,
            leading=16
        )
        
        # Alert styles
        styles['CriticalAlert'] = ParagraphStyle(
            'CriticalAlert',
            parent=self.styles['Normal'],
            fontSize=12,
            textColor=colors.white,
            backColor=self.colors['critical'] if hasattr(self, 'colors') else colors.red,
            borderWidth=2,
            borderColor=self.colors['critical'] if hasattr(self, 'colors') else colors.red,
            borderPadding=10,
            fontName='Helvetica-Bold',
            alignment=TA_CENTER
        )
        
        styles['HighAlert'] = ParagraphStyle(
            'HighAlert',
            parent=self.styles['Normal'],
            fontSize=11,
            textColor=colors.white,
            backColor=self.colors['high'] if hasattr(self, 'colors') else colors.orange,
            borderWidth=1,
            borderColor=self.colors['high'] if hasattr(self, 'colors') else colors.orange,
            borderPadding=8,
            fontName='Helvetica-Bold'
        )
        
        # Footer style
        styles['Footer'] = ParagraphStyle(
            'Footer',
            parent=self.styles['Normal'],
            fontSize=9,
            textColor=self.colors['dark_grey'] if hasattr(self, 'colors') else colors.grey,
            alignment=TA_CENTER,
            spaceAfter=0
        )
        
        return styles
    
    def generate_comprehensive_report(self, results: Dict, metadata: Dict = None) -> str:
        """Generate a comprehensive professional threat analysis report."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"logsentinel_threat_analysis_{timestamp}.pdf"
        
        # Create document
        doc = SimpleDocTemplate(
            filename,
            pagesize=self.pagesize,
            rightMargin=1*inch,
            leftMargin=1*inch,
            topMargin=1.5*inch,
            bottomMargin=1*inch
        )
        
        # Build story
        story = []
        
        # Add all sections
        story.extend(self._create_cover_page(results, metadata))
        story.append(PageBreak())
        
        story.extend(self._create_executive_summary(results))
        story.append(PageBreak())
        
        story.extend(self._create_threat_overview(results))
        story.extend(self._create_detailed_findings(results))
        story.extend(self._create_recommendations(results))
        story.extend(self._create_technical_appendix(results))
        
        # Build PDF
        doc.build(story, onFirstPage=self._add_header_footer, onLaterPages=self._add_header_footer)
        
        return filename
    
    def _create_cover_page(self, results: Dict, metadata: Dict = None) -> List:
        """Create professional cover page."""
        story = []
        
        # Classification banner
        story.append(Paragraph(self.report_metadata["classification"], self.custom_styles['Classification']))
        
        # Title
        story.append(Spacer(1, 1*inch))
        story.append(Paragraph(self.report_metadata["title"], self.custom_styles['DocumentTitle']))
        
        # Subtitle
        story.append(Spacer(1, 0.5*inch))
        story.append(Paragraph("Automated Threat Intelligence & Security Analysis", 
                              self.custom_styles['SubHeading']))
        
        # Risk gauge
        if MATPLOTLIB_AVAILABLE:
            risk_score = results.get('risk_score', 0)
            gauge_image = self._create_professional_risk_gauge(risk_score)
            if gauge_image:
                story.append(Spacer(1, 0.5*inch))
                story.append(gauge_image)
        
        # Metadata table
        story.append(Spacer(1, 1*inch))
        
        meta = metadata or {}
        cover_data = [
            ['Report Generated:', datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")],
            ['Analysis Engine:', self.report_metadata["version"]],
            ['Risk Score:', f"{results.get('risk_score', 0)}/100 ({self._get_risk_classification(results.get('risk_score', 0)).upper()})"],
            ['Threats Identified:', str(len(results.get('intelligence_matches', [])))],
            ['Anomalies Detected:', str(len(results.get('anomalies', [])))],
            ['Events Analyzed:', str(meta.get('events_analyzed', 'N/A'))],
            ['Generated By:', self.report_metadata["generated_by"]]
        ]
        
        cover_table = Table(cover_data, colWidths=[2.5*inch, 3*inch])
        cover_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), self.colors['light_grey']),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 1, self.colors['border_grey']),
            ('LEFTPADDING', (0, 0), (-1, -1), 12),
            ('RIGHTPADDING', (0, 0), (-1, -1), 12),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        
        story.append(cover_table)
        
        # Classification footer
        story.append(Spacer(1, 2*inch))
        story.append(Paragraph("This report contains sensitive security information and should be handled according to your organization's data classification policies.", 
                              self.custom_styles['Footer']))
        
        return story
    
    def _create_executive_summary(self, results: Dict) -> List:
        """Create executive summary with key findings."""
        story = []
        
        story.append(Paragraph("Executive Summary", self.custom_styles['SectionHeading']))
        
        # Risk assessment
        risk_score = results.get('risk_score', 0)
        total_threats = len(results.get('intelligence_matches', []))
        total_anomalies = len(results.get('anomalies', []))
        total_chains = len(results.get('attack_chains', []))
        
        # Executive summary text
        summary_text = f"""
        LogSentinel Pro's automated threat analysis has completed a comprehensive security assessment 
        of your environment. The analysis identified <b>{total_threats}</b> threat intelligence indicators, 
        <b>{total_anomalies}</b> behavioral anomalies, and <b>{total_chains}</b> potential attack chains.
        <br/><br/>
        <b>Overall Risk Assessment:</b> {risk_score}/100 ({self._get_risk_classification(risk_score).upper()})
        <br/><br/>
        <b>Recommended Action:</b> {self._get_response_urgency(risk_score)}
        """
        
        if risk_score >= 80:
            story.append(Paragraph("🚨 CRITICAL SECURITY ALERT", self.custom_styles['CriticalAlert']))
            story.append(Spacer(1, 0.2*inch))
            summary_text += """<br/><br/>
            <b>IMMEDIATE ATTENTION REQUIRED:</b> Critical threats have been identified that require 
            immediate security response. Evidence suggests active or imminent attack activity."""
        elif risk_score >= 60:
            story.append(Paragraph("⚠️ HIGH RISK DETECTED", self.custom_styles['HighAlert']))
            story.append(Spacer(1, 0.2*inch))
        
        story.append(Paragraph(summary_text, self.custom_styles['ExecutiveSummary']))
        
        # Key metrics table
        story.append(Spacer(1, 0.3*inch))
        story.append(Paragraph("Key Security Metrics", self.custom_styles['SubHeading']))
        
        metrics_data = [
            ['Security Metric', 'Count', 'Highest Severity', 'Impact Level'],
            ['Threat Intelligence Matches', str(total_threats), 
             self._get_highest_severity(results.get('intelligence_matches', []), 'threat_data'), 
             self._assess_impact(total_threats, 'threats')],
            ['Behavioral Anomalies', str(total_anomalies), 
             self._get_highest_severity(results.get('anomalies', [])), 
             self._assess_impact(total_anomalies, 'anomalies')],
            ['Attack Chain Sequences', str(total_chains), 
             self._get_highest_severity(results.get('attack_chains', [])), 
             self._assess_impact(total_chains, 'chains')]
        ]
        
        metrics_table = Table(metrics_data, colWidths=[2.2*inch, 0.8*inch, 1.2*inch, 1.3*inch])
        metrics_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.colors['primary_dark']),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 1, self.colors['border_grey']),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, self.colors['light_grey']]),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        
        story.append(metrics_table)
        
        return story
    
    def _create_threat_overview(self, results: Dict) -> List:
        """Create threat overview section with detailed analysis."""
        story = []
        
        story.append(Paragraph("Threat Intelligence Analysis", self.custom_styles['SectionHeading']))
        
        intel_matches = results.get('intelligence_matches', [])
        
        if not intel_matches:
            story.append(Paragraph("No threat intelligence matches were identified in the analyzed data.", 
                                 self.custom_styles['BodyText']))
            return story
        
        # Group by severity and type
        by_severity = {'critical': [], 'high': [], 'medium': [], 'low': []}
        by_type = {}
        
        for match in intel_matches:
            threat_data = match.get('threat_data', {})
            severity = threat_data.get('severity', 'low').lower()
            threat_type = threat_data.get('type', 'unknown')
            
            by_severity[severity].append(match)
            if threat_type not in by_type:
                by_type[threat_type] = []
            by_type[threat_type].append(match)
        
        # Threat summary by severity
        for severity in ['critical', 'high', 'medium', 'low']:
            if by_severity[severity]:
                count = len(by_severity[severity])
                story.append(Paragraph(f"{severity.title()} Severity Threats ({count} found)", 
                                     self.custom_styles['SubHeading']))
                
                # Create detailed table for this severity
                threat_data = [['Indicator', 'Type', 'Source', 'First Seen', 'Description']]
                
                for match in by_severity[severity][:10]:  # Limit to top 10
                    indicator = match.get('indicator', 'N/A')
                    threat_info = match.get('threat_data', {})
                    description = self._get_threat_description(threat_info.get('type', ''))
                    
                    threat_data.append([
                        indicator[:20] + "..." if len(indicator) > 20 else indicator,
                        threat_info.get('type', 'Unknown').title(),
                        threat_info.get('source', 'Unknown'),
                        threat_info.get('first_seen', 'Unknown'),
                        description
                    ])
                
                if len(by_severity[severity]) > 10:
                    threat_data.append([f"... and {len(by_severity[severity]) - 10} more", '', '', '', ''])
                
                threat_table = Table(threat_data, colWidths=[1.8*inch, 1.2*inch, 1.2*inch, 1*inch, 1.3*inch])
                threat_table.setStyle(self._get_professional_table_style())
                
                story.append(threat_table)
                story.append(Spacer(1, 0.2*inch))
        
        return story
    
    def _create_detailed_findings(self, results: Dict) -> List:
        """Create detailed findings section."""
        story = []
        
        story.append(Paragraph("Detailed Security Findings", self.custom_styles['SectionHeading']))
        
        # Anomalies section
        anomalies = results.get('anomalies', [])
        if anomalies:
            story.append(Paragraph("Behavioral Anomalies", self.custom_styles['SubHeading']))
            
            anomaly_data = [['Anomaly Type', 'Severity', 'Confidence', 'MITRE Technique', 'Description']]
            
            for anomaly in anomalies:
                anomaly_data.append([
                    anomaly.get('type', 'Unknown').replace('_', ' ').title(),
                    anomaly.get('severity', 'Low').title(),
                    f"{int(anomaly.get('confidence', 0) * 100)}%",
                    anomaly.get('mitre_technique', 'N/A'),
                    anomaly.get('description', 'No description available')[:50] + "..."
                ])
            
            anomaly_table = Table(anomaly_data, colWidths=[1.5*inch, 1*inch, 1*inch, 1.2*inch, 1.8*inch])
            anomaly_table.setStyle(self._get_professional_table_style())
            
            story.append(anomaly_table)
            story.append(Spacer(1, 0.3*inch))
        
        # Attack chains section
        attack_chains = results.get('attack_chains', [])
        if attack_chains:
            story.append(Paragraph("Attack Chain Analysis", self.custom_styles['SubHeading']))
            
            for i, chain in enumerate(attack_chains, 1):
                chain_text = f"""
                <b>Attack Chain #{i}:</b> {chain.get('attack_type', 'Unknown Attack')}
                <br/>Attacker: {chain.get('attacker', 'Unknown')}
                <br/>Confidence: {int(chain.get('confidence', 0) * 100)}%
                <br/>Duration: {chain.get('duration', 'Unknown')}
                <br/>Phases: {len(chain.get('phases', []))}
                """
                
                story.append(Paragraph(chain_text, self.custom_styles['BodyText']))
                story.append(Spacer(1, 0.1*inch))
        
        return story
    
    def _create_recommendations(self, results: Dict) -> List:
        """Create recommendations section."""
        story = []
        
        story.append(Paragraph("Security Recommendations", self.custom_styles['SectionHeading']))
        
        risk_score = results.get('risk_score', 0)
        recommendations = self._generate_recommendations(results, risk_score)
        
        # Immediate actions
        if recommendations['immediate']:
            story.append(Paragraph("Immediate Actions Required", self.custom_styles['SubHeading']))
            
            for i, action in enumerate(recommendations['immediate'], 1):
                story.append(Paragraph(f"{i}. {action}", self.custom_styles['BodyText']))
            
            story.append(Spacer(1, 0.2*inch))
        
        # Strategic recommendations
        if recommendations['strategic']:
            story.append(Paragraph("Strategic Security Improvements", self.custom_styles['SubHeading']))
            
            for i, action in enumerate(recommendations['strategic'], 1):
                story.append(Paragraph(f"{i}. {action}", self.custom_styles['BodyText']))
        
        return story
    
    def _create_technical_appendix(self, results: Dict) -> List:
        """Create technical appendix with detailed data."""
        story = []
        
        story.append(PageBreak())
        story.append(Paragraph("Technical Appendix", self.custom_styles['SectionHeading']))
        
        # Raw data summary
        story.append(Paragraph("Analysis Metadata", self.custom_styles['SubHeading']))
        
        metadata_text = f"""
        Analysis Timestamp: {results.get('analysis_timestamp', datetime.now().isoformat())}
        <br/>Engine Version: LogSentinel Pro v3.0.0
        <br/>Detection Rules: Updated threat intelligence database
        <br/>ML Models: Behavioral analysis algorithms v2.1
        """
        
        story.append(Paragraph(metadata_text, self.custom_styles['BodyText']))
        
        return story
    
    def _create_professional_risk_gauge(self, risk_score: int) -> Optional[RLImage]:
        """Create a professional risk assessment gauge."""
        if not MATPLOTLIB_AVAILABLE:
            return None
        
        try:
            fig, ax = plt.subplots(figsize=(6, 4), facecolor='white')
            
            # Create gauge
            theta = np.linspace(0, np.pi, 100)
            
            # Background arc
            ax.fill_between(theta, 0.8, 1.0, color='#f0f0f0', alpha=0.3)
            
            # Risk zones
            zones = [
                (0, 0.2, '#22c55e', 'LOW'),      # Green
                (0.2, 0.4, '#eab308', 'MEDIUM'),  # Yellow  
                (0.4, 0.7, '#f97316', 'HIGH'),   # Orange
                (0.7, 1.0, '#ef4444', 'CRITICAL') # Red
            ]
            
            for start, end, color, label in zones:
                start_angle = start * np.pi
                end_angle = end * np.pi
                theta_zone = np.linspace(start_angle, end_angle, 50)
                ax.fill_between(theta_zone, 0.8, 1.0, color=color, alpha=0.7)
                
                # Add labels
                mid_angle = (start_angle + end_angle) / 2
                ax.text(mid_angle, 1.1, label, ha='center', va='center', 
                       fontsize=9, fontweight='bold')
            
            # Risk needle
            needle_angle = (risk_score / 100) * np.pi
            needle_x = [0, 0.9 * np.cos(needle_angle)]
            needle_y = [0, 0.9 * np.sin(needle_angle)]
            ax.plot(needle_x, needle_y, 'k-', linewidth=4)
            ax.plot(0, 0, 'ko', markersize=8)
            
            # Score display
            ax.text(0, -0.3, f'{risk_score}', ha='center', va='center', 
                   fontsize=24, fontweight='bold')
            ax.text(0, -0.45, 'RISK SCORE', ha='center', va='center', 
                   fontsize=12, fontweight='bold')
            
            ax.set_xlim(-1.2, 1.2)
            ax.set_ylim(-0.6, 1.3)
            ax.set_aspect('equal')
            ax.axis('off')
            
            # Save to memory
            img_buffer = io.BytesIO()
            plt.savefig(img_buffer, format='PNG', dpi=150, bbox_inches='tight')
            img_buffer.seek(0)
            plt.close()
            
            return RLImage(img_buffer, width=4*inch, height=2.5*inch)
            
        except Exception as e:
            print(f"Error creating risk gauge: {e}")
            return None
    
    def _get_professional_table_style(self) -> TableStyle:
        """Get professional table styling."""
        return TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.colors['primary_dark']),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 1, self.colors['border_grey']),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, self.colors['light_grey']]),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ])
    
    def _add_header_footer(self, canvas, doc):
        """Add professional header and footer to each page."""
        canvas.saveState()
        
        # Header
        canvas.setFont('Helvetica-Bold', 10)
        canvas.setFillColor(self.colors['primary_dark'])
        canvas.drawString(1*inch, doc.pagesize[1] - 0.75*inch, "LogSentinel Pro - Threat Analysis Report")
        
        canvas.setFont('Helvetica', 9)
        canvas.setFillColor(colors.red)
        canvas.drawRightString(doc.pagesize[0] - 1*inch, doc.pagesize[1] - 0.75*inch, "CONFIDENTIAL")
        
        # Footer
        canvas.setFont('Helvetica', 8)
        canvas.setFillColor(self.colors['dark_grey'])
        canvas.drawString(1*inch, 0.75*inch, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        canvas.drawRightString(doc.pagesize[0] - 1*inch, 0.75*inch, f"Page {doc.page}")
        
        canvas.restoreState()
    
    # Helper methods
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
            return "IMMEDIATE response required (within 1 hour)"
        elif risk_score >= 60:
            return "Urgent response required (within 4 hours)"
        elif risk_score >= 40:
            return "Standard response required (within 24 hours)"
        else:
            return "Routine monitoring (review within 1 week)"
    
    def _get_highest_severity(self, items: List[Dict], nested_key: str = None) -> str:
        """Get highest severity from a list of items."""
        if not items:
            return "None"
        
        severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        highest = 'low'
        
        for item in items:
            if nested_key:
                severity = item.get(nested_key, {}).get('severity', 'low')
            else:
                severity = item.get('severity', 'low')
            
            if severity_order.get(severity.lower(), 0) > severity_order.get(highest, 0):
                highest = severity.lower()
        
        return highest.title()
    
    def _assess_impact(self, count: int, item_type: str) -> str:
        """Assess impact level based on count and type."""
        if item_type == 'threats':
            if count >= 10:
                return "High Impact"
            elif count >= 5:
                return "Medium Impact"
            elif count >= 1:
                return "Low Impact"
        elif item_type == 'anomalies':
            if count >= 5:
                return "High Impact"
            elif count >= 3:
                return "Medium Impact"
            elif count >= 1:
                return "Low Impact"
        elif item_type == 'chains':
            if count >= 3:
                return "High Impact"
            elif count >= 1:
                return "Medium Impact"
        
        return "Minimal Impact"
    
    def _get_threat_description(self, threat_type: str) -> str:
        """Get description for threat type."""
        descriptions = {
            'botnet': 'Compromised system participating in botnet',
            'c2_server': 'Command and control server communication',
            'malware': 'Malicious software detected',
            'phishing': 'Phishing attack infrastructure',
            'scanner': 'Network scanning activity',
            'tor_exit': 'Tor network exit node traffic',
            'lateral_movement': 'Internal network lateral movement'
        }
        return descriptions.get(threat_type, 'Unknown threat type')
    
    def _generate_recommendations(self, results: Dict, risk_score: int) -> Dict:
        """Generate actionable recommendations based on findings."""
        recommendations = {'immediate': [], 'strategic': []}
        
        intel_matches = results.get('intelligence_matches', [])
        anomalies = results.get('anomalies', [])
        
        # Immediate actions based on risk score
        if risk_score >= 80:
            recommendations['immediate'].extend([
                "Activate incident response team immediately",
                "Isolate affected systems from network",
                "Begin forensic data collection",
                "Notify security stakeholders and management"
            ])
        elif risk_score >= 60:
            recommendations['immediate'].extend([
                "Investigate identified threats within 4 hours",
                "Increase monitoring on affected systems",
                "Review and update firewall rules"
            ])
        
        # Specific recommendations based on findings
        if any(match.get('threat_data', {}).get('type') == 'c2_server' for match in intel_matches):
            recommendations['immediate'].append("Block C2 server communications immediately")
        
        if any(match.get('threat_data', {}).get('type') == 'botnet' for match in intel_matches):
            recommendations['immediate'].append("Quarantine systems showing botnet activity")
        
        # Strategic recommendations
        recommendations['strategic'].extend([
            "Implement advanced threat hunting procedures",
            "Enhance security awareness training",
            "Deploy additional network monitoring tools",
            "Review and update incident response procedures",
            "Consider threat intelligence platform integration"
        ])
        
        return recommendations


def generate_compliance_report_pdf(results: Dict, compliance_framework: str = "SOX") -> str:
    """Generate professional compliance report in PDF format."""
    reporter = ProfessionalPDFReporter()
    
    # Override title for compliance report
    reporter.report_metadata["title"] = f"{compliance_framework} Compliance Assessment Report"
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"logsentinel_{compliance_framework.lower()}_compliance_{timestamp}.pdf"
    
    doc = SimpleDocTemplate(
        filename,
        pagesize=reporter.pagesize,
        rightMargin=1*inch,
        leftMargin=1*inch,
        topMargin=1.5*inch,
        bottomMargin=1*inch
    )
    
    story = []
    
    # Compliance-specific content
    story.append(Paragraph(f"{compliance_framework} Compliance Assessment", 
                          reporter.custom_styles['DocumentTitle']))
    story.append(Spacer(1, 0.5*inch))
    
    # Compliance status summary
    risk_score = results.get('risk_score', 0)
    compliance_status = "NON-COMPLIANT" if risk_score >= 60 else "COMPLIANT"
    status_color = "red" if risk_score >= 60 else "green"
    
    story.append(Paragraph(f"<font color='{status_color}'><b>Status: {compliance_status}</b></font>", 
                          reporter.custom_styles['SubHeading']))
    
    # Framework-specific requirements
    frameworks = {
        "SOX": ["Access Controls", "Data Integrity", "Audit Trail", "Change Management"],
        "PCI-DSS": ["Network Security", "Data Protection", "Access Controls", "Monitoring"],
        "HIPAA": ["Access Controls", "Data Encryption", "Audit Logs", "Risk Assessment"],
        "ISO27001": ["ISMS", "Risk Management", "Security Controls", "Continuous Improvement"]
    }
    
    requirements = frameworks.get(compliance_framework, ["Generic Requirements"])
    
    story.append(Paragraph("Compliance Requirements Assessment", 
                          reporter.custom_styles['SectionHeading']))
    
    req_data = [['Requirement', 'Status', 'Risk Level', 'Action Required']]
    
    for req in requirements:
        # Simple logic for demo - in production this would be more sophisticated
        status = "FAIL" if risk_score >= 60 else "PASS"
        risk_level = reporter._get_risk_classification(risk_score).upper()
        action = "Immediate remediation required" if status == "FAIL" else "Continue monitoring"
        
        req_data.append([req, status, risk_level, action])
    
    req_table = Table(req_data, colWidths=[2*inch, 1*inch, 1.2*inch, 2.3*inch])
    req_table.setStyle(reporter._get_professional_table_style())
    
    story.append(req_table)
    
    # Build PDF
    doc.build(story, onFirstPage=reporter._add_header_footer, onLaterPages=reporter._add_header_footer)
    
    return filename


# Compatibility function for existing code
def generate_threat_report(results: Dict, metadata: Dict = None) -> str:
    """Generate threat analysis report using professional PDF generator."""
    if not REPORTLAB_AVAILABLE:
        # Fallback to text report
        return _generate_text_report(results, metadata)
    
    try:
        reporter = ProfessionalPDFReporter()
        return reporter.generate_comprehensive_report(results, metadata)
    except Exception as e:
        print(f"PDF generation failed: {e}, falling back to text report")
        return _generate_text_report(results, metadata)


def _generate_text_report(results: Dict, metadata: Dict = None) -> str:
    """Fallback text report generation."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"threat_analysis_report_{timestamp}.txt"
    
    with open(filename, 'w') as f:
        f.write("LogSentinel Pro - Threat Analysis Report\n")
        f.write("=" * 50 + "\n\n")
        f.write(f"Generated: {datetime.now().isoformat()}\n")
        f.write(f"Risk Score: {results.get('risk_score', 0)}/100\n\n")
        
        intel_matches = results.get('intelligence_matches', [])
        f.write(f"Threat Intelligence Matches: {len(intel_matches)}\n")
        for match in intel_matches:
            f.write(f"  - {match.get('indicator', 'N/A')}: {match.get('threat_data', {}).get('type', 'Unknown')}\n")
        
        f.write(f"\nAnomalies: {len(results.get('anomalies', []))}\n")
        for anomaly in results.get('anomalies', []):
            f.write(f"  - {anomaly.get('type', 'Unknown')}: {anomaly.get('description', 'No description')}\n")
    
    return filename