import numpy as np
import pandas as pd
import time
import random
import hashlib
import threading
from sklearn.ensemble import IsolationForest
from collections import deque

class AISecurityEngine:
    def __init__(self):
        # Initialize detection models
        self.models = {
            'anomaly_detection': IsolationForest(contamination=0.01, random_state=42),
            'pattern_recognition': None  # Placeholder for a more complex model
        }
        
        # Threat database - would be cloud-synced in production
        self.known_threats = set([
            "malware_signature_1", 
            "suspicious_network_pattern_a",
            "unusual_system_call_sequence",
            "potential_data_exfiltration",
            "brute_force_attempt"
        ])
        
        # Recent activities queue for pattern analysis
        self.recent_activities = deque(maxlen=100)
        
        # Security strategies that rotate
        self.security_strategies = [
            self._strategy_network_focused,
            self._strategy_file_system_focused,
            self._strategy_memory_focused,
            self._strategy_behavior_based,
            self._strategy_signature_based
        ]
        
        # Current strategy index
        self.current_strategy_index = 0
        
        # Dynamic security salt - changes every second
        self.security_salt = self._generate_random_salt()
        
        # Threat analytics
        self.threat_history = []
        self.threat_level = "Low"
        
        # Start the dynamic security rotation
        self._start_dynamic_security_rotation()
    
    def _generate_random_salt(self):
        """Generate a random security salt"""
        return hashlib.sha256(str(time.time() + random.random()).encode()).hexdigest()
    
    def _rotate_security_strategy(self):
        """Change the working principle every second"""
        while True:
            # Change salt
            self.security_salt = self._generate_random_salt()
            
            # Rotate strategy
            self.current_strategy_index = (self.current_strategy_index + 1) % len(self.security_strategies)
            
            # Sleep for one second
            time.sleep(1)
    
    def _start_dynamic_security_rotation(self):
        """Start the security rotation in a separate thread"""
        rotation_thread = threading.Thread(target=self._rotate_security_strategy, daemon=True)
        rotation_thread.start()
    
    def _strategy_network_focused(self, data):
        """Network-focused security strategy"""
        # Implementation would analyze network patterns, ports, protocols
        return self._analyze_network_patterns(data)
    
    def _strategy_file_system_focused(self, data):
        """File system focused security strategy"""
        # Implementation would scan for file integrity, unusual file operations
        return self._analyze_file_operations(data)
    
    def _strategy_memory_focused(self, data):
        """Memory analysis security strategy"""
        # Implementation would look for unusual memory access patterns
        return self._analyze_memory_patterns(data)
    
    def _strategy_behavior_based(self, data):
        """Behavior-based security strategy"""
        # Implementation would analyze process behavior, syscalls
        return self._analyze_behavior_patterns(data)
    
    def _strategy_signature_based(self, data):
        """Signature-based security strategy"""
        # Implementation would check against known signatures
        return self._analyze_signatures(data)
    
    def _analyze_network_patterns(self, data):
        """Analyze network patterns for threats"""
        # Simplified implementation
        threat_score = 0
        
        if 'network' in data:
            network_data = data['network']
            if 'connections' in network_data:
                # Check suspicious IPs (would be more comprehensive in production)
                suspicious_connections = [conn for conn in network_data['connections'] 
                                         if conn.get('port') in [4444, 8080, 1337] or
                                         'suspicious' in conn.get('destination', '')]
                threat_score += len(suspicious_connections) * 0.2
                
        return threat_score
    
    def _analyze_file_operations(self, data):
        """Analyze file operations for threats"""
        # Simplified implementation
        threat_score = 0
        
        if 'filesystem' in data:
            fs_data = data['filesystem']
            if 'operations' in fs_data:
                # Check suspicious file operations
                suspicious_ops = [op for op in fs_data['operations'] 
                                 if op.get('path', '').endswith(('.exe', '.dll', '.sh')) and
                                 op.get('operation') in ['write', 'modify', 'execute']]
                threat_score += len(suspicious_ops) * 0.25
                
        return threat_score
    
    def _analyze_memory_patterns(self, data):
        """Analyze memory patterns for threats"""
        # Simplified implementation
        threat_score = 0
        
        if 'memory' in data:
            memory_data = data['memory']
            if 'allocations' in memory_data:
                # Check suspicious memory allocations
                suspicious_allocs = [alloc for alloc in memory_data['allocations'] 
                                    if alloc.get('size', 0) > 100000000 or
                                    alloc.get('permission') == 'rwx']
                threat_score += len(suspicious_allocs) * 0.3
                
        return threat_score
    
    def _analyze_behavior_patterns(self, data):
        """Analyze behavior patterns for threats"""
        # Simplified implementation
        threat_score = 0
        
        if 'processes' in data:
            process_data = data['processes']
            if 'activities' in process_data:
                # Check suspicious process activities
                suspicious_activities = [act for act in process_data['activities'] 
                                        if act.get('type') in ['keylogging', 'screenshot', 'webcam'] or
                                        'sensitive' in act.get('resource', '')]
                threat_score += len(suspicious_activities) * 0.4
                
        return threat_score
    
    def _analyze_signatures(self, data):
        """Analyze for known threat signatures"""
        # Simplified implementation
        threat_score = 0
        
        if 'signatures' in data:
            signatures = data['signatures']
            matching_signatures = [sig for sig in signatures if sig in self.known_threats]
            threat_score += len(matching_signatures) * 0.5
                
        return threat_score
    
    def detect_threats(self, system_data):
        """Main method to detect threats using the current security strategy"""
        # Add to recent activities for pattern analysis
        self.recent_activities.append(system_data)
        
        # Apply current security strategy
        current_strategy = self.security_strategies[self.current_strategy_index]
        threat_score = current_strategy(system_data)
        
        # Update threat level
        if threat_score > 0.7:
            self.threat_level = "Critical"
        elif threat_score > 0.4:
            self.threat_level = "High"
        elif threat_score > 0.2:
            self.threat_level = "Medium"
        else:
            self.threat_level = "Low"
        
        # Record threat data
        threat_data = {
            'timestamp': time.time(),
            'threat_score': threat_score,
            'threat_level': self.threat_level,
            'strategy_used': current_strategy.__name__,
            'security_salt': self.security_salt[:8]  # Only store part of the salt for security
        }
        self.threat_history.append(threat_data)
        
        # Return threat assessment
        return {
            'detected': threat_score > 0.1,
            'threat_level': self.threat_level,
            'threat_score': threat_score,
            'timestamp': time.time(),
            'details': self._generate_threat_details(system_data, threat_score)
        }
    
    def _generate_threat_details(self, data, threat_score):
        """Generate detailed information about detected threats"""
        if threat_score <= 0.1:
            return "No significant threats detected."
        
        # In a real implementation, this would provide specific details about the threat
        threat_types = []
        
        if 'network' in data and threat_score > 0.2:
            threat_types.append("Suspicious network activity")
        if 'filesystem' in data and threat_score > 0.2:
            threat_types.append("Unusual file system operations")
        if 'memory' in data and threat_score > 0.3:
            threat_types.append("Abnormal memory activity")
        if 'processes' in data and threat_score > 0.3:
            threat_types.append("Suspicious process behavior")
        if 'signatures' in data and threat_score > 0.1:
            threat_types.append("Known threat signatures detected")
            
        if not threat_types:
            threat_types.append("Unspecified suspicious activity")
            
        return ", ".join(threat_types)
    
    def get_mitigation_steps(self, threat_assessment):
        """Generate mitigation steps based on threat assessment"""
        if not threat_assessment['detected']:
            return ["No action needed. System appears secure."]
        
        # Basic mitigation steps based on threat level
        if threat_assessment['threat_level'] == "Critical":
            return [
                "Disconnect from the network immediately",
                "Run a full system scan",
                "Check for unauthorized applications",
                "Update all security software",
                "Contact your security team"
            ]
        elif threat_assessment['threat_level'] == "High":
            return [
                "Limit network connectivity",
                "Run a targeted system scan",
                "Check recently installed applications",
                "Update security definitions"
            ]
        elif threat_assessment['threat_level'] == "Medium":
            return [
                "Monitor system activity",
                "Schedule a system scan",
                "Review application permissions"
            ]
        else:  # Low
            return [
                "Continue normal monitoring",
                "Follow security best practices"
            ]
    
    def get_threat_history(self):
        """Get history of recent threats"""
        return self.threat_history[-10:] if self.threat_history else []


class AISecurityAssistant:
    def __init__(self, security_engine):
        self.security_engine = security_engine
        self.security_tips = [
            "Regularly update your software and operating system",
            "Use a password manager to create and store strong passwords",
            "Enable two-factor authentication when available",
            "Be cautious when clicking on links or downloading attachments",
            "Regularly backup your important data",
            "Use a VPN when connecting to public Wi-Fi networks",
            "Install software only from trusted sources",
            "Use different passwords for different accounts",
            "Keep your antivirus software up to date",
            "Be wary of phishing attempts in emails and messages"
        ]
    
    def get_security_tip(self):
        """Get a random security tip"""
        return random.choice(self.security_tips)
    
    def explain_threat(self, threat_assessment):
        """Explain a detected threat in simple terms"""
        if not threat_assessment['detected']:
            return "Your system is currently secure. No threats have been detected."
        
        threat_level = threat_assessment['threat_level']
        details = threat_assessment['details']
        
        explanations = {
            "Critical": "URGENT: Your device has detected a serious security threat that requires immediate action.",
            "High": "ALERT: Your device has detected a significant security concern that should be addressed soon.",
            "Medium": "CAUTION: Your device has detected a potential security issue that you should be aware of.",
            "Low": "NOTICE: Your device has detected minor security concerns. No immediate action is needed."
        }
        
        base_explanation = explanations.get(threat_level, "Unknown threat level detected.")
        full_explanation = f"{base_explanation}\n\nDetails: {details}"
        
        return full_explanation
    
    def get_mitigation_advice(self, threat_assessment):
        """Get advice on how to mitigate a threat"""
        steps = self.security_engine.get_mitigation_steps(threat_assessment)
        return steps


# Mock data collection module - in a real system, this would collect actual system data
class SystemDataCollector:
    def __init__(self):
        self.mock_data_templates = [
            {
                'network': {
                    'connections': [
                        {'source': '192.168.1.5', 'destination': '8.8.8.8', 'port': 443, 'protocol': 'https'},
                        {'source': '192.168.1.5', 'destination': '192.168.1.1', 'port': 53, 'protocol': 'dns'}
                    ]
                },
                'filesystem': {
                    'operations': [
                        {'path': '/usr/bin/python', 'operation': 'read', 'timestamp': time.time()},
                        {'path': '/home/user/documents/report.docx', 'operation': 'write', 'timestamp': time.time()}
                    ]
                },
                'memory': {
                    'allocations': [
                        {'process': 'chrome', 'size': 1024000, 'permission': 'rw-'},
                        {'process': 'system', 'size': 512000, 'permission': 'r--'}
                    ]
                },
                'processes': {
                    'activities': [
                        {'process': 'chrome', 'type': 'network', 'resource': 'https://example.com'},
                        {'process': 'word', 'type': 'file', 'resource': '/home/user/documents/report.docx'}
                    ]
                },
                'signatures': []
            }
        ]
        
        # Add a few more mock data templates with varying levels of suspicious activity
        self._add_mock_templates()
    
    def _add_mock_templates(self):
        # Add slightly suspicious template
        slightly_suspicious = {
            'network': {
                'connections': [
                    {'source': '192.168.1.5', 'destination': '8.8.8.8', 'port': 443, 'protocol': 'https'},
                    {'source': '192.168.1.5', 'destination': 'suspicious-site.com', 'port': 8080, 'protocol': 'http'}
                ]
            },
            'filesystem': {
                'operations': [
                    {'path': '/usr/bin/python', 'operation': 'read', 'timestamp': time.time()},
                    {'path': '/tmp/update.exe', 'operation': 'write', 'timestamp': time.time()}
                ]
            },
            'memory': {
                'allocations': [
                    {'process': 'chrome', 'size': 1024000, 'permission': 'rw-'},
                    {'process': 'unknown', 'size': 512000, 'permission': 'rwx'}
                ]
            },
            'processes': {
                'activities': [
                    {'process': 'chrome', 'type': 'network', 'resource': 'https://example.com'},
                    {'process': 'unknown', 'type': 'network', 'resource': 'suspicious-site.com'}
                ]
            },
            'signatures': []
        }
        self.mock_data_templates.append(slightly_suspicious)
        
        # Add very suspicious template
        very_suspicious = {
            'network': {
                'connections': [
                    {'source': '192.168.1.5', 'destination': 'malware-server.com', 'port': 4444, 'protocol': 'tcp'},
                    {'source': '192.168.1.5', 'destination': 'data-exfil.com', 'port': 1337, 'protocol': 'tcp'}
                ]
            },
            'filesystem': {
                'operations': [
                    {'path': '/usr/bin/python', 'operation': 'read', 'timestamp': time.time()},
                    {'path': '/home/user/documents/passwords.txt', 'operation': 'read', 'timestamp': time.time()},
                    {'path': '/tmp/backdoor.exe', 'operation': 'execute', 'timestamp': time.time()}
                ]
            },
            'memory': {
                'allocations': [
                    {'process': 'chrome', 'size': 1024000, 'permission': 'rw-'},
                    {'process': 'backdoor', 'size': 999999999, 'permission': 'rwx'}
                ]
            },
            'processes': {
                'activities': [
                    {'process': 'chrome', 'type': 'network', 'resource': 'https://example.com'},
                    {'process': 'backdoor', 'type': 'keylogging', 'resource': 'keyboard'},
                    {'process': 'backdoor', 'type': 'screenshot', 'resource': 'screen'}
                ]
            },
            'signatures': ['malware_signature_1', 'unusual_system_call_sequence']
        }
        self.mock_data_templates.append(very_suspicious)
    
    def collect_data(self):
        """Collect system data - in this mock version, it returns random data"""
        # Select a random template and make a deep copy
        template = random.choice(self.mock_data_templates)
        import copy
        data = copy.deepcopy(template)
        
        # Add some randomness to the data
        # For example, modify some timestamps, add/remove some connections, etc.
        
        return data


# Demo usage
def run_security_demo():
    print("Starting AI Security Engine...")
    engine = AISecurityEngine()
    assistant = AISecurityAssistant(engine)
    collector = SystemDataCollector()
    
    print("Engine initialized with dynamic security rotation.")
    print("Monitoring system for threats...")
    
    for i in range(5):
        print(f"\n--- Scan {i+1} ---")
        
        # Collect system data
        data = collector.collect_data()
        print(f"Collected system data: {len(str(data))} bytes")
        
        # Detect threats
        start_time = time.time()
        threat_assessment = engine.detect_threats(data)
        detection_time = time.time() - start_time
        
        print(f"Threat detection completed in {detection_time:.4f} seconds")
        print(f"Threat level: {threat_assessment['threat_level']}")
        print(f"Threat score: {threat_assessment['threat_score']:.4f}")
        
        if threat_assessment['detected']:
            print("\nThreat explanation:")
            print(assistant.explain_threat(threat_assessment))
            
            print("\nRecommended mitigation steps:")
            for step in assistant.get_mitigation_advice(threat_assessment):
                print(f"- {step}")
        else:
            print("No threats detected.")
            print(f"\nSecurity tip: {assistant.get_security_tip()}")
        
        # Wait a bit before the next scan
        time.sleep(2)
    
    print("\nSecurity demo completed.")


if __name__ == "__main__":
    run_security_demo()