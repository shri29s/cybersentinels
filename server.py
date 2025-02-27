from flask import Flask, request, jsonify
import time
import random
from ai_security_engine import AISecurityEngine, AISecurityAssistant, SystemDataCollector

app = Flask(__name__)

# Initialize security components
security_engine = AISecurityEngine()
security_assistant = AISecurityAssistant(security_engine)
data_collector = SystemDataCollector()

@app.route('/api/detect_threats', methods=['POST'])
def detect_threats():
    """
    Detect threats based on provided system data
    """
    try:
        # Get data from request
        data = request.json
        
        # If no data provided or empty, use the data collector to generate test data
        if not data:
            data = data_collector.collect_data()
        
        # Process with security engine
        threat_assessment = security_engine.detect_threats(data)
        
        return jsonify(threat_assessment)
    
    except Exception as e:
        return jsonify({
            'error': str(e),
            'detected': False,
            'threat_level': 'Low',
            'threat_score': 0.0,
            'details': 'Error processing threat detection',
            'timestamp': time.time()
        }), 500

@app.route('/api/get_mitigation', methods=['POST'])
def get_mitigation():
    """
    Get mitigation steps for a detected threat
    """
    try:
        # Get threat assessment from request
        threat_data = request.json
        
        # Process with security assistant
        mitigation_steps = security_engine.get_mitigation_steps(threat_data)
        
        return jsonify({
            'steps': mitigation_steps
        })
    
    except Exception as e:
        return jsonify({
            'error': str(e),
            'steps': ['Update your security software', 'Run a system scan']
        }), 500

@app.route('/api/security_tip', methods=['GET'])
def get_security_tip():
    """
    Get a random security tip
    """
    try:
        tip = security_assistant.get_security_tip()
        return jsonify({
            'tip': tip
        })
    
    except Exception as e:
        return jsonify({
            'error': str(e),
            'tip': 'Keep your software updated to stay protected.'
        }), 500

@app.route('/api/threat_history', methods=['GET'])
def get_threat_history():
    """
    Get history of recent threats
    """
    try:
        history = security_engine.get_threat_history()
        return jsonify({
            'history': history
        })
    
    except Exception as e:
        return jsonify({
            'error': str(e),
            'history': []
        }), 500

if __name__ == '__main__':
    print("Starting AI Security Engine Server...")
    app.run(host='0.0.0.0', port=5000, debug=True)