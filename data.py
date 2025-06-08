import uuid
from datetime import datetime, timedelta
from random import choice, randint, uniform
from faker import Faker
from app import create_app, db
from app.models import User, Incident, Enrichment, MLModel, LLMPrompt, AnalyticsLog, SystemSetting
import json

fake = Faker()

def create_fake_users():
    """Create specific users with defined roles"""
    users_data = [
        {"name": "Mohamed Aziz Akrout", "role": "analyst"},
        {"name": "Hedi Dridi", "role": "analyst"},
        {"name": "Chiheb Mahfoudh", "role": "analyst"},
        {"name": "Sami Jhin", "role": "manager"},
        {"name": "maram", "role": "manager"},
        {"name": "benmoussa", "role": "admin"}
    ]
    
    users = []
    for user_data in users_data:
        username = user_data["name"].lower().replace(" ", "_")
        user = User(
            username=username,
            role=user_data["role"],
            is_active=True
        )
        user.set_password('password')
        users.append(user)
        db.session.add(user)
    db.session.commit()
    return users

def create_fake_ml_models():
    """Create fake ML models"""
    models = [
        {
            'name': 'Anomaly Detection',
            'purpose': 'Network behavior analysis',
            'model_type': 'anomaly',
            'endpoint': 'http://localhost:3001',
            'api_key': str(uuid.uuid4()),
            'version': '1.3.1',
            'is_active': True,
            'last_active': datetime.now() - timedelta(days=randint(0, 30))
        },
        {
            'name': 'Malware Detection',
            'purpose': 'Malicious file detection',
            'model_type': 'malware',
            'endpoint': 'http://localhost:4000',
            'api_key': str(uuid.uuid4()),
            'version': '1.7.4',
            'is_active': True,
            'last_active': datetime.now() - timedelta(days=randint(0, 30))
        },
        {
            'name': 'Phishing Detection',
            'purpose': 'Email and URL analysis',
            'model_type': 'phishing',
            'endpoint': 'http://localhost:6000',
            'api_key': str(uuid.uuid4()),
            'version': '1.0.2',
            'is_active': True,
            'last_active': datetime.now() - timedelta(days=randint(0, 30))
        },
        {
            'name': 'Windows Log Analysis',
            'purpose': 'Windows event log analysis',
            'model_type': 'windows_log',
            'endpoint': 'http://localhost:7000',
            'api_key': str(uuid.uuid4()),
            'version': '1.2.0',
            'is_active': True,
            'last_active': datetime.now() - timedelta(days=randint(0, 30))
        }
    ]
    
    ml_models = []
    for model_data in models:
        model = MLModel(**model_data)
        ml_models.append(model)
        db.session.add(model)
    db.session.commit()
    return ml_models

def create_fake_llm_prompts():
    """Create enhanced LLM prompts with mitigation and full report sections"""
    prompts = [
        {
            'type': 'phishing',
            'prompt_text': """Analyze this potential phishing attempt: {alert_details}
            
            Provide:
            1. Threat assessment
            2. Indicators of compromise
            3. Recommended mitigation steps
            4. Full incident report including timeline and affected systems""",
            'llm_provider': 'OpenAI'
        },
        {
            'type': 'malware',
            'prompt_text': """Investigate this malware alert: {alert_details}
            
            Provide:
            1. Malware analysis including behavior and capabilities
            2. Impact assessment
            3. Containment and eradication steps
            4. Full technical report with IOCs and mitigation recommendations""",
            'llm_provider': 'OpenAI'
        },
        {
            'type': 'insider_threat',
            'prompt_text': """Examine this potential insider threat: {alert_details}
            
            Provide:
            1. Risk assessment
            2. Behavioral analysis
            3. Recommended actions for containment
            4. Full investigation report with evidence and next steps""",
            'llm_provider': 'Anthropic'
        }
    ]
    
    llm_prompts = []
    for prompt_data in prompts:
        prompt = LLMPrompt(**prompt_data)
        llm_prompts.append(prompt)
        db.session.add(prompt)
    db.session.commit()
    return llm_prompts

def create_fake_incidents(users=None, ml_models=None):
    """Create fake incidents based on the provided data"""
    if not users:
        users = User.query.filter_by(role='analyst').all()
    if not ml_models:
        ml_models = MLModel.query.all()
    
    # Windows events incidents
    windows_incidents = []
    for event in incident_data["Windows_events"]["results"]:
        timestamp = datetime.strptime(event["timestamp"], "%Y-%m-%dT%H:%M:%S.%f%z")
        
        incident = Incident(
            timestamp=timestamp,
            source_ip=event["raw_alert"]["agent"]["ip"],
            type="Windows Event",
            severity="High" if "svchost" in event["process_name"] else "Medium",
            ml_model_name="Windows Log Analysis",
            confidence_score=float(event["raw_result"]["prediction"]["alert"]),
            assigned_to=choice(users).id if randint(0, 4) > 0 else None,
            status=choice(["New", "In Progress", "Closed"]),
            description=event["rule_description"],
            llm_summary=f"Process {event['process_name']} executed with command: {event['command_line']}. Parent process: {event['parent_process']}"
        )
        windows_incidents.append(incident)
        db.session.add(incident)
    
    # Phishing incidents
    phishing_incidents = []
    for email in incident_data["Phishing"]["results"]:
        timestamp = datetime.strptime(email["timestamp"], "%Y-%m-%dT%H:%M:%S.%f")
        
        incident = Incident(
            timestamp=timestamp,
            source_ip=fake.ipv4(),
            type="Phishing",
            severity="High" if "linkedin" in email["from"].lower() else "Medium",
            ml_model_name="Phishing Detection",
            confidence_score=float(email["prediction"]),
            assigned_to=choice(users).id if randint(0, 4) > 0 else None,
            status=choice(["New", "In Progress", "Closed"]),
            description=f"Phishing email from {email['from']} with subject: {email['subject']}",
            llm_summary=f"Email contains suspicious URL: {email['url']}. Marked as {email['result']} by detector."
        )
        phishing_incidents.append(incident)
        db.session.add(incident)
    
    # Malware incidents
    malware_incidents = []
    for file in incident_data["Malware"]["results"]:
        timestamp = datetime.now() - timedelta(days=randint(0, 7))
        
        incident = Incident(
            timestamp=timestamp,
            source_ip=fake.ipv4(),
            type="Malware",
            severity="Critical" if file["analysis_result"]["verdict"] == "Suspicious" else "High",
            ml_model_name="Malware Detection",
            confidence_score=float(file["analysis_result"]["probability"]),
            assigned_to=choice(users).id if randint(0, 4) > 0 else None,
            status=choice(["New", "In Progress", "Closed"]),
            description=f"{file['file_info']['file_type']} file detected: {file['file_info']['filename']}",
            llm_summary=f"File hash: {file['file_info']['sha256_hash']}. Verdict: {file['analysis_result']['verdict']}"
        )
        malware_incidents.append(incident)
        db.session.add(incident)
    
    # Network incidents
    network_incidents = []
    for net_event in incident_data["network"]["results"]:
        if net_event["prediction"] == "anomaly":
            timestamp = datetime.strptime(net_event["timestamp"], "%Y-%m-%d %H:%M:%S")
            
            incident = Incident(
                timestamp=timestamp,
                source_ip=fake.ipv4(),
                type="Network Anomaly",
                severity="High" if net_event["confidence"] < 0.05 else "Medium",
                ml_model_name="Anomaly Detection",
                confidence_score=float(net_event["confidence"]),
                assigned_to=choice(users).id if randint(0, 4) > 0 else None,
                status=choice(["New", "In Progress", "Closed"]),
                description=f"Network anomaly detected for service {net_event['features']['service']}",
                llm_summary=f"Anomalous network activity with protocol {net_event['features']['protocol_type']}. Flag: {net_event['features']['flag']}"
            )
            network_incidents.append(incident)
            db.session.add(incident)
    
    db.session.commit()
    return windows_incidents + phishing_incidents + malware_incidents + network_incidents

def create_fake_enrichments(incidents=None):
    """Create fake enrichments with VirusTotal and OpenCTI data"""
    if not incidents:
        incidents = Incident.query.all()
    
    for incident in incidents:
        # VirusTotal enrichment
        vt_enrichment = Enrichment(
            incident_id=incident.id,
            source="VirusTotal",
            data={
                'score': randint(0, 100),
                'details': "Sample VirusTotal analysis results",
                'link': f"https://www.virustotal.com/gui/file/{uuid.uuid4()}",
                'last_updated': fake.date_time_this_month().isoformat(),
                'malicious_votes': randint(1, 50) if incident.type == "Malware" else 0,
                'harmless_votes': randint(0, 20)
            }
        )
        db.session.add(vt_enrichment)
        
        # OpenCTI enrichment
        octi_enrichment = Enrichment(
            incident_id=incident.id,
            source="OpenCTI",
            data={
                'related_entities': randint(1, 5),
                'details': "Threat intelligence from OpenCTI",
                'link': f"https://demo.opencti.io/dashboard/threats/{uuid.uuid4()}",
                'last_updated': fake.date_time_this_month().isoformat(),
                'confidence_level': choice(["low", "medium", "high"])
            }
        )
        db.session.add(octi_enrichment)
        
        # Optional third enrichment
        if randint(0, 1):
            other_sources = ['ThreatFox']
            enrichment = Enrichment(
                incident_id=incident.id,
                source=choice(other_sources),
                data={
                    'score': randint(0, 100),
                    'details': fake.sentence(),
                    'link': fake.url(),
                    'last_updated': fake.date_time_this_month().isoformat()
                }
            )
            db.session.add(enrichment)
    
    db.session.commit()

def create_fake_analytics_logs(incidents=None, users=None):
    """Create fake analytics logs"""
    if not incidents:
        incidents = Incident.query.all()
    if not users:
        users = User.query.all()
    
    event_types = ['status_change', 'assignment', 'note_added', 'enrichment_added']
    
    for incident in incidents:
        # Create creation log
        creation_log = AnalyticsLog(
            incident_id=incident.id,
            analyst_id=choice(users).id,
            event_type='created',
            timestamp=incident.timestamp
        )
        db.session.add(creation_log)
        
        # Create status change logs if incident isn't new
        if incident.status != 'New':
            status_log = AnalyticsLog(
                incident_id=incident.id,
                analyst_id=incident.assigned_to or choice(users).id,
                event_type='status_change',
                timestamp=incident.timestamp + timedelta(hours=randint(1, 24))
            )
            db.session.add(status_log)
        
        # Create 1-3 random logs
        for _ in range(randint(1, 3)):
            log = AnalyticsLog(
                incident_id=incident.id,
                analyst_id=choice(users).id,
                event_type=choice(event_types),
                timestamp=incident.timestamp + timedelta(hours=randint(1, 72))
            )
            db.session.add(log)
    db.session.commit()

def create_system_settings():
    """Create default system settings"""
    settings = [
        {
            'name': 'fair_distribution_enabled',
            'value': True,
            'description': 'Whether to enable fair distribution of incidents among analysts'
        },
        {
            'name': 'analyst_capacity',
            'value': 20,
            'description': 'Default maximum incidents an analyst should have assigned'
        }
    ]
    
    for setting_data in settings:
        if not SystemSetting.query.filter_by(name=setting_data['name']).first():
            setting = SystemSetting(**setting_data)
            db.session.add(setting)
    db.session.commit()

def initialize_system_settings(app):
    """Initialize system settings for testing"""
    with app.app_context():
        from app.utils.settings import init_default_settings
        init_default_settings(app)

def seed_database(app):
    """Main function to seed the database"""
    with app.app_context():
        print("Initializing system settings...")
        initialize_system_settings(app)

        print("Creating specific users...")
        users = create_fake_users()
        
        print("Creating fake ML models...")
        ml_models = create_fake_ml_models()
        
        print("Creating enhanced LLM prompts...")
        llm_prompts = create_fake_llm_prompts()
        
        print("Creating system settings...")
        create_system_settings()
        
        print("Creating fake incidents from provided data...")
        incidents = create_fake_incidents(users=users, ml_models=ml_models)
        
        print("Creating enrichments with VirusTotal and OpenCTI data...")
        create_fake_enrichments(incidents=incidents)
        
        print("Creating fake analytics logs...")
        create_fake_analytics_logs(incidents=incidents, users=users)
        
        print("Database seeding completed successfully!")


import json
import re


def load_json_file(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# Utilities
def load_json_file(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def load_partial_json(path):
    with open(path, 'r', encoding='utf-8') as f:
        content = f.read()

    try:
        return json.loads(content)
    except json.JSONDecodeError as e:
        print(f"⚠️ Truncated or invalid JSON in {path}, attempting salvage...")

        # Try to recover just the 'results' array
        try:
            prefix = content.find('"results":')
            start = content.find('[', prefix)
            end = content.rfind(']')
            trimmed = content[start:end + 1].strip()
            if not trimmed.endswith(']'):
                trimmed += ']'
            fixed_json = {"count": 0, "results": json.loads(trimmed)}
            return fixed_json
        except Exception as e:
            print(f"❌ Failed to recover {path}: {e}")
            return {"count": 0, "results": []}

import json
import re
from json.decoder import JSONDecodeError

def load_and_fix_wazuh_json(path):
    """Load Wazuh JSON data with aggressive fixing of common issues"""
    with open(path, 'r', encoding='utf-8') as f:
        raw_content = f.read()

    # First attempt to parse as-is
    try:
        return json.loads(raw_content)
    except JSONDecodeError:
        pass

    # If that fails, try fixing common issues
    def fix_string(match):
        s = match.group(1)
        # Fix backslashes that aren't part of valid escape sequences
        s = re.sub(r'(?<!\\)\\(?![\\"ntbfr])', r'\\\\', s)
        # Fix unescaped quotes
        s = s.replace('"', '\\"')
        return f'"{s}"'

    # Apply fixes to all string values
    fixed_content = re.sub(r'"((?:\\.|[^"\\])*)"', fix_string, raw_content)

    try:
        return json.loads(fixed_content)
    except JSONDecodeError as e:
        print(f"⛔ Failed to load Wazuh JSON after fixes: {e}")
        return {"count": 0, "results": []}

def process_wazuh_events(raw_events):
    """Process Wazuh events with robust error handling"""
    cleaned_events = []
    error_count = 0
    
    for event in raw_events.get("results", []):
        try:
            # Handle the alert field
            alert_str = event.get("alert", "{}")
            try:
                alert_data = json.loads(alert_str)
            except JSONDecodeError:
                # Try cleaning the string
                alert_str = alert_str.replace('\\"', '"')
                alert_str = re.sub(r'\\(?![\\"ntbfr])', r'\\\\', alert_str)
                alert_data = json.loads(alert_str)

            # Handle the result field
            result_str = event.get("result", "{}")
            try:
                result_data = json.loads(result_str)
            except JSONDecodeError:
                # Try cleaning the string
                result_str = result_str.replace('\\"', '"')
                result_str = re.sub(r'\\(?![\\"ntbfr])', r'\\\\', result_str)
                result_data = json.loads(result_str)

            # Extract relevant fields with fallbacks
            cleaned_event = {
                "timestamp": alert_data.get("timestamp", ""),
                "raw_alert": alert_data,
                "raw_result": result_data,
                "process_name": result_data.get("event", "unknown"),
                "command_line": result_data.get("prediction", {})
                                   .get("event_data", {})
                                   .get("CommandLine", ""),
                "parent_process": result_data.get("prediction", {})
                                        .get("event_data", {})
                                        .get("ParentImage", ""),
                "rule_description": alert_data.get("rule", {})
                                        .get("description", "")
            }
            cleaned_events.append(cleaned_event)
            
        except Exception as e:
            error_count += 1
            print(f"⛔ Skipped Wazuh event ({error_count}): {str(e)}")
            continue

    print(f"Processed {len(cleaned_events)} Wazuh events ({error_count} errors)")
    return cleaned_events

# Load everything
if __name__ == '__main__':
    # Safe load for good files
    phishing_data = load_json_file('data/phishing_results.json')
    malware_data = load_json_file('data/malwares_results.json')
    network_data = load_partial_json('data/network_results.json')

    # Wazuh requires special handling (contains embedded JSON in strings)
    windows_raw = load_and_fix_wazuh_json('data/wazuh_results.json')
    cleaned_windows = process_wazuh_events(windows_raw)
    for event in windows_raw["results"]:
        try:
            raw_alert = json.loads(event["alert"])
            raw_result = json.loads(event["result"])
            cleaned_event = {
                "timestamp": raw_alert["timestamp"],
                "raw_alert": raw_alert,
                "raw_result": raw_result,
                "process_name": raw_result.get("event", "unknown"),
                "command_line": raw_result["prediction"]["event_data"].get("CommandLine", ""),
                "parent_process": raw_result["prediction"]["event_data"].get("ParentImage", ""),
                "rule_description": raw_alert["rule"]["description"]
            }
            cleaned_windows.append(cleaned_event)
        except Exception as e:
            print(f"⛔ Skipped Wazuh event: {e}")


    incident_data = {
        "Windows_events": {
            "count": len(cleaned_windows),
            "results": cleaned_windows
        },
        "Phishing": phishing_data,
        "Malware": malware_data,
        "network": network_data
    }

    app = create_app()
    with app.app_context():
        db.drop_all()
        db.create_all()
        seed_database(app)

