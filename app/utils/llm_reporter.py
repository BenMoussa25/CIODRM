class LLMReporter:
    def __init__(self):
        self.llm_endpoint = "http://192.168.8.128:9999"

    def get_recent_reports(self, limit=5):
        # Replace with actual LLM report retrieval
        return [
            {
                'title': 'Phishing Campaign Detected',
                'summary': 'Model 1 identified a new phishing campaign',
                'timestamp': '2023-11-15 09:15:00',
                'severity': 'High'
            },
            {
                'title': 'Unusual Data Exfiltration',
                'summary': 'Model 3 detected anomalous data transfer',
                'timestamp': '2023-11-15 08:30:00',
                'severity': 'Critical'
            }
        ][:limit]

    def generate_incident_report(self, incident, prompt=None):
        """Generate a report for an incident using the Mistral model"""
        import requests
        
        if not prompt:
            # Default prompt if none provided
            prompt = f"""Given this security incident, provide a detailed analysis:
            - Incident Type: {incident.type}
            - Source IP: {incident.source_ip}
            - Severity: {incident.severity}
            - ML Model: {incident.ml_model_name}
            - Confidence Score: {incident.confidence_score}
            - Description: {incident.description}
            
            Provide:
            1. Detailed analysis of the incident
            2. Potential impact assessment
            3. Recommended actions
            4. Prevention measures"""

        try:
            response = requests.post(
                f"{self.llm_endpoint}/chat",
                json={"message": prompt}
            )
            response.raise_for_status()
            return response.json()["response"]
        except Exception as e:
            return f"Error generating report: {str(e)}"

    def generate_test_report(self, custom_prompt):
        """Generate a test report using custom prompt"""
        import requests
        
        try:
            response = requests.post(
                f"{self.llm_endpoint}/chat",
                json={"message": custom_prompt}
            )
            response.raise_for_status()
            return response.json()["response"]
        except Exception as e:
            return f"Error generating report: {str(e)}"