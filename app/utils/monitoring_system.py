class BaseMonitor:
    """Base class for monitoring systems"""
    
    def __init__(self, config):
        self.config = config
        self.active = False
        self.last_check = None
    
    def get_status(self):
        """Get current status of monitoring system"""
        return {
            'status': 'Active' if self.active else 'Inactive',
            'active': self.active,
            'last_updated': self.last_check.strftime('%Y-%m-%d %H:%M:%S') if self.last_check else None,
            'alert_count': 0  # Should be overridden by child classes
        }
    
    def get_details(self, **kwargs):
        """Get detailed information for a specific incident context
        Override in child classes to provide specific implementation"""
        return {
            'status': 'Not implemented',
            'details': {},
            'active': self.active
        }


class WazuhMonitor(BaseMonitor):
    """Monitor for Wazuh security events"""
    
    def get_status(self):
        """Get Wazuh monitoring status"""
        status = super().get_status()
        
        try:
            # Make API call to Wazuh to get alerts count
            import requests
            from datetime import datetime
            
            # Get authentication token (in a real implementation, you'd handle this better)
            auth_endpoint = f"{self.config['api_url']}/security/user/authenticate"
            auth_headers = {'Content-Type': 'application/json'}
            auth_response = requests.post(
                auth_endpoint, 
                headers=auth_headers,
                auth=(self.config['api_user'], self.config['api_password']),
                verify=False  # In production, you should use proper certificate verification
            )
            
            if auth_response.status_code == 200:
                token = auth_response.json()['data']['token']
                
                # Get alerts count
                alerts_endpoint = f"{self.config['api_url']}/alerts/summary"
                headers = {
                    'Content-Type': 'application/json',
                    'Authorization': f'Bearer {token}'
                }
                response = requests.get(alerts_endpoint, headers=headers, verify=False)
                
                if response.status_code == 200:
                    alert_data = response.json().get('data', {})
                    alert_count = alert_data.get('total', 0)
                    status['alert_count'] = alert_count
                    status['status'] = 'Active' if alert_count > 0 else 'Idle'
                    self.last_check = datetime.now()
            
            status['last_updated'] = self.last_check.strftime('%Y-%m-%d %H:%M:%S') if self.last_check else None
            return status
            
        except Exception as e:
            status['status'] = f'Error: {str(e)}'
            return status
    
    def get_details(self, source_ip=None, timestamp=None, **kwargs):
        """Get Wazuh alerts related to a specific IP and time range"""
        try:
            import requests
            from datetime import datetime, timedelta
            
            # If no timestamp provided, use current time
            if timestamp is None:
                timestamp = datetime.now()
            
            # Set time range (30 min before and after the incident)
            time_range = {
                'from': (timestamp - timedelta(minutes=30)).strftime('%Y-%m-%dT%H:%M:%S'),
                'to': (timestamp + timedelta(minutes=30)).strftime('%Y-%m-%dT%H:%M:%S')
            }
            
            # Get authentication token
            auth_endpoint = f"{self.config['api_url']}/security/user/authenticate"
            auth_headers = {'Content-Type': 'application/json'}
            auth_response = requests.post(
                auth_endpoint, 
                headers=auth_headers,
                auth=(self.config['api_user'], self.config['api_password']),
                verify=False
            )
            
            if auth_response.status_code != 200:
                return {
                    'status': 'Error authenticating with Wazuh API',
                    'alerts': [],
                    'count': 0
                }
            
            token = auth_response.json()['data']['token']
            
            # Construct query for alerts
            query = {
                'select': ['rule.id', 'rule.description', 'agent.name', 'agent.ip', 'timestamp', 'rule.level'],
                'where': {}
            }
            
            # Add source IP filter if provided
            if source_ip:
                query['where']['srcip'] = source_ip
            
            # Add time range
            query['where']['timestamp'] = {
                '>=': time_range['from'],
                '<=': time_range['to']
            }
            
            # Get alerts
            alerts_endpoint = f"{self.config['api_url']}/alerts"
            headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {token}'
            }
            response = requests.post(
                alerts_endpoint, 
                headers=headers, 
                json=query,
                verify=False
            )
            
            if response.status_code != 200:
                return {
                    'status': f'Error {response.status_code} from Wazuh API',
                    'alerts': [],
                    'count': 0
                }
            
            alert_data = response.json().get('data', {})
            alerts = alert_data.get('affected_items', [])
            
            return {
                'status': 'Success',
                'alerts': alerts,
                'count': len(alerts),
                'time_range': time_range
            }
            
        except Exception as e:
            return {
                'status': f'Error: {str(e)}',
                'alerts': [],
                'count': 0
            }


class EmailMonitor(BaseMonitor):
    """Monitor for email security events"""
    
    def get_status(self):
        """Get email monitoring status"""
        status = super().get_status()
        
        try:
            # This would be implemented with actual email server connection
            # For now, we'll simulate with random data
            import random
            from datetime import datetime
            
            status['alert_count'] = random.randint(0, 20)
            status['status'] = 'Active' if status['alert_count'] > 0 else 'Idle'
            self.last_check = datetime.now()
            status['last_updated'] = self.last_check.strftime('%Y-%m-%d %H:%M:%S')
            
            return status
        except Exception as e:
            status['status'] = f'Error: {str(e)}'
            return status
    
    def get_details(self, timestamp=None, **kwargs):
        """Get email alerts related to a specific time range"""
        try:
            from datetime import datetime, timedelta
            import random
            
            # If no timestamp provided, use current time
            if timestamp is None:
                timestamp = datetime.now()
            
            # Set time range (30 min before and after the incident)
            time_from = timestamp - timedelta(minutes=30)
            time_to = timestamp + timedelta(minutes=30)
            
            # In a real implementation, this would query your email server
            # For demo purposes, generate random email alerts
            alert_count = random.randint(1, 5)
            alerts = []
            
            email_types = ['phishing', 'spam', 'malware', 'suspicious link']
            domains = ['example.com', 'suspicious-site.com', 'malware-delivery.net', 'legitimate-business.com']
            
            for i in range(alert_count):
                alert_time = timestamp - timedelta(minutes=random.randint(0, 25))
                alerts.append({
                    'id': f"email_{random.randint(10000, 99999)}",
                    'timestamp': alert_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'from': f"sender{random.randint(1,100)}@{random.choice(domains)}",
                    'subject': f"Subject for {random.choice(email_types)} email",
                    'type': random.choice(email_types),
                    'score': round(random.uniform(0.7, 1.0), 2),
                    'attachment': bool(random.getrandbits(1))
                })
            
            return {
                'status': 'Success',
                'alerts': alerts,
                'count': len(alerts),
                'time_range': {
                    'from': time_from.strftime('%Y-%m-%d %H:%M:%S'),
                    'to': time_to.strftime('%Y-%m-%d %H:%M:%S')
                }
            }
            
        except Exception as e:
            return {
                'status': f'Error: {str(e)}',
                'alerts': [],
                'count': 0
            }


class NetworkHostMonitor(BaseMonitor):
    """Monitor for network and host security events"""
    
    def get_status(self):
        """Get network/host monitoring status"""
        status = super().get_status()
        
        try:
            # This would be implemented with actual networking monitoring API calls
            # For now, we'll simulate with random data
            import random
            from datetime import datetime
            
            status['alert_count'] = random.randint(0, 30)
            status['status'] = 'Active' if status['alert_count'] > 0 else 'Idle'
            self.last_check = datetime.now()
            status['last_updated'] = self.last_check.strftime('%Y-%m-%d %H:%M:%S')
            
            return status
        except Exception as e:
            status['status'] = f'Error: {str(e)}'
            return status
    
    def get_details(self, source_ip=None, timestamp=None, **kwargs):
        """Get network alerts related to a specific IP and time range"""
        try:
            from datetime import datetime, timedelta
            import random
            
            # If no timestamp provided, use current time
            if timestamp is None:
                timestamp = datetime.now()
            
            # Set time range (30 min before and after the incident)
            time_from = timestamp - timedelta(minutes=30)
            time_to = timestamp + timedelta(minutes=30)
            
            # In a real implementation, this would query your network monitoring system
            # For demo purposes, generate random network alerts
            alert_count = random.randint(2, 7)
            alerts = []
            
            alert_types = ['port_scan', 'brute_force', 'unusual_traffic', 'data_exfiltration', 'lateral_movement']
            protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'FTP', 'SMB']
            
            # Default IP if none provided
            if not source_ip:
                source_ip = f"192.168.1.{random.randint(2, 254)}"
            
            for i in range(alert_count):
                dest_ip = f"10.0.0.{random.randint(2, 254)}"
                alert_time = timestamp - timedelta(minutes=random.randint(0, 25))
                
                alerts.append({
                    'id': f"net_{random.randint(10000, 99999)}",
                    'timestamp': alert_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'source_ip': source_ip,
                    'destination_ip': dest_ip,
                    'protocol': random.choice(protocols),
                    'port': random.randint(1, 65535),
                    'type': random.choice(alert_types),
                    'severity': random.choice(['Critical', 'High', 'Medium', 'Low']),
                    'bytes_transferred': random.randint(100, 10000000)
                })
            
            return {
                'status': 'Success',
                'alerts': alerts,
                'count': len(alerts),
                'source_ip': source_ip,
                'time_range': {
                    'from': time_from.strftime('%Y-%m-%d %H:%M:%S'),
                    'to': time_to.strftime('%Y-%m-%d %H:%M:%S')
                }
            }
            
        except Exception as e:
            return {
                'status': f'Error: {str(e)}',
                'alerts': [],
                'count': 0
            }


class PEMonitor(BaseMonitor):
    """Monitor for Windows PE (executable) files"""
    
    def get_status(self):
        """Get PE file monitoring status"""
        status = super().get_status()
        
        try:
            # This would be implemented with actual file monitoring system
            # For now, we'll simulate with random data
            import random
            from datetime import datetime
            
            status['alert_count'] = random.randint(0, 15)
            status['status'] = 'Active' if status['alert_count'] > 0 else 'Idle'
            self.last_check = datetime.now()
            status['last_updated'] = self.last_check.strftime('%Y-%m-%d %H:%M:%S')
            
            return status
        except Exception as e:
            status['status'] = f'Error: {str(e)}'
            return status
    
    def get_details(self, timestamp=None, **kwargs):
        """Get PE file alerts related to a specific time range"""
        try:
            from datetime import datetime, timedelta
            import random
            
            # If no timestamp provided, use current time
            if timestamp is None:
                timestamp = datetime.now()
            
            # Set time range (30 min before and after the incident)
            time_from = timestamp - timedelta(minutes=30)
            time_to = timestamp + timedelta(minutes=30)
            
            # In a real implementation, this would query your PE file monitoring system
            # For demo purposes, generate random PE file alerts
            alert_count = random.randint(1, 4)
            alerts = []
            
            file_types = ['executable', 'dll', 'driver', 'script']
            malware_types = ['trojan', 'ransomware', 'backdoor', 'dropper', 'worm']
            
            for i in range(alert_count):
                alert_time = timestamp - timedelta(minutes=random.randint(0, 25))
                file_name = f"suspicious_file_{random.randint(1000, 9999)}.{random.choice(['exe', 'dll', 'sys', 'bat'])}"
                
                alerts.append({
                    'id': f"pe_{random.randint(10000, 99999)}",
                    'timestamp': alert_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'file_name': file_name,
                    'file_path': f"C:\\Users\\{random.choice(['admin', 'user'])}\\Downloads\\{file_name}",
                    'file_type': random.choice(file_types),
                    'file_size': random.randint(10000, 5000000),
                    'md5': ''.join(random.choice('0123456789abcdef') for _ in range(32)),
                    'sha256': ''.join(random.choice('0123456789abcdef') for _ in range(64)),
                    'detected_as': random.choice(malware_types),
                    'severity': random.choice(['Critical', 'High', 'Medium', 'Low']),
                    'confidence': round(random.uniform(0.7, 1.0), 2)
                })
            
            return {
                'status': 'Success',
                'alerts': alerts,
                'count': len(alerts),
                'time_range': {
                    'from': time_from.strftime('%Y-%m-%d %H:%M:%S'),
                    'to': time_to.strftime('%Y-%m-%d %H:%M:%S')
                }
            }
            
        except Exception as e:
            return {
                'status': f'Error: {str(e)}',
                'alerts': [],
                'count': 0
            }

class NetworkTrafficMonitor(BaseMonitor):
    """Monitor for network traffic analysis results"""
    
    def __init__(self, config):
        super().__init__(config)
        self.results_cache = []
        self.last_results_count = 0
    
    def get_status(self):
        """Get network traffic monitoring status"""
        status = super().get_status()
        
        try:
            # Update with actual results count
            status['alert_count'] = self.last_results_count
            status['status'] = 'Active' if self.active else 'Inactive'
            self.last_check = datetime.now()
            status['last_updated'] = self.last_check.strftime('%Y-%m-%d %H:%M:%S')
            
            # Add specific network monitoring metrics
            status.update({
                'monitoring': {
                    'active': self.active,
                    'last_results_count': self.last_results_count,
                    'last_anomaly': self._get_last_anomaly_time(),
                    'prediction_stats': self._get_prediction_stats()
                }
            })
            
            return status
        except Exception as e:
            status['status'] = f'Error: {str(e)}'
            return status
    
    def _get_last_anomaly_time(self):
        """Get timestamp of last anomaly detected"""
        if not self.results_cache:
            return None
        
        anomalies = [r for r in self.results_cache if r['prediction'].lower() != 'normal']
        if not anomalies:
            return None
            
        last_anomaly = max(anomalies, key=lambda x: x['timestamp'])
        return last_anomaly['timestamp']
    
    def _get_prediction_stats(self):
        """Get statistics about predictions"""
        if not self.results_cache:
            return {}
            
        total = len(self.results_cache)
        normal = len([r for r in self.results_cache if r['prediction'].lower() == 'normal'])
        anomalies = total - normal
        
        return {
            'total': total,
            'normal': normal,
            'anomalies': anomalies,
            'anomaly_rate': anomalies / total if total > 0 else 0
        }
    
    def get_details(self, source_ip=None, timestamp=None, limit=100, **kwargs):
        """Get network traffic analysis results"""
        try:
            from datetime import datetime, timedelta
            
            # If we have cached results, use those
            if self.results_cache:
                results = self.results_cache
            else:
                # In a real implementation, this would query your network traffic analysis system
                # For now, we'll return an empty result set
                results = []
            
            # Apply filters if provided
            filtered_results = results
            
            if source_ip:
                filtered_results = [
                    r for r in filtered_results 
                    if r['features'].get('src_ip') == source_ip or 
                       r['features'].get('dst_ip') == source_ip
                ]
            
            if timestamp:
                # Convert timestamp to datetime if it's a string
                if isinstance(timestamp, str):
                    timestamp = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
                
                # Filter for results within 30 minutes of the timestamp
                time_from = timestamp - timedelta(minutes=30)
                time_to = timestamp + timedelta(minutes=30)
                
                filtered_results = [
                    r for r in filtered_results
                    if time_from <= datetime.strptime(r['timestamp'], '%Y-%m-%d %H:%M:%S') <= time_to
                ]
            
            # Apply limit
            filtered_results = filtered_results[:limit]
            
            # Format results for display
            formatted_results = []
            for result in filtered_results:
                features = result['features']
                formatted_results.append({
                    'timestamp': result['timestamp'],
                    'prediction': result['prediction'],
                    'confidence': result['confidence'],
                    'protocol': features.get('protocol_type', 'unknown'),
                    'service': features.get('service', 'unknown'),
                    'src_bytes': features.get('src_bytes', 0),
                    'dst_bytes': features.get('dst_bytes', 0),
                    'flag': features.get('flag', 'OTHER'),
                    'duration': features.get('duration', 0),
                    'src_ip': features.get('src_ip', 'unknown'),
                    'dst_ip': features.get('dst_ip', 'unknown')
                })
            
            return {
                'status': 'Success',
                'count': len(filtered_results),
                'results': formatted_results,
                'prediction_stats': self._get_prediction_stats(),
                'source_ip': source_ip,
                'timestamp_filter': timestamp.strftime('%Y-%m-%d %H:%M:%S') if timestamp else None
            }
            
        except Exception as e:
            return {
                'status': f'Error: {str(e)}',
                'count': 0,
                'results': []
            }
    
    def update_results(self, new_results):
        """Update the monitor with new results data"""
        try:
            # Validate new results format
            if not isinstance(new_results, dict) or 'results' not in new_results:
                raise ValueError("Invalid results format - expected dict with 'results' key")
            
            # Store the results
            self.results_cache = new_results['results']
            self.last_results_count = len(self.results_cache)
            self.last_check = datetime.now()
            
            # Return stats about the update
            return {
                'status': 'Success',
                'new_results_count': self.last_results_count,
                'anomalies_detected': len([r for r in self.results_cache if r['prediction'].lower() != 'normal'])
            }
            
        except Exception as e:
            return {
                'status': f'Error: {str(e)}',
                'new_results_count': 0
            }