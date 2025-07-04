# SOC Dashboard

A comprehensive Security Operations Center (SOC) dashboard application built with Flask, providing real-time monitoring, incident management, and security analytics capabilities.

## Features

### 1. Real-time Security Monitoring
- Network traffic analysis with machine learning-based anomaly detection
- Email security monitoring for phishing and malware
- Windows log analysis through Wazuh integration
- PE (Portable Executable) file monitoring for malware detection
- Real-time health monitoring of all security services

### 2. Incident Management
- Automated incident creation from multiple security sources
- Incident prioritization based on severity levels
- Customizable incident workflows
- Incident enrichment with contextual data
- LLM-powered incident summaries and analysis

### 3. Advanced Analytics
- Real-time metrics and KPIs
- Severity distribution analysis
- Alert type distribution tracking
- Mean Time To Resolution (MTTR) tracking
- Analyst performance monitoring
- Export capabilities (CSV, PDF)

### 4. Machine Learning Integration
- Multiple ML models for security analysis:
  - Anomaly Detection
  - Malware Detection
  - Phishing Detection
  - Windows Log Analysis
- Model health monitoring
- Performance metrics tracking
- Real-time prediction capabilities

### 5. Workload Management
- Analyst workload tracking
- Automated task assignment
- Fair distribution algorithms
- Real-time capacity monitoring
- Team performance analytics

### 6. Role-Based Access Control
- Multiple user roles:
  - Analyst
  - Manager
  - Administrator
- Role-specific features and views
- Secure authentication system

## Technology Stack

- **Backend**: Python Flask
- **Database**: SQLite
- **Frontend**: 
  - Bootstrap 5
  - Chart.js for visualizations
  - jQuery for dynamic interactions
- **Security Components**:
  - JWT for authentication
  - Role-based access control
  - Secure API endpoints

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd soc_dashboard
```

2. Create a virtual environment and activate it:
```bash
python -m venv venv
.\venv\Scripts\activate  # Windows
source venv/bin/activate  # Linux/Mac
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Initialize the database:
```bash
python init_data.py
```

5. Create an admin user:
```bash
python create_admin.py
```

6. Start the application:
```bash
python run.py
```

## Configuration

The application can be configured through multiple configuration files:

- `config.py`: Main application configuration
- `instance/config.py`: Instance-specific configuration (not version controlled)

Key configuration options:
- Database settings
- Security service endpoints
- Authentication settings
- Monitoring intervals

## API Endpoints

### Incident Management
- `POST /api/incidents/ingest`: Ingest new security incidents
- `GET /api/incidents`: Retrieve incident list
- `PUT /api/incidents/<id>`: Update incident details

### Monitoring
- `GET /api/monitoring/all/status`: Get status of all monitoring services
- `POST /api/monitoring/<service>/start`: Start a monitoring service
- `POST /api/monitoring/<service>/stop`: Stop a monitoring service

### Analytics
- `GET /api/analytics/metrics`: Get dashboard metrics
- `GET /api/analytics/export/csv`: Export analytics data as CSV
- `GET /api/analytics/export/pdf`: Export analytics data as PDF

### ML Models
- `GET /api/ml-models/<model_id>/health`: Check model health
- `POST /api/ml-models/<model_id>/test`: Test model with sample data

## Directory Structure

```
soc_dashboard/
├── app/
│   ├── static/          # Static files (CSS, JS)
│   ├── templates/       # HTML templates
│   ├── utils/          # Utility modules
│   ├── models.py       # Database models
│   ├── routes.py       # Route handlers
│   └── auth.py         # Authentication logic
├── instance/           # Instance-specific files
├── config.py           # Configuration
├── requirements.txt    # Dependencies
└── run.py             # Application entry point
```

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Commit changes: `git commit -am 'Add feature'`
4. Push to the branch: `git push origin feature-name`
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.