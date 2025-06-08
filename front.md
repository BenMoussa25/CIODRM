# AI & CTI Threat Detection Dashboard

## Overview
This project is an AI-powered Security Operations Center (SOC) dashboard designed to detect and monitor cybersecurity threats using multiple Cyber Threat Intelligence (CTI) data sources. It integrates machine learning, natural language processing (NLP), and external APIs to provide real-time incident analysis, threat detection, and automated reporting.

The dashboard offers visualizations of security incidents, anomaly detection, threat actor insights, and workload monitoring, aiming to assist SOC analysts in prioritizing and investigating threats effectively.

---

# Security Incident Management Platform 

---

## 1. FRONTEND MODULE

*Stack*: Flask + HTML + CSS + Bootstrap

### Authentication

- `/login`: Login form with username/password  
- Role-based redirect (analyst, manager, admin)  
- Get the JWT Token  

---

### Dashboard `/dashboard`

- **Stats:** Total alerts today/week/month  
- **Charts:** Active incidents per severity, alert types (bar/pie), analyst workload heatmap  
- **Integrations:** API/ML model health status  

---

### Incident Management

#### `/incidents` (Table View)

- Incident cards: ID, Type, Severity, Status, Assigned Analyst  
- Filters: time, type, status  
- Sort: timestamp, severity  
- Bulk actions: assign, close, escalate  

#### `/incident/:id` (Detail View)

- **Summary:** IPs, alert type, ML result, time  
- **Tabs:**  
  - **ML Metadata:** Model name, confidence  
  - **Enrichment:** VirusTotal, OpenCTI, Cortex, Hive links  
  - **LLM Report:** Narrative, threat hypothesis, suggested actions  
  - **Actions:** assign, tag false positive, comment  

---

### Analytics `/analytics`

- MTTR, top alert types, volume trends, analyst performance, false positives  
- Export: PDF/CSV  

---

### Workload `/workload`

- Analyst list, incident count, assign/reassign, fair distribution toggle  

---

### ML API Management `/ml-models`

- Model table: name, purpose, version, status, endpoint  
- Add/Edit/Delete, activate/deactivate, test endpoint, health/stats  

---

### Monitoring System Management `/monitoring`

- Model table: name, purpose, version, status, endpoint  
- Activate/deactivate, test endpoint, health/stats, get results  

---

### LLM Config `/llm-config`

- Prompt templates for phishing, malware, zero-day  
- API keys, token stats, per-alert-type overrides  

---

### Integration Settings `/integrations`

- Configure VirusTotal, OpenCTI  
- API health check, search patterns  

---

## Key Features
- Real-time monitoring of cybersecurity incidents and alerts  
- Integration with CTI platforms and APIs for enriched threat intelligence  
- Automated incident classification using AI/ML models  
- Natural Language Generation (NLG) for generating analyst-friendly reports  
- User authentication and role-based access control  
- Interactive dashboards for incident analysis, workload, and analytics  
- Background task processing for data updates and model inference  

## Technology Stack
- Python 3.10 with Flask web framework  
- HTML/CSS for frontend with Jinja2 templating  
- AI/ML components for incident detection and report generation  
- REST APIs for CTI data integration  
- SQLite or other database for persistent storage  
- Background task queue (e.g., Celery or custom) for asynchronous processing  

## Installation

1. **Clone the repository:**
   ```bash
   git clone <repository_url>
   cd soc_dashboard
