from flask import Flask
from config import DevelopmentConfig
import logging
from logging.handlers import RotatingFileHandler
from app import create_app

app = create_app()
app.config.from_object(DevelopmentConfig)

if __name__ == '__main__':
    # Configure logging
    handler = RotatingFileHandler('soc_dashboard.log', maxBytes=10000, backupCount=1)
    handler.setLevel(logging.INFO)
    app.logger.addHandler(handler)
    
    # Run the application
    app.run(debug=True, host='0.0.0.0', port=5000)