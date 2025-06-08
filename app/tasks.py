import click
from flask.cli import with_appcontext
from app.routes import fetch_monitoring_results

def register_tasks(app):
    @app.cli.command('ingest-monitoring-results')
    @with_appcontext
    def ingest_monitoring_results():
        """Fetch and ingest monitoring service results into the Incident database."""
        fetch_monitoring_results()
        click.echo('Monitoring service results ingested into the Incident database.')
