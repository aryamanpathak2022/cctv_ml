"""Web dashboard for vulnerability visualization and reporting"""

from .app import create_dashboard_app
from .views import dashboard_blueprint

__all__ = ["create_dashboard_app", "dashboard_blueprint"]