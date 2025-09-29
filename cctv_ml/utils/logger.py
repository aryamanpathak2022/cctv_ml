"""
Logging utilities for CCTV ML vulnerability assessment tool.
"""

import logging
import logging.handlers
import os
from pathlib import Path
from typing import Optional
import colorlog


def setup_logger(name: str, level: str = "INFO", log_file: Optional[str] = None) -> logging.Logger:
    """
    Set up a logger with both console and file output.
    
    Args:
        name: Logger name
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional log file path
        
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    
    # Avoid duplicate handlers
    if logger.handlers:
        return logger
    
    # Set logging level
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(numeric_level)
    
    # Create formatters
    detailed_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s - [%(filename)s:%(lineno)d]'
    )
    
    console_formatter = colorlog.ColoredFormatter(
        '%(log_color)s%(asctime)s - %(name)s - %(levelname)s - %(message)s%(reset)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        log_colors={
            'DEBUG': 'cyan',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'bold_red',
        }
    )
    
    # Console handler with colors
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(console_formatter)
    console_handler.setLevel(numeric_level)
    logger.addHandler(console_handler)
    
    # File handler if specified
    if log_file:
        # Ensure log directory exists
        log_dir = os.path.dirname(log_file)
        if log_dir:
            Path(log_dir).mkdir(parents=True, exist_ok=True)
        
        # Rotating file handler to prevent huge log files
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5
        )
        file_handler.setFormatter(detailed_formatter)
        file_handler.setLevel(logging.DEBUG)  # File logs everything
        logger.addHandler(file_handler)
    
    return logger


class SecurityLogger:
    """Specialized logger for security events and audit trails."""
    
    def __init__(self, log_file: str = "logs/security.log"):
        """Initialize security logger."""
        self.logger = setup_logger("SecurityAudit", "INFO", log_file)
    
    def log_scan_start(self, target: str, scan_type: str):
        """Log start of security scan."""
        self.logger.info(f"SCAN_START: {scan_type} scan initiated against {target}")
    
    def log_scan_complete(self, target: str, scan_type: str, results_count: int):
        """Log completion of security scan."""
        self.logger.info(f"SCAN_COMPLETE: {scan_type} scan completed on {target}, {results_count} results")
    
    def log_vulnerability_found(self, target: str, vuln_type: str, severity: str):
        """Log discovery of vulnerability."""
        self.logger.warning(f"VULN_FOUND: {severity} {vuln_type} vulnerability discovered on {target}")
    
    def log_exploitation_attempt(self, target: str, vuln_type: str, success: bool):
        """Log exploitation attempt."""
        status = "SUCCESS" if success else "FAILED"
        self.logger.critical(f"EXPLOIT_{status}: {vuln_type} exploitation {status.lower()} on {target}")
    
    def log_access_attempt(self, target: str, method: str, success: bool):
        """Log access attempt."""
        status = "GRANTED" if success else "DENIED"
        self.logger.warning(f"ACCESS_{status}: {method} access {status.lower()} for {target}")
    
    def log_credential_test(self, target: str, username: str, success: bool):
        """Log credential testing."""
        status = "VALID" if success else "INVALID"
        self.logger.warning(f"CRED_{status}: {username} credentials {status.lower()} on {target}")
    
    def log_config_change(self, component: str, change: str):
        """Log configuration changes."""
        self.logger.info(f"CONFIG_CHANGE: {component} - {change}")
    
    def log_error(self, component: str, error: str):
        """Log errors."""
        self.logger.error(f"ERROR: {component} - {error}")


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance with standard configuration."""
    return setup_logger(name)