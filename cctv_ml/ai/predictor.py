"""
AI-Powered Vulnerability Predictor for CCTV devices.

This module uses machine learning to predict potential zero-day vulnerabilities
and assess the security posture of discovered CCTV devices.
"""

import logging
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
import json
import pickle
import os

try:
    from sklearn.ensemble import RandomForestClassifier, IsolationForest
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.preprocessing import StandardScaler, LabelEncoder
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, accuracy_score
    sklearn_available = True
except ImportError:
    sklearn_available = False

from .models import ZeroDayPredictor, ThreatIntelligenceEngine
from ..utils.logger import setup_logger


class VulnerabilityPredictor:
    """
    AI-powered vulnerability prediction engine for CCTV devices.
    
    Features:
    - Zero-day vulnerability prediction using ML models
    - Behavioral anomaly detection
    - Threat intelligence integration
    - Risk scoring and prioritization
    """
    
    def __init__(self, config):
        """Initialize the vulnerability predictor."""
        self.config = config
        self.logger = setup_logger("VulnPredictor", config.log_level)
        
        # Initialize models
        self.zero_day_predictor = ZeroDayPredictor(config)
        self.threat_intel_engine = ThreatIntelligenceEngine(config)
        
        # ML components
        self.vulnerability_classifier = None
        self.anomaly_detector = None
        self.feature_scaler = StandardScaler()
        self.text_vectorizer = TfidfVectorizer(max_features=1000)
        
        # Load or initialize models
        self._load_models()
        
        # Vulnerability patterns and features
        self.vulnerability_features = [
            'manufacturer_risk_score',
            'firmware_age_days', 
            'default_credentials',
            'encryption_strength',
            'open_ports_count',
            'web_interface_complexity',
            'authentication_methods',
            'known_cve_count',
            'device_popularity_score',
            'network_exposure_score'
        ]
        
    async def predict_vulnerabilities(self, device: Dict[str, Any], 
                                    known_vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Predict potential vulnerabilities for a CCTV device using AI.
        
        Args:
            device: Device information from scanning
            known_vulns: List of already discovered vulnerabilities
            
        Returns:
            List of predicted vulnerabilities with confidence scores
        """
        self.logger.info(f"Predicting vulnerabilities for {device['ip']}")
        
        predictions = []
        
        try:
            # Extract features from device
            features = self._extract_device_features(device, known_vulns)
            
            # Zero-day vulnerability prediction
            zero_day_predictions = await self.zero_day_predictor.predict(device, features)
            predictions.extend(zero_day_predictions)
            
            # Behavioral anomaly detection
            anomaly_predictions = self._detect_anomalies(device, features)
            predictions.extend(anomaly_predictions)
            
            # Threat intelligence correlation
            threat_intel_predictions = await self.threat_intel_engine.correlate_threats(device)
            predictions.extend(threat_intel_predictions)
            
            # Risk-based vulnerability prediction
            risk_predictions = self._predict_risk_based_vulns(device, features)
            predictions.extend(risk_predictions)
            
            # Filter and rank predictions
            filtered_predictions = self._filter_and_rank_predictions(predictions)
            
            self.logger.info(f"Generated {len(filtered_predictions)} vulnerability predictions")
            return filtered_predictions
            
        except Exception as e:
            self.logger.error(f"Vulnerability prediction failed: {str(e)}")
            return []
    
    def _extract_device_features(self, device: Dict[str, Any], 
                                known_vulns: List[Dict[str, Any]]) -> Dict[str, float]:
        """Extract numerical features from device for ML prediction."""
        features = {}
        
        # Manufacturer risk scoring
        manufacturer = device.get('manufacturer', '').lower()
        manufacturer_risks = {
            'hikvision': 0.8,  # High due to past vulnerabilities
            'dahua': 0.7,
            'foscam': 0.9,     # Very high due to poor security record
            'tp-link': 0.6,
            'axis': 0.3,       # Generally better security
            'bosch': 0.2,
            'unknown': 0.5
        }
        features['manufacturer_risk_score'] = manufacturer_risks.get(manufacturer, 0.5)
        
        # Firmware age estimation (if available)
        firmware_version = device.get('firmware_version', '')
        features['firmware_age_days'] = self._estimate_firmware_age(firmware_version)
        
        # Default credentials risk
        features['default_credentials'] = 1.0 if device.get('default_credentials') else 0.0
        
        # Encryption strength assessment
        features['encryption_strength'] = self._assess_encryption_strength(device)
        
        # Open ports count (security exposure)
        features['open_ports_count'] = len(device.get('open_ports', []))
        
        # Web interface complexity (more complex = more attack surface)
        features['web_interface_complexity'] = self._assess_interface_complexity(device)
        
        # Authentication methods assessment
        features['authentication_methods'] = self._assess_auth_methods(device)
        
        # Known CVE count for this device type/manufacturer
        features['known_cve_count'] = len([v for v in known_vulns if v.get('cve_id')])
        
        # Device popularity score (more popular = more likely to be targeted)
        features['device_popularity_score'] = self._calculate_popularity_score(device)
        
        # Network exposure score
        features['network_exposure_score'] = self._calculate_exposure_score(device)
        
        return features
    
    def _estimate_firmware_age(self, firmware_version: str) -> float:
        """Estimate firmware age in days based on version string."""
        if not firmware_version:
            return 365.0  # Assume 1 year if unknown
        
        # Try to extract date patterns from version
        import re
        
        # Look for year patterns (e.g., v2.1.2023, 20230401)
        year_match = re.search(r'20(\d{2})', firmware_version)
        if year_match:
            year = int('20' + year_match.group(1))
            current_year = datetime.now().year
            age_years = current_year - year
            return max(0, age_years * 365)
        
        # Version-based heuristic (higher versions are newer)
        version_match = re.search(r'(\d+)\.(\d+)(?:.(\d+))?', firmware_version)
        if version_match:
            major = int(version_match.group(1))
            minor = int(version_match.group(2))
            
            # Heuristic: newer versions have lower age
            if major >= 5:
                return 180.0  # 6 months
            elif major >= 3:
                return 365.0  # 1 year
            else:
                return 730.0  # 2 years
        
        return 365.0  # Default to 1 year
    
    def _assess_encryption_strength(self, device: Dict[str, Any]) -> float:
        """Assess encryption strength (0.0 = weak, 1.0 = strong)."""
        score = 0.5  # Default neutral score
        
        # Check if HTTPS is available
        if device.get('protocol') == 'HTTPS':
            score += 0.3
        
        # Check for specific encryption indicators
        fingerprint = device.get('fingerprint', {})
        
        # Look for TLS/SSL version information
        server_header = device.get('server_header', '').lower()
        if 'ssl' in server_header or 'tls' in server_header:
            score += 0.2
        
        return min(1.0, score)
    
    def _assess_interface_complexity(self, device: Dict[str, Any]) -> float:
        """Assess web interface complexity (more features = higher attack surface)."""
        fingerprint = device.get('fingerprint', {})
        
        # Count potential interface features
        complexity_indicators = [
            'login', 'admin', 'config', 'setup', 'network',
            'video', 'audio', 'recording', 'playback', 'alarm',
            'motion', 'ptz', 'preset', 'schedule'
        ]
        
        content = str(fingerprint).lower()
        complexity_score = sum(1 for indicator in complexity_indicators if indicator in content)
        
        # Normalize to 0-1 scale
        return min(1.0, complexity_score / len(complexity_indicators))
    
    def _assess_auth_methods(self, device: Dict[str, Any]) -> float:
        """Assess authentication methods strength."""
        if not device.get('authentication_required'):
            return 0.0  # No auth required = weakest
        
        if device.get('default_credentials'):
            return 0.1  # Default creds = very weak
        
        # Check for multi-factor authentication indicators
        fingerprint = device.get('fingerprint', {})
        mfa_indicators = ['2fa', 'two-factor', 'otp', 'token']
        
        content = str(fingerprint).lower()
        if any(indicator in content for indicator in mfa_indicators):
            return 0.9  # MFA = strong
        
        return 0.5  # Basic auth = medium
    
    def _calculate_popularity_score(self, device: Dict[str, Any]) -> float:
        """Calculate device popularity score based on manufacturer and model."""
        manufacturer = device.get('manufacturer', '').lower()
        
        # Popular manufacturers are more likely to be targeted
        popularity_scores = {
            'hikvision': 0.9,
            'dahua': 0.8,
            'axis': 0.7,
            'foscam': 0.6,
            'tp-link': 0.6,
            'sony': 0.5,
            'panasonic': 0.4
        }
        
        return popularity_scores.get(manufacturer, 0.3)
    
    def _calculate_exposure_score(self, device: Dict[str, Any]) -> float:
        """Calculate network exposure score."""
        score = 0.0
        
        # Internet-facing devices have higher exposure
        ip = device.get('ip', '')
        if self._is_public_ip(ip):
            score += 0.5
        
        # Multiple open ports increase exposure
        open_ports = device.get('open_ports', [])
        score += min(0.3, len(open_ports) * 0.05)
        
        # Web interface increases exposure
        if device.get('web_interface_url'):
            score += 0.2
        
        return min(1.0, score)
    
    def _is_public_ip(self, ip: str) -> bool:
        """Check if IP address is public/internet-routable."""
        import ipaddress
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_global
        except:
            return False
    
    def _detect_anomalies(self, device: Dict[str, Any], features: Dict[str, float]) -> List[Dict[str, Any]]:
        """Detect behavioral anomalies that might indicate vulnerabilities."""
        anomalies = []
        
        if not sklearn_available:
            self.logger.warning("scikit-learn not available, skipping anomaly detection")
            return anomalies
        
        try:
            # Convert features to array
            feature_array = np.array([list(features.values())]).reshape(1, -1)
            
            # Use isolation forest for anomaly detection
            if self.anomaly_detector is None:
                self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
                # For demo, we'll assume we have some training data
                # In practice, this would be trained on historical device data
                
            # Predict anomaly (would need proper training data in production)
            # For now, we'll use heuristic-based anomaly detection
            
            # High-risk combinations
            if (features.get('default_credentials', 0) > 0.5 and 
                features.get('network_exposure_score', 0) > 0.7):
                anomalies.append({
                    'id': f"anomaly_exposed_default_creds_{datetime.utcnow().timestamp()}",
                    'type': 'configuration_anomaly',
                    'severity': 'critical',
                    'title': 'Exposed Device with Default Credentials',
                    'description': 'Device is network-exposed with default credentials',
                    'confidence_score': 0.9,
                    'exploitable': True,
                    'remediation': 'Change default credentials and restrict network access'
                })
            
            # Old firmware with high exposure
            if (features.get('firmware_age_days', 0) > 730 and 
                features.get('network_exposure_score', 0) > 0.5):
                anomalies.append({
                    'id': f"anomaly_old_firmware_{datetime.utcnow().timestamp()}",
                    'type': 'firmware_anomaly',
                    'severity': 'high',
                    'title': 'Outdated Firmware on Exposed Device',
                    'description': 'Device with old firmware is network-exposed',
                    'confidence_score': 0.8,
                    'exploitable': True,
                    'remediation': 'Update firmware to latest version'
                })
            
        except Exception as e:
            self.logger.error(f"Anomaly detection failed: {str(e)}")
        
        return anomalies
    
    def _predict_risk_based_vulns(self, device: Dict[str, Any], 
                                 features: Dict[str, float]) -> List[Dict[str, Any]]:
        """Predict vulnerabilities based on risk factors."""
        predictions = []
        
        # High manufacturer risk + network exposure = likely RCE vulnerability
        if (features.get('manufacturer_risk_score', 0) > 0.7 and 
            features.get('network_exposure_score', 0) > 0.6):
            predictions.append({
                'id': f"risk_rce_{datetime.utcnow().timestamp()}",
                'type': 'remote_code_execution',
                'severity': 'critical',
                'title': 'Potential Remote Code Execution Vulnerability',
                'description': 'High-risk manufacturer device with network exposure',
                'confidence_score': 0.7,
                'exploitable': True,
                'remediation': 'Restrict network access and monitor for patches'
            })
        
        # Complex interface + weak auth = privilege escalation risk
        if (features.get('web_interface_complexity', 0) > 0.7 and 
            features.get('authentication_methods', 0) < 0.5):
            predictions.append({
                'id': f"risk_privesc_{datetime.utcnow().timestamp()}",
                'type': 'privilege_escalation',
                'severity': 'high',
                'title': 'Potential Privilege Escalation Vulnerability',
                'description': 'Complex interface with weak authentication',
                'confidence_score': 0.6,
                'exploitable': True,
                'remediation': 'Strengthen authentication mechanisms'
            })
        
        return predictions
    
    def _filter_and_rank_predictions(self, predictions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter and rank predictions by confidence and severity."""
        # Filter by minimum confidence threshold
        min_confidence = self.config.ai_prediction_threshold
        filtered = [p for p in predictions if p.get('confidence_score', 0) >= min_confidence]
        
        # Rank by severity and confidence
        severity_weights = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        
        def rank_key(pred):
            severity_weight = severity_weights.get(pred.get('severity', 'low'), 1)
            confidence = pred.get('confidence_score', 0)
            return -(severity_weight * confidence)  # Negative for descending sort
        
        ranked = sorted(filtered, key=rank_key)
        
        # Limit number of predictions per device
        max_predictions = self.config.get('ai.max_predictions_per_device', 10)
        return ranked[:max_predictions]
    
    def _load_models(self):
        """Load trained ML models from disk."""
        model_path = self.config.get('ai.model_path', 'models/')
        
        try:
            # Load vulnerability classifier
            classifier_path = os.path.join(model_path, 'vuln_classifier.pkl')
            if os.path.exists(classifier_path):
                with open(classifier_path, 'rb') as f:
                    self.vulnerability_classifier = pickle.load(f)
                self.logger.info("Loaded vulnerability classifier model")
            
            # Load anomaly detector
            anomaly_path = os.path.join(model_path, 'anomaly_detector.pkl')
            if os.path.exists(anomaly_path):
                with open(anomaly_path, 'rb') as f:
                    self.anomaly_detector = pickle.load(f)
                self.logger.info("Loaded anomaly detector model")
                
        except Exception as e:
            self.logger.warning(f"Failed to load models: {str(e)}")
    
    def train_models(self, training_data: List[Dict[str, Any]]):
        """Train ML models on historical vulnerability data."""
        if not sklearn_available:
            self.logger.error("scikit-learn not available for model training")
            return
        
        self.logger.info(f"Training models on {len(training_data)} samples")
        
        try:
            # Prepare training data
            X, y = self._prepare_training_data(training_data)
            
            if len(X) == 0:
                self.logger.warning("No training data available")
                return
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42
            )
            
            # Scale features
            X_train_scaled = self.feature_scaler.fit_transform(X_train)
            X_test_scaled = self.feature_scaler.transform(X_test)
            
            # Train vulnerability classifier
            self.vulnerability_classifier = RandomForestClassifier(
                n_estimators=100, random_state=42
            )
            self.vulnerability_classifier.fit(X_train_scaled, y_train)
            
            # Evaluate model
            y_pred = self.vulnerability_classifier.predict(X_test_scaled)
            accuracy = accuracy_score(y_test, y_pred)
            
            self.logger.info(f"Model training completed. Accuracy: {accuracy:.3f}")
            
            # Save models
            self._save_models()
            
        except Exception as e:
            self.logger.error(f"Model training failed: {str(e)}")
    
    def _prepare_training_data(self, training_data: List[Dict[str, Any]]) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare training data for ML models."""
        X = []
        y = []
        
        for sample in training_data:
            features = self._extract_device_features(sample.get('device', {}), [])
            feature_vector = [features.get(feat, 0.0) for feat in self.vulnerability_features]
            
            X.append(feature_vector)
            y.append(1 if sample.get('vulnerable', False) else 0)
        
        return np.array(X), np.array(y)
    
    def _save_models(self):
        """Save trained models to disk.""" 
        model_path = self.config.get('ai.model_path', 'models/')
        os.makedirs(model_path, exist_ok=True)
        
        try:
            if self.vulnerability_classifier:
                classifier_path = os.path.join(model_path, 'vuln_classifier.pkl')
                with open(classifier_path, 'wb') as f:
                    pickle.dump(self.vulnerability_classifier, f)
            
            if self.anomaly_detector:
                anomaly_path = os.path.join(model_path, 'anomaly_detector.pkl')
                with open(anomaly_path, 'wb') as f:
                    pickle.dump(self.anomaly_detector, f)
            
            # Save feature scaler
            scaler_path = os.path.join(model_path, 'feature_scaler.pkl')
            with open(scaler_path, 'wb') as f:
                pickle.dump(self.feature_scaler, f)
                
            self.logger.info("Models saved successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to save models: {str(e)}")