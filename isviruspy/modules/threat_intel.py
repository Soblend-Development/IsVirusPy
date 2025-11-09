
import hashlib
from typing import Dict, Any, List

class ThreatIntelligence:
    def __init__(self):
        # Simular base de datos de hashes maliciosos conocidos
        self.known_malware_hashes = {
            # Estos son hashes de ejemplo - en producción conectar a APIs reales
            "5d41402abc4b2a76b9719d911017c592": {"name": "Generic.Trojan", "severity": "high"},
            "098f6bcd4621d373cade4e832627b4f6": {"name": "Win32.Worm", "severity": "critical"},
        }
        
        # Simular reputación de archivos
        self.reputation_db = {}
        
    def check_hash_reputation(self, file_hashes: Dict[str, str]) -> Dict[str, Any]:
        results = {
            "sources_checked": 5,
            "detections": [],
            "hash_found": False,
            "reputation_score": 0
        }
        
        # Simular consulta a múltiples fuentes
        sources = [
            "MalwareBazaar_DB",
            "VirusShare_DB", 
            "Hybrid_Analysis_DB",
            "ThreatCrowd_DB",
            "AlienVault_OTX"
        ]
        
        for hash_type, hash_value in file_hashes.items():
            if hash_value in self.known_malware_hashes:
                malware_info = self.known_malware_hashes[hash_value]
                results["hash_found"] = True
                results["detections"].append({
                    "source": "Local_Database",
                    "hash_type": hash_type,
                    "hash_value": hash_value,
                    "malware_name": malware_info["name"],
                    "severity": malware_info["severity"]
                })
                results["reputation_score"] = 100  # Malware conocido
        
        if not results["hash_found"]:
            # Simular resultados de fuentes externas (sin detección)
            results["reputation_score"] = 0  # Archivo no conocido
        
        return results
    
    def analyze_file_reputation(self, static_data: Dict) -> Dict[str, Any]:
        reputation = {
            "file_age_days": 0,
            "prevalence": "unknown",
            "trust_score": 50,  # 0-100
            "observations": []
        }
        
        # Analizar características del archivo
        file_info = static_data.get("file_info", {})
        file_size = file_info.get("size_bytes", 0)
        
        # Archivos muy pequeños o muy grandes son sospechosos
        if file_size < 10000:
            reputation["observations"].append("Archivo inusualmente pequeño")
            reputation["trust_score"] -= 10
        elif file_size > 50000000:  # >50MB
            reputation["observations"].append("Archivo inusualmente grande")
            reputation["trust_score"] -= 5
        
        # Entropía alta reduce confianza
        entropy = static_data.get("entropy", 0)
        if entropy > 7.5:
            reputation["observations"].append("Alta entropía - posiblemente empaquetado/cifrado")
            reputation["trust_score"] -= 20
        elif entropy > 7.0:
            reputation["trust_score"] -= 10
        
        # Analizar formato
        format_data = static_data.get("format_specific", {})
        if format_data.get("type") == "PE":
            # Sin firma digital es sospechoso
            if not format_data.get("is_signed", False):
                reputation["observations"].append("Sin firma digital")
                reputation["trust_score"] -= 15
            
            # Overlay sospechoso
            if format_data.get("has_overlay"):
                reputation["observations"].append("Contiene overlay (datos adicionales)")
                reputation["trust_score"] -= 10
        
        reputation["trust_score"] = max(0, min(100, reputation["trust_score"]))
        
        return reputation
    
    def get_threat_context(self, sandbox_data: Dict) -> Dict[str, Any]:
        context = {
            "threat_categories": [],
            "attack_vectors": [],
            "target_platforms": [],
            "mitre_tactics": []
        }
        
        behavioral = sandbox_data.get("behavioral_indicators", {})
        
        # Categorizar amenazas
        if "code_injection" in behavioral:
            context["threat_categories"].append("Trojan")
            context["attack_vectors"].append("Process Injection")
            context["mitre_tactics"].append("T1055 - Process Injection")
        
        if "keylogging" in behavioral:
            context["threat_categories"].append("Spyware/Keylogger")
            context["attack_vectors"].append("Credential Theft")
            context["mitre_tactics"].append("T1056 - Input Capture")
        
        if "cryptography" in behavioral:
            context["threat_categories"].append("Ransomware")
            context["attack_vectors"].append("Data Encryption")
            context["mitre_tactics"].append("T1486 - Data Encrypted for Impact")
        
        if "network" in behavioral:
            context["threat_categories"].append("Remote Access Tool / Backdoor")
            context["attack_vectors"].append("Command & Control")
            context["mitre_tactics"].append("T1071 - Application Layer Protocol")
        
        if "persistence" in behavioral:
            context["attack_vectors"].append("Persistence Mechanism")
            context["mitre_tactics"].append("T1547 - Boot or Logon Autostart")
        
        if "anti_analysis" in behavioral:
            context["attack_vectors"].append("Defense Evasion")
            context["mitre_tactics"].append("T1027 - Obfuscated Files or Information")
        
        # Plataformas objetivo
        format_type = sandbox_data.get("format_type", "Unknown")
        if format_type == "PE":
            context["target_platforms"].append("Windows")
        elif format_type == "ELF":
            context["target_platforms"].append("Linux")
        
        return context
    
    def generate_threat_intel_report(self, file_hashes: Dict, static_data: Dict, 
                                     sandbox_data: Dict) -> Dict[str, Any]:
        hash_reputation = self.check_hash_reputation(file_hashes)
        file_reputation = self.analyze_file_reputation(static_data)
        threat_context = self.get_threat_context(sandbox_data)
        
        # Calcular score global de amenaza
        threat_score = 0
        
        if hash_reputation["hash_found"]:
            threat_score = 100
        else:
            # Basar en reputación y contexto
            threat_score = 100 - file_reputation["trust_score"]
            
            if threat_context["threat_categories"]:
                threat_score = max(threat_score, 60 + len(threat_context["threat_categories"]) * 10)
        
        threat_score = min(100, threat_score)
        
        return {
            "threat_intelligence_score": threat_score,
            "hash_reputation": hash_reputation,
            "file_reputation": file_reputation,
            "threat_context": threat_context,
            "sources_consulted": hash_reputation["sources_checked"],
            "recommendation": self._get_recommendation(threat_score, hash_reputation)
        }
    
    def _get_recommendation(self, threat_score: int, hash_reputation: Dict) -> str:
        if hash_reputation["hash_found"]:
            return "⚠️ CRÍTICO: Hash coincide con malware conocido - eliminar inmediatamente"
        elif threat_score >= 80:
            return "Alto riesgo - Someter a análisis dinámico en sandbox aislado"
        elif threat_score >= 60:
            return "Riesgo medio - Investigar más antes de ejecutar"
        elif threat_score >= 40:
            return "Riesgo bajo - Mantener monitoreo"
        else:
            return "Archivo parece legítimo - verificar firma digital si está disponible"
