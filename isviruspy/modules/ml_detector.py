import numpy as np
from typing import Dict, List, Any, Optional
from sklearn.ensemble import RandomForestClassifier
import joblib
import os

class MLDetector:
    def __init__(self, model_path: Optional[str] = None):
        self.models = []
        self.model_names = []
        
        # Cargar modelo principal si existe
        if model_path and os.path.exists(model_path):
            try:
                self.models.append(joblib.load(model_path))
                self.model_names.append(os.path.basename(model_path))
            except Exception as e:
                print(f"[ML] No se pudo cargar modelo: {e}")
        
        # Siempre incluir múltiples clasificadores heurísticos
        self.model_names.extend([
            "heuristic_entropy_v1",
            "heuristic_behavioral_v1", 
            "heuristic_pe_analysis_v1",
            "heuristic_combined_v1"
        ])
    
    def analyze(self, static_data: Dict[str, Any], yara_data: Dict[str, Any], 
                sandbox_data: Dict[str, Any]) -> Dict[str, Any]:
        features = self._extract_features(static_data, yara_data, sandbox_data)
        
        # Consultar todos los modelos
        model_results = []
        
        # Modelo ML si existe
        if self.models:
            for i, model in enumerate(self.models):
                prob = self._predict_with_model(features, model)
                model_results.append({
                    "model": self.model_names[i],
                    "probability": round(prob, 4),
                    "type": "ml"
                })
        
        # Heurística basada en entropía
        entropy_prob = self._heuristic_entropy(features)
        model_results.append({
            "model": "heuristic_entropy_v1",
            "probability": round(entropy_prob, 4),
            "type": "heuristic"
        })
        
        # Heurística basada en comportamiento
        behavioral_prob = self._heuristic_behavioral(features)
        model_results.append({
            "model": "heuristic_behavioral_v1",
            "probability": round(behavioral_prob, 4),
            "type": "heuristic"
        })
        
        # Heurística basada en análisis PE
        pe_prob = self._heuristic_pe_analysis(features)
        model_results.append({
            "model": "heuristic_pe_analysis_v1",
            "probability": round(pe_prob, 4),
            "type": "heuristic"
        })
        
        # Heurística combinada (original)
        combined_prob = self._heuristic_classification(features)
        model_results.append({
            "model": "heuristic_combined_v1",
            "probability": round(combined_prob, 4),
            "type": "heuristic"
        })
        
        # Calcular consenso (promedio ponderado)
        probabilities = [r["probability"] for r in model_results]
        consensus_prob = sum(probabilities) / len(probabilities)
        
        # Calcular confianza basada en acuerdo entre modelos
        variance = np.var(probabilities)
        confidence = 1.0 - min(variance * 2, 0.5)  # Mayor acuerdo = mayor confianza
        
        return {
            "models_consulted": len(model_results),
            "model_results": model_results,
            "consensus_probability": round(consensus_prob, 4),
            "confidence": round(confidence, 2),
            "agreement_variance": round(variance, 4),
            "features_used": len(features),
            "top_features": self._get_top_features(features)
        }
    
    def _extract_features(self, static_data: Dict, yara_data: Dict, 
                         sandbox_data: Dict) -> Dict[str, float]:
        features = {}
        
        features["file_size"] = static_data.get("file_info", {}).get("size_bytes", 0)
        features["entropy"] = static_data.get("entropy", 0.0)
        
        format_data = static_data.get("format_specific", {})
        if format_data.get("type") == "PE":
            features["num_sections"] = format_data.get("num_sections", 0)
            features["num_imports"] = len(format_data.get("imports", []))
            features["has_overlay"] = 1.0 if format_data.get("has_overlay") else 0.0
            features["overlay_size"] = format_data.get("overlay_size", 0)
            
            sections = format_data.get("sections", [])
            if sections:
                features["max_section_entropy"] = max(s.get("entropy", 0) for s in sections)
                features["avg_section_entropy"] = np.mean([s.get("entropy", 0) for s in sections])
            
            features["suspicious_characteristics"] = len(format_data.get("suspicious_characteristics", []))
        
        features["yara_matches"] = yara_data.get("total_matches", 0)
        
        behavioral = sandbox_data.get("behavioral_indicators", {})
        features["behavioral_categories"] = len(behavioral)
        features["code_injection"] = 1.0 if "code_injection" in behavioral else 0.0
        features["persistence"] = 1.0 if "persistence" in behavioral else 0.0
        features["network_activity"] = 1.0 if "network_activity" in behavioral else 0.0
        features["anti_analysis"] = 1.0 if "anti_analysis" in behavioral else 0.0
        features["cryptography"] = 1.0 if "cryptography" in behavioral else 0.0
        
        iocs = sandbox_data.get("iocs", {})
        features["num_domains"] = len(iocs.get("domains", []))
        features["num_ips"] = len(iocs.get("ips", []))
        features["num_registry_keys"] = len(iocs.get("registry_keys", []))
        
        strings_data = static_data.get("strings", {})
        features["num_urls"] = len(strings_data.get("urls", []))
        features["num_suspicious_commands"] = len(strings_data.get("suspicious_commands", []))
        
        return features
    
    def _predict_with_model(self, features: Dict[str, float], model) -> float:
        try:
            feature_vector = np.array(list(features.values())).reshape(1, -1)
            prediction = model.predict_proba(feature_vector)[0]
            return prediction[1] if len(prediction) > 1 else prediction[0]
        except Exception as e:
            print(f"[ML] Error en predicción: {e}")
            return 0.5
    
    def _heuristic_entropy(self, features: Dict[str, float]) -> float:
        score = 0.0
        
        entropy = features.get("entropy", 0)
        if entropy > 7.9:
            score += 0.9
        elif entropy > 7.5:
            score += 0.7
        elif entropy > 7.0:
            score += 0.4
        elif entropy > 6.5:
            score += 0.2
        
        max_section_entropy = features.get("max_section_entropy", 0)
        if max_section_entropy > 7.9:
            score += 0.8
        elif max_section_entropy > 7.5:
            score += 0.5
        elif max_section_entropy > 7.0:
            score += 0.3
        
        # Overlay con alta entropía
        if features.get("has_overlay", 0) > 0:
            overlay_size = features.get("overlay_size", 0)
            if overlay_size > 100000:
                score += 0.4
            elif overlay_size > 50000:
                score += 0.2
        
        return min(score / 2.1, 1.0)
    
    def _heuristic_behavioral(self, features: Dict[str, float]) -> float:
        score = 0.0
        
        # Comportamientos críticos
        if features.get("code_injection", 0) > 0:
            score += 0.95
        
        if features.get("keylogging", 0) > 0:
            score += 1.0
        
        if features.get("cryptography", 0) > 0:
            score += 0.85
        
        if features.get("anti_analysis", 0) > 0:
            score += 0.80
        
        if features.get("persistence", 0) > 0:
            score += 0.75
        
        # Combinaciones peligrosas
        if features.get("persistence", 0) > 0 and features.get("network_activity", 0) > 0:
            score += 0.5  # Persistencia + red = backdoor potencial
        
        behavioral_categories = features.get("behavioral_categories", 0)
        if behavioral_categories >= 5:
            score += 0.6
        elif behavioral_categories >= 3:
            score += 0.3
        
        return min(score / 4.45, 1.0)
    
    def _heuristic_pe_analysis(self, features: Dict[str, float]) -> float:
        score = 0.0
        
        # Características sospechosas
        susp_chars = features.get("suspicious_characteristics", 0)
        if susp_chars > 10:
            score += 0.9
        elif susp_chars > 6:
            score += 0.6
        elif susp_chars > 3:
            score += 0.3
        
        # Número anormal de secciones
        num_sections = features.get("num_sections", 0)
        if num_sections > 25:
            score += 0.8
        elif num_sections > 15:
            score += 0.5
        elif num_sections > 10:
            score += 0.2
        
        # Imports sospechosos
        num_imports = features.get("num_imports", 0)
        if num_imports > 150:
            score += 0.3
        elif num_imports > 100:
            score += 0.15
        
        # Comandos sospechosos embebidos
        suspicious_cmds = features.get("num_suspicious_commands", 0)
        if suspicious_cmds > 20:
            score += 0.7
        elif suspicious_cmds > 10:
            score += 0.4
        elif suspicious_cmds > 5:
            score += 0.2
        
        # URLs y dominios
        num_urls = features.get("num_urls", 0)
        num_domains = features.get("num_domains", 0)
        if num_urls > 10 or num_domains > 5:
            score += 0.4
        elif num_urls > 5 or num_domains > 2:
            score += 0.2
        
        return min(score / 3.4, 1.0)
    
    def _heuristic_classification(self, features: Dict[str, float]) -> float:
        score = 0.0
        
        # Entropía extremadamente alta (empaquetado/cifrado)
        if features.get("entropy", 0) > 7.8:
            score += 0.35
        elif features.get("entropy", 0) > 7.2:
            score += 0.15
        
        # Secciones con entropía sospechosa
        if features.get("max_section_entropy", 0) > 7.9:
            score += 0.40
        elif features.get("max_section_entropy", 0) > 7.5:
            score += 0.20
        
        # Número excesivo de secciones (muy raro en binarios legítimos)
        if features.get("num_sections", 0) > 20:
            score += 0.35
        elif features.get("num_sections", 0) > 12:
            score += 0.15
        
        # YARA matches son muy confiables
        if features.get("yara_matches", 0) >= 2:
            score += 0.50
        elif features.get("yara_matches", 0) == 1:
            score += 0.25
        
        # Características sospechosas de PE (solo si son muchas)
        susp_chars = features.get("suspicious_characteristics", 0)
        if susp_chars > 8:
            score += 0.45
        elif susp_chars > 5:
            score += 0.25
        elif susp_chars > 3:
            score += 0.10
        
        # Comportamientos MUY sospechosos
        if features.get("code_injection", 0) > 0:
            score += 0.40  # Inyección de código es muy grave
        
        if features.get("persistence", 0) > 0 and features.get("anti_analysis", 0) > 0:
            score += 0.35  # Persistencia + anti-análisis = muy sospechoso
        elif features.get("anti_analysis", 0) > 0:
            score += 0.25
        
        # Múltiples categorías de comportamiento malicioso
        behavioral = features.get("behavioral_categories", 0)
        if behavioral >= 5:
            score += 0.40
        elif behavioral >= 3:
            score += 0.15
        
        # Overlay grande (común en malware empaquetado)
        if features.get("has_overlay", 0) > 0 and features.get("overlay_size", 0) > 100000:
            score += 0.25
        elif features.get("has_overlay", 0) > 0 and features.get("overlay_size", 0) > 50000:
            score += 0.10
        
        # Comandos sospechosos embebidos
        if features.get("num_suspicious_commands", 0) > 15:
            score += 0.30
        elif features.get("num_suspicious_commands", 0) > 8:
            score += 0.15
        
        # Reducir peso de imports (muchos legítimos tienen 50+)
        if features.get("num_imports", 0) > 100:
            score += 0.05
        
        return min(score, 1.0)
    
    def _get_top_features(self, features: Dict[str, float]) -> List[Dict[str, Any]]:
        importance_weights = {
            "yara_matches": 10.0,
            "code_injection": 9.0,
            "anti_analysis": 8.0,
            "max_section_entropy": 7.0,
            "suspicious_characteristics": 7.0,
            "persistence": 6.0,
            "cryptography": 6.0,
            "behavioral_categories": 5.0,
            "network_activity": 5.0,
            "entropy": 4.0
        }
        
        weighted_features = []
        for fname, fvalue in features.items():
            weight = importance_weights.get(fname, 1.0)
            if fvalue > 0:
                weighted_features.append({
                    "feature": fname,
                    "value": fvalue,
                    "importance": weight
                })
        
        weighted_features.sort(key=lambda x: x["importance"] * x["value"], reverse=True)
        return weighted_features[:10]
