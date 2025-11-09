import os
from typing import Dict, List, Any
import yara

class YaraEngine:
    def __init__(self, rules_dir: str = "isviruspy/rules"):
        self.rules_dir = rules_dir
        self.rules = None
        self._load_rules()
    
    def _load_rules(self):
        rule_files = {}
        
        if os.path.exists(self.rules_dir):
            for filename in os.listdir(self.rules_dir):
                if filename.endswith('.yar') or filename.endswith('.yara'):
                    rule_path = os.path.join(self.rules_dir, filename)
                    namespace = filename.replace('.yar', '').replace('.yara', '')
                    rule_files[namespace] = rule_path
        
        if rule_files:
            try:
                self.rules = yara.compile(filepaths=rule_files)
            except Exception as e:
                print(f"[YARA] Error compilando reglas: {e}")
                self.rules = None
    
    def scan(self, file_path: str) -> Dict[str, Any]:
        if not self.rules:
            return {
                "matches": [],
                "total_matches": 0,
                "status": "no_rules_loaded"
            }
        
        try:
            matches = self.rules.match(file_path, timeout=60)
            
            match_details = []
            for match in matches:
                match_info = {
                    "rule": match.rule,
                    "namespace": match.namespace,
                    "tags": match.tags,
                    "meta": match.meta,
                    "strings": []
                }
                
                for string_match in match.strings[:10]:
                    match_info["strings"].append({
                        "offset": string_match[0],
                        "identifier": string_match[1],
                        "data": string_match[2].decode('utf-8', errors='ignore')[:100]
                    })
                
                match_details.append(match_info)
            
            return {
                "matches": match_details,
                "total_matches": len(matches),
                "status": "scanned"
            }
            
        except Exception as e:
            return {
                "matches": [],
                "total_matches": 0,
                "status": "error",
                "error": str(e)
            }
