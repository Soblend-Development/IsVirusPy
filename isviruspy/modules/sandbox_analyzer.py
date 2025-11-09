import re
from typing import Dict, List, Any

class SandboxAnalyzer:
    def __init__(self):
        # APIs altamente sospechosas (combinaciones específicas)
        self.behavioral_indicators = {
            "code_injection": [
                "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                "NtMapViewOfSection", "QueueUserAPC", "SetThreadContext",
                "NtQueueApcThread", "RtlCreateUserThread"
            ],
            "persistence": [
                "RegSetValueEx.*Run", "RegCreateKey.*Run",
                "HKEY_CURRENT_USER\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run",
                "schtasks /create", "at.exe", "WMI.*Win32_ScheduledJob"
            ],
            "suspicious_network": [
                "URLDownloadToFile", "InternetOpenUrl.*http",
                "WinHttpOpen.*download", "recv.*4444", "connect.*cmd"
            ],
            "anti_analysis": [
                "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                "rdtsc", "cpuid.*hypervisor", "VirtualBox", "VMware", "QEMU",
                "wine_get", "SbieDll"
            ],
            "privilege_escalation": [
                "AdjustTokenPrivileges", "SeDebugPrivilege", "SeTakeOwnershipPrivilege",
                "ImpersonateLoggedOnUser"
            ],
            "keylogging": [
                "SetWindowsHookEx.*WH_KEYBOARD", "GetAsyncKeyState",
                "GetForegroundWindow.*GetWindowText"
            ],
            "ransomware_indicators": [
                "CryptEncrypt.*DeleteFile", "vssadmin delete shadows",
                "bcdedit.*recoveryenabled.*no", "cipher /w"
            ]
        }
        
        # APIs comunes que NO son sospechosas por sí solas
        self.common_apis = {
            "CreateFile", "ReadFile", "WriteFile", "CloseHandle",
            "CreateProcess", "GetModuleHandle", "LoadLibrary",
            "CreateToolhelp32Snapshot", "Process32First", "Process32Next",
            "GetProcAddress", "VirtualAlloc", "GetSystemInfo",
            "CreateMutex", "CreateEvent", "CreateThread",
            "RegOpenKey", "RegQueryValue", "GetTempPath",
            "socket", "send", "recv", "WSAStartup", "connect",
            "InternetOpen", "InternetConnect", "CryptAcquireContext"
        }
    
    def analyze(self, static_data: Dict[str, Any]) -> Dict[str, Any]:
        results = {
            "disclaimer": "ANÁLISIS ESTÁTICO - El archivo NO fue ejecutado",
            "behavioral_indicators": {},
            "risk_factors": [],
            "iocs": {
                "domains": [],
                "ips": [],
                "registry_keys": [],
                "file_paths": [],
                "mutexes": []
            }
        }
        
        all_strings = []
        if "strings" in static_data:
            all_strings.extend(static_data["strings"].get("all_strings", []))
            all_strings.extend(static_data["strings"].get("suspicious_commands", []))
        
        if "format_specific" in static_data and "imports" in static_data["format_specific"]:
            for imp in static_data["format_specific"]["imports"]:
                all_strings.extend(imp.get("functions", []))
        
        all_strings_lower = [s.lower() for s in all_strings]
        combined_text = " ".join(all_strings_lower)
        
        # Análisis contextual - requiere múltiples indicadores o combinaciones
        for category, indicators in self.behavioral_indicators.items():
            matches = []
            for indicator in indicators:
                # Búsqueda más específica con contexto
                if indicator.lower() in combined_text:
                    matches.append(indicator)
            
            # Solo reportar si hay indicadores suficientes o combinaciones peligrosas
            threshold = 2 if category in ["code_injection", "ransomware_indicators"] else 3
            
            if len(matches) >= threshold:
                results["behavioral_indicators"][category] = {
                    "detected": True,
                    "indicators": matches,
                    "count": len(matches)
                }
            elif category == "code_injection" and len(matches) == 1:
                # Inyección de código con 1 API es suficiente si es muy específica
                dangerous_apis = ["NtMapViewOfSection", "QueueUserAPC", "SetThreadContext", "RtlCreateUserThread"]
                if any(api in matches for api in dangerous_apis):
                    results["behavioral_indicators"][category] = {
                        "detected": True,
                        "indicators": matches,
                        "count": len(matches)
                    }
        
        results["risk_factors"] = self._assess_risk_factors(results["behavioral_indicators"])
        
        if "strings" in static_data:
            results["iocs"]["domains"] = self._extract_domains(static_data["strings"].get("urls", []))
            results["iocs"]["ips"] = static_data["strings"].get("ips", [])
        
        results["iocs"]["registry_keys"] = self._extract_registry_keys(all_strings)
        results["iocs"]["file_paths"] = self._extract_file_paths(all_strings)
        results["iocs"]["mutexes"] = self._extract_mutexes(all_strings)
        
        return results
    
    def _assess_risk_factors(self, indicators: Dict[str, Any]) -> List[str]:
        risk_factors = []
        
        if "code_injection" in indicators:
            risk_factors.append("Capacidad de inyección de código en otros procesos")
        
        if "persistence" in indicators:
            risk_factors.append("Mecanismos de persistencia (sobrevive reinicios)")
        
        if "network_activity" in indicators:
            risk_factors.append("Comunicación de red (posible C2)")
        
        if "anti_analysis" in indicators:
            risk_factors.append("Técnicas anti-análisis/anti-debugging")
        
        if "cryptography" in indicators and "file_operations" in indicators:
            risk_factors.append("Posible ransomware (cifrado + manipulación de archivos)")
        
        if "keylogging" in indicators:
            risk_factors.append("Capacidad de captura de teclas (keylogger)")
        
        if len(indicators) >= 4:
            risk_factors.append("Múltiples capacidades maliciosas detectadas")
        
        return risk_factors
    
    def _extract_domains(self, urls: List[str]) -> List[str]:
        domains = []
        domain_pattern = r'(?:https?://)?(?:www\.)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'
        
        for url in urls:
            matches = re.findall(domain_pattern, url)
            domains.extend(matches)
        
        return list(set(domains))
    
    def _extract_registry_keys(self, strings: List[str]) -> List[str]:
        registry_keys = []
        registry_patterns = [
            r'HKEY_[A-Z_]+\\[^"\'<>|]*',
            r'HKLM\\[^"\'<>|]*',
            r'HKCU\\[^"\'<>|]*',
            r'SOFTWARE\\[^"\'<>|]*'
        ]
        
        for string in strings:
            for pattern in registry_patterns:
                matches = re.findall(pattern, string, re.IGNORECASE)
                registry_keys.extend(matches)
        
        return list(set(registry_keys))[:20]
    
    def _extract_file_paths(self, strings: List[str]) -> List[str]:
        paths = []
        path_patterns = [
            r'[A-Za-z]:\\[^<>:"|?*\n]+',
            r'/(?:tmp|var|etc|home)/[^\s<>"|*\n]+',
            r'%[A-Za-z]+%\\[^\s<>"|*\n]+'
        ]
        
        for string in strings:
            for pattern in path_patterns:
                matches = re.findall(pattern, string)
                paths.extend(matches)
        
        return list(set(paths))[:20]
    
    def _extract_mutexes(self, strings: List[str]) -> List[str]:
        mutexes = []
        
        for string in strings:
            if any(prefix in string for prefix in ['Global\\', 'Local\\', 'Session\\']):
                if len(string) > 7 and len(string) < 100:
                    mutexes.append(string)
        
        return list(set(mutexes))[:10]
