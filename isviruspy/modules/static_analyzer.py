import hashlib
import re
import math
from typing import Dict, List, Any, Optional
import magic
import pefile
import lief

class StaticAnalyzer:
    def __init__(self):
        self.magic = magic.Magic(mime=True)
    
    def analyze(self, file_path: str) -> Dict[str, Any]:
        results = {
            "file_info": self._get_file_info(file_path),
            "hashes": self._calculate_hashes(file_path),
            "strings": self._extract_strings(file_path),
            "entropy": self._calculate_entropy(file_path),
            "format_specific": {}
        }
        
        file_type = results["file_info"]["mime_type"].lower()
        
        if any(x in file_type for x in ["dosexec", "executable", "portable-executable", "pe32", "mz"]):
            results["format_specific"] = self._analyze_pe(file_path)
        elif "elf" in file_type:
            results["format_specific"] = self._analyze_elf(file_path)
        else:
            pe_result = self._analyze_pe(file_path)
            if pe_result.get("type") == "PE" and "error" not in pe_result:
                results["format_specific"] = pe_result
        
        return results
    
    def _get_file_info(self, file_path: str) -> Dict[str, Any]:
        import os
        stat_info = os.stat(file_path)
        
        return {
            "size_bytes": stat_info.st_size,
            "mime_type": self.magic.from_file(file_path),
            "file_path": file_path,
            "file_name": os.path.basename(file_path)
        }
    
    def _calculate_hashes(self, file_path: str) -> Dict[str, str]:
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            data = f.read()
            md5.update(data)
            sha1.update(data)
            sha256.update(data)
        
        return {
            "md5": md5.hexdigest(),
            "sha1": sha1.hexdigest(),
            "sha256": sha256.hexdigest()
        }
    
    def _extract_strings(self, file_path: str, min_length: int = 4) -> Dict[str, List[str]]:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        ascii_strings = re.findall(rb'[\x20-\x7E]{%d,}' % min_length, data)
        ascii_strings = [s.decode('ascii', errors='ignore') for s in ascii_strings[:500]]
        
        urls = [s for s in ascii_strings if any(proto in s for proto in ['http://', 'https://', 'ftp://'])]
        
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ips = list(set(re.findall(ip_pattern, ' '.join(ascii_strings))))
        
        suspicious_commands = []
        cmd_keywords = ['powershell', 'cmd.exe', 'bash', 'sh', 'wget', 'curl', 'download', 'exec']
        for s in ascii_strings:
            if any(kw in s.lower() for kw in cmd_keywords):
                suspicious_commands.append(s)
        
        return {
            "all_strings": ascii_strings[:100],
            "urls": urls,
            "ips": ips,
            "suspicious_commands": suspicious_commands[:20]
        }
    
    def _calculate_entropy(self, file_path: str) -> float:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        if not data:
            return 0.0
        
        entropy = 0.0
        for x in range(256):
            p_x = float(data.count(bytes([x]))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        
        return round(entropy, 2)
    
    def _analyze_pe(self, file_path: str) -> Dict[str, Any]:
        try:
            pe = pefile.PE(file_path)
            
            sections = []
            for section in pe.sections:
                sections.append({
                    "name": section.Name.decode().strip('\x00'),
                    "virtual_address": hex(section.VirtualAddress),
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData,
                    "entropy": round(section.get_entropy(), 2),
                    "md5": section.get_hash_md5()
                })
            
            imports = []
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_imports = []
                    for imp in entry.imports[:50]:
                        if imp.name:
                            dll_imports.append(imp.name.decode('utf-8', errors='ignore'))
                    imports.append({
                        "dll": entry.dll.decode('utf-8', errors='ignore'),
                        "functions": dll_imports
                    })
            
            overlay_offset = pe.get_overlay_data_start_offset()
            overlay_size = 0
            if overlay_offset:
                with open(file_path, 'rb') as f:
                    f.seek(0, 2)
                    file_size = f.tell()
                    overlay_size = file_size - overlay_offset
            
            pe_info = {
                "type": "PE",
                "machine": hex(pe.FILE_HEADER.Machine),
                "num_sections": pe.FILE_HEADER.NumberOfSections,
                "timestamp": pe.FILE_HEADER.TimeDateStamp,
                "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
                "sections": sections,
                "imports": imports[:10],
                "has_overlay": overlay_offset is not None,
                "overlay_size": overlay_size,
                "suspicious_characteristics": self._detect_suspicious_pe(pe, sections, imports)
            }
            
            pe.close()
            return pe_info
            
        except Exception as e:
            return {"type": "PE", "error": str(e)}
    
    def _analyze_elf(self, file_path: str) -> Dict[str, Any]:
        try:
            binary = lief.parse(file_path)
            
            sections = []
            for section in binary.sections:
                sections.append({
                    "name": section.name,
                    "type": str(section.type),
                    "virtual_address": hex(section.virtual_address),
                    "size": section.size,
                    "entropy": round(section.entropy, 2)
                })
            
            imports = []
            for lib in binary.libraries[:10]:
                imports.append(lib)
            
            return {
                "type": "ELF",
                "architecture": str(binary.header.machine_type),
                "entry_point": hex(binary.entrypoint),
                "sections": sections,
                "libraries": imports
            }
            
        except Exception as e:
            return {"type": "ELF", "error": str(e)}
    
    def _detect_suspicious_pe(self, pe, sections: List[Dict], imports: List[Dict]) -> List[str]:
        suspicious = []
        
        # Solo marcar si es EXCESIVO (20+, no 10)
        num_sections = len(sections)
        if num_sections > 20:
            suspicious.append(f"Número excesivo de secciones ({num_sections}) - muy inusual")
        
        # Solo reportar entropía MUY alta (7.5+)
        very_high_entropy = []
        for section in sections:
            if section["entropy"] > 7.8:
                very_high_entropy.append(section)
                suspicious.append(f"Sección '{section['name']}' cifrada/empaquetada (entropía {section['entropy']})")
            
            # Detectar firmas de empaquetadores
            packer_sigs = {'.upx': 'UPX', '.aspack': 'ASPack', '.themida': 'Themida', 
                          '.enigma': 'Enigma', '.mpress': 'MPRESS', '.petite': 'Petite',
                          '.nsp': 'NsPack', '.rlpack': 'RLPack'}
            for sig, name in packer_sigs.items():
                if sig in section['name'].lower():
                    suspicious.append(f"Empaquetador detectado: {name}")
        
        if len(very_high_entropy) >= 3:
            suspicious.append(f"Múltiples secciones cifradas ({len(very_high_entropy)}) - altamente sospechoso")
        
        # APIs REALMENTE peligrosas (no todas las APIs de Windows)
        dangerous_api_combos = {
            "code_injection": ['WriteProcessMemory', 'CreateRemoteThread', 'NtMapViewOfSection', 
                              'QueueUserAPC', 'SetThreadContext', 'RtlCreateUserThread'],
            "download_exec": ['URLDownloadToFile', 'InternetOpenUrl'],
            "anti_debug": ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess'],
            "privilege": ['AdjustTokenPrivileges', 'ImpersonateLoggedOnUser'],
            "keylogging": ['SetWindowsHookEx', 'GetAsyncKeyState']
        }
        
        detected_categories = {}
        for category, apis in dangerous_api_combos.items():
            matches = []
            for imp in imports:
                for func in imp.get("functions", []):
                    for api in apis:
                        if api.lower() == func.lower():
                            matches.append(f"{imp['dll']}!{func}")
            if matches:
                detected_categories[category] = matches
                if category in ["code_injection", "privilege"]:
                    suspicious.append(f"APIs de {category}: {', '.join(matches[:3])}")
        
        # Solo marcar si hay MÚLTIPLES categorías peligrosas
        if len(detected_categories) >= 3:
            suspicious.append(f"Múltiples categorías de APIs maliciosas ({len(detected_categories)})")
        
        return suspicious
