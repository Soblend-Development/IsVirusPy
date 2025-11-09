
<div align="center">
  <img src="https://rogddqelmxyuvhpjvxbf.supabase.co/storage/v1/object/public/files/vmv3maki25s.png" alt="IsVirusPY Logo" width="400"/>
  
  <h1>IsVirusPY - Sistema de Análisis y Detección de Malware</h1>
  
  <p><strong>Herramienta forense de seguridad para análisis estático y detección de amenazas</strong></p>
  
  [![Made with Replit](https://replit.com/badge?theme=dark)](https://replit.com)
  ![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
  ![License](https://img.shields.io/badge/license-Educational-green.svg)
</div>

---

## 📋 Tabla de Contenidos

- [Descripción General](#-descripción-general)
- [Advertencias Legales](#️-advertencias-legales-y-de-seguridad)
- [Características Principales](#-características-principales)
- [Instalación](#-instalación)
- [Guía de Uso](#-guía-de-uso)
- [Arquitectura del Sistema](#-arquitectura-del-sistema)
- [Técnicas de Detección](#-técnicas-de-detección)
- [Formato de Reportes](#-formato-de-reportes)
- [Configuración Avanzada](#️-configuración-avanzada)
- [Ejemplos Prácticos](#-ejemplos-prácticos)
- [API y Módulos](#-api-y-módulos)
- [Contribuir](#-contribuir)
- [FAQ](#-preguntas-frecuentes)
- [Recursos](#-recursos)

---

## 🎯 Descripción General

**IsVirusPY** es una plataforma avanzada de análisis forense y detección de malware desarrollada en Python. Combina múltiples técnicas de análisis estático, detección basada en reglas YARA, análisis de comportamiento simulado y machine learning para identificar y clasificar archivos potencialmente maliciosos.

### ¿Para quién es esta herramienta?

- 🎓 **Estudiantes de ciberseguridad**: Aprende técnicas de análisis de malware
- 🔬 **Investigadores de seguridad**: Analiza muestras en entornos controlados
- 👨‍💻 **Analistas SOC**: Complementa tu arsenal de herramientas forenses
- 🏫 **Educadores**: Enseña conceptos de malware y análisis estático

### Capacidades Principales

✅ Análisis estático profundo de archivos PE, ELF y otros formatos  
✅ Motor de detección YARA con 10+ reglas personalizables  
✅ Análisis de comportamiento basado en indicadores (IOCs)  
✅ Machine learning con consenso de múltiples modelos  
✅ Reportes detallados en JSON y visualización en terminal  
✅ Integración con inteligencia de amenazas (hashes, familias)  
✅ Puntuación de riesgo (0-100) y recomendaciones de acción  

---

## ⚠️ ADVERTENCIAS LEGALES Y DE SEGURIDAD

### 🚨 USO EXCLUSIVAMENTE EDUCATIVO Y DE INVESTIGACIÓN

**IMPORTANTE - LEE ESTO ANTES DE USAR LA HERRAMIENTA:**

- ✋ Esta herramienta es **SOLO para fines educativos** y de investigación en seguridad
- ⛔ **NO ejecuta archivos maliciosos** en el sistema host
- 🔒 El análisis dinámico es **COMPLETAMENTE SIMULADO** - no hay ejecución real de malware
- ⚠️ Puede generar **falsos positivos** (archivos legítimos marcados como maliciosos)
- ⚠️ Puede generar **falsos negativos** (malware no detectado)
- 🏢 **NO reemplaza** soluciones profesionales de AV/EDR o equipos SOC
- 📜 Consulta las **leyes locales** sobre posesión y análisis de muestras de malware
- ✅ Obtén **consentimiento** antes de analizar archivos de terceros
- 🔐 No cargues muestras a servicios públicos sin autorización del propietario

### Responsabilidades del Usuario

Al usar IsVirusPY, aceptas:
- Usar la herramienta solo con fines legales y éticos
- Mantener las muestras en entornos aislados y seguros
- No distribuir malware o usar la herramienta para crear amenazas
- Seguir las regulaciones de tu jurisdicción sobre análisis forense

---

## 🚀 Características Principales

### 1️⃣ Análisis Estático Avanzado

El módulo de análisis estático extrae información detallada sin ejecutar el archivo:

#### Formatos Soportados
- **PE (Portable Executable)**: Archivos .exe, .dll, .sys de Windows
- **ELF (Executable and Linkable Format)**: Binarios de Linux/Unix
- **Mach-O**: Ejecutables de macOS
- **APK**: Aplicaciones Android
- **Documentos**: PDF, DOC, DOCX, XLS, XLSX

#### Información Extraída
- 🔢 **Hashes criptográficos**: MD5, SHA1, SHA256, SHA512
- 📊 **Entropía**: Detección de empaquetamiento/cifrado (0-8 bits)
- 📝 **Strings**: URLs, IPs, correos, comandos, rutas de archivo
- 🏗️ **Estructura del archivo**: Cabeceras, secciones, overlays
- 🔗 **Imports/Exports**: APIs importadas/exportadas (PE/ELF)
- 🎯 **Características sospechosas**: APIs peligrosas, secciones ejecutables/escribibles
- 📦 **Recursos**: Iconos, manifiestos, recursos embebidos (PE)
- 🔍 **Metadatos**: Versión, compilador, timestamp de compilación

#### Ejemplo de Salida
```json
{
  "file_type": "PE32 executable (GUI) Intel 80386",
  "hashes": {
    "md5": "5d41402abc4b2a76b9719d911017c592",
    "sha256": "2c26b46b68ffc68ff99b453c1d30413413422d706..."
  },
  "entropy": 7.89,
  "strings": {
    "urls": ["http://malicious.example.com/payload.exe"],
    "ips": ["192.0.2.1"],
    "suspicious_commands": ["cmd.exe /c del"]
  }
}
```

### 2️⃣ Motor de Reglas YARA

Sistema de detección basado en patrones usando el estándar YARA:

#### Reglas Incluidas (10+)
1. **Empaquetadores**: UPX, ASPack, PECompact, Themida, VMProtect
2. **Inyección de código**: VirtualAllocEx, WriteProcessMemory, CreateRemoteThread
3. **Ransomware**: Cifrado, extensiones, notas de rescate
4. **Keyloggers**: Hooks de teclado, GetAsyncKeyState
5. **Persistencia**: Claves de registro Run, tareas programadas
6. **Anti-debugging**: IsDebuggerPresent, RDTSC, detección de VM
7. **Downloaders**: URLDownloadToFile, WinHTTP, sockets
8. **PowerShell embebido**: Scripts ofuscados, comandos codificados
9. **Rootkits**: Hooks SSDT, manipulación de drivers
10. **Backdoors**: Conexiones reversas, bind shells

#### Sintaxis de Reglas YARA
```yara
rule Ransomware_Generic {
    meta:
        description = "Detecta características de ransomware"
        severity = "critical"
    
    strings:
        $encrypt_api = "CryptEncrypt" ascii
        $ransom_note = "YOUR FILES HAVE BEEN ENCRYPTED" nocase
        $bitcoin = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ ascii
    
    condition:
        uint16(0) == 0x5A4D and
        ($encrypt_api or $ransom_note) and $bitcoin
}
```

### 3️⃣ Análisis de Comportamiento Simulado

Detecta indicadores de comportamiento malicioso basándose en análisis estático:

#### Categorías de Comportamiento
- 💉 **Code Injection**: Inyección en procesos remotos
- 🔄 **Persistence**: Supervivencia a reinicios del sistema
- 🌐 **Network Activity**: Comunicación C2, descarga de payloads
- 🛡️ **Anti-Analysis**: Evasión de debuggers, sandboxes, VMs
- ⬆️ **Privilege Escalation**: Escalada de privilegios
- ⌨️ **Keylogging**: Captura de pulsaciones de teclado
- 🔐 **Cryptography**: Cifrado de archivos/comunicaciones
- 📁 **File Operations**: Creación, modificación, eliminación masiva
- 📝 **Registry Manipulation**: Modificación del Registro de Windows

#### IOCs (Indicators of Compromise) Extraídos
- 🌍 Dominios y URLs
- 🔢 Direcciones IP
- 🔑 Claves de registro
- 📂 Rutas de archivos
- 🔒 Mutexes
- 🔧 Comandos del sistema

### 4️⃣ Detección con Machine Learning

Sistema de ML con múltiples modelos y consenso:

#### Modelos Integrados
1. **Heurístico basado en reglas**: Scoring de características conocidas
2. **XGBoost**: Gradient boosting para clasificación binaria
3. **Random Forest**: Ensemble de árboles de decisión
4. **Redes Neuronales**: Deep learning (opcional)

#### Características Extraídas (87+)
- Número de imports/exports
- Entropía de secciones
- Tamaño y permisos de secciones
- Número de strings sospechosos
- Coincidencias YARA
- Indicadores de comportamiento
- Características de empaquetamiento
- Propiedades del grafo de llamadas

#### Consenso de Modelos
```python
consensus_probability = (
    heuristic_score * 0.30 +
    xgboost_score * 0.40 +
    random_forest_score * 0.30
)
```

### 5️⃣ Sistema de Reportes Avanzado

Generación de reportes en múltiples formatos con visualización rica:

#### Formatos de Salida
- 📊 **Terminal**: Visualización colorida con Rich (barras de progreso, tablas)
- 📄 **JSON**: Estructurado para integración con SIEM/SOAR
- 📝 **HTML**: Reporte web interactivo (próximamente)
- 📋 **PDF**: Documentación profesional (próximamente)

#### Componentes del Reporte
- **Risk Score**: 0-100 basado en múltiples factores
- **Veredicto**: clean / suspicious / malicious / unknown
- **Confianza**: 0-100% de certeza en la clasificación
- **Razones de detección**: Lista detallada de hallazgos
- **Capacidades detectadas**: Qué puede hacer el malware
- **IOCs extraídos**: Indicadores de compromiso
- **Recomendaciones**: Acciones específicas a tomar
- **Timeline**: Secuencia de eventos detectados

---

## 📦 Instalación

### Requisitos Previos
- Python 3.11 o superior
- Sistema operativo: Linux, macOS, Windows (WSL recomendado)
- Memoria RAM: Mínimo 2GB, recomendado 4GB+
- Espacio en disco: 500MB para instalación + espacio para muestras

### Instalación Local

```bash
# Clonar repositorio
git clone https://github.com/Soblend-Development/isviruspy.git
cd isviruspy
pip install -e .
```

### Dependencias Principales

```txt
pefile>=2023.2.7          # Parsing de archivos PE
lief>=0.14.0               # Multi-formato (PE, ELF, Mach-O)
yara-python>=4.5.0         # Motor YARA
scikit-learn>=1.4.0        # Machine Learning
xgboost>=2.0.0             # Gradient Boosting
pandas>=2.2.0              # Manipulación de datos
numpy>=1.26.0              # Operaciones numéricas
rich>=13.7.0               # Visualización en terminal
python-magic>=0.4.27       # Detección de tipo de archivo
requests>=2.31.0           # HTTP requests
```

---

## 🎮 Guía de Uso

### Comandos Básicos

#### 1. Escanear un archivo individual

```bash
isviruspy scan archivo.exe
```

Salida en terminal con visualización colorida:
```
╔═══════════════════════════════════════════════╗
║              ISVIRUSPY v1.0                  ║
║     Sistema de Análisis de Malware           ║
╚═══════════════════════════════════════════════╝

📂 Archivo: archivo.exe
📊 SHA256: 2c26b46b68ffc68ff99b453c1d30413413422d706...
⚠️  VEREDICTO: MALICIOUS
🎯 Risk Score: 87/100
💯 Confianza: 92%

🔍 CAPACIDADES DETECTADAS:
┌──────────────────────────────┬─────────┐
│ Capacidad                    │ Peligro │
├──────────────────────────────┼─────────┤
│ Inyección de Código          │ ████████│ 95%
│ Persistencia en Sistema      │ ████████│ 80%
│ Comunicación de Red          │ ██████  │ 65%
└──────────────────────────────┴─────────┘
```

#### 2. Guardar reporte en JSON

```bash
isviruspy scan malware.dll --json reporte.json
```

#### 3. Escanear directorio completo

```bash
isviruspy scan-dir ./muestras --output-dir ./reportes
```

#### 4. Escanear recursivamente

```bash
isviruspy scan-dir /ruta/muestras --recursive --output-dir /ruta/reportes
```

#### 5. Verificar hash conocido

```bash
isviruspy check-hash 5d41402abc4b2a76b9719d911017c592
```

### Opciones Avanzadas

#### Ajustar umbral de detección

```bash
isviruspy scan archivo.exe --threshold 70
```

#### Habilitar análisis profundo

```bash
isviruspy scan archivo.exe --deep-analysis
```

#### Excluir ciertos análisis

```bash
isviruspy scan archivo.exe --skip-ml --skip-yara
```

#### Modo silencioso (solo JSON)

```bash
isviruspy scan archivo.exe --quiet --json output.json
```

---

## 🏗️ Arquitectura del Sistema

### Estructura de Directorios

```
isviruspy/
│
├── __init__.py                 # Inicialización del paquete
├── cli.py                      # Interfaz de línea de comandos
│
├── modules/                    # Módulos principales
│   ├── __init__.py
│   ├── static_analyzer.py      # Análisis estático (PE/ELF/Mach-O)
│   ├── yara_engine.py          # Motor de reglas YARA
│   ├── sandbox_analyzer.py     # Análisis de comportamiento
│   ├── ml_detector.py          # Detección con ML
│   ├── threat_intel.py         # Inteligencia de amenazas
│   └── report_generator.py     # Generación de reportes
│
├── rules/                      # Reglas de detección
│   ├── malware_detection.yar   # Reglas YARA principales
│   ├── ransomware.yar          # Reglas específicas ransomware
│   └── apt.yar                 # Reglas APT/targeted attacks
│
├── models/                     # Modelos de ML entrenados
│   ├── xgboost_model.pkl
│   ├── random_forest.pkl
│   └── features_scaler.pkl
│
├── data/                       # Datasets y datos de entrenamiento
│   ├── malware_samples/
│   ├── benign_samples/
│   └── training_features.csv
│
├── reports/                    # Reportes generados
│   └── [SHA256]_report.json
│
└── tests/                      # Tests unitarios
    ├── test_static_analyzer.py
    ├── test_yara_engine.py
    └── test_ml_detector.py
```

### Flujo de Análisis

```
┌─────────────┐
│   Archivo   │
└──────┬──────┘
       │
       ▼
┌─────────────────────┐
│ Static Analyzer     │◄── Extrae hashes, strings, estructura
└──────┬──────────────┘
       │
       ▼
┌─────────────────────┐
│ YARA Engine         │◄── Coincidencias con reglas
└──────┬──────────────┘
       │
       ▼
┌─────────────────────┐
│ Sandbox Analyzer    │◄── Detecta comportamiento (simulado)
└──────┬──────────────┘
       │
       ▼
┌─────────────────────┐
│ ML Detector         │◄── Clasificación con múltiples modelos
└──────┬──────────────┘
       │
       ▼
┌─────────────────────┐
│ Threat Intelligence │◄── Enriquecimiento con IOCs conocidos
└──────┬──────────────┘
       │
       ▼
┌─────────────────────┐
│ Report Generator    │◄── Reporte final JSON + visualización
└─────────────────────┘
```

---

## 🔬 Técnicas de Detección

### Análisis Estático

#### Parsing de Formatos Binarios
```python
import pefile
import lief

pe = pefile.PE('malware.exe')
sections = pe.sections
imports = pe.DIRECTORY_ENTRY_IMPORT
```

#### Cálculo de Entropía
```python
import math

def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(bytes([x]))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy
```

Interpretación:
- **0-3**: Texto plano sin comprimir
- **3-5**: Datos comprimidos normalmente
- **5-7**: Ejecutables típicos
- **7-8**: Cifrado/empaquetamiento fuerte (sospechoso)

### Detección YARA

#### Ejemplo de Regla Compleja

```yara
rule APT_Backdoor_Generic {
    meta:
        description = "Detecta backdoor genérico de APT"
        author = "IsVirusPY Team"
        date = "2025-01-09"
        severity = "high"
        mitre_attack = "T1071.001"  # Application Layer Protocol: Web
    
    strings:
        $mz = { 4D 5A }  // MZ header
        
        $api_socket = "WSAStartup" ascii
        $api_connect = "connect" ascii
        $api_send = "send" ascii
        $api_recv = "recv" ascii
        
        $cmd_shell = "cmd.exe" nocase
        $powershell = "powershell" nocase
        
        $persistence_reg = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii
        
        $c2_pattern = /(https?:\/\/)?[a-z0-9-]+\.(tk|ml|ga|cf|gq)/ nocase
    
    condition:
        $mz at 0 and
        3 of ($api_*) and
        any of ($cmd_shell, $powershell) and
        ($persistence_reg or $c2_pattern)
}
```

### Heurísticas de Machine Learning

#### Feature Engineering

```python
features = {
    # Características estructurales
    'num_sections': len(pe.sections),
    'num_imports': len(imports),
    'num_exports': len(exports),
    'entry_point_section': entry_point_section_index,
    
    # Características de entropía
    'max_section_entropy': max(s.get_entropy() for s in sections),
    'avg_section_entropy': sum(s.get_entropy() for s in sections) / len(sections),
    
    # Características de comportamiento
    'has_code_injection_apis': bool(dangerous_apis & imported_apis),
    'has_persistence_mechanisms': bool(registry_keys),
    'has_network_activity': bool(network_apis),
    
    # Características de empaquetamiento
    'is_packed': entropy > 7.0,
    'has_overlay': overlay_size > 0,
    
    # Características de strings
    'num_suspicious_strings': len(suspicious_strings),
    'num_urls': len(urls),
    'num_ips': len(ips)
}
```

---

## 📊 Formato de Reportes

### Estructura Completa del JSON

```json
{
  "scan_metadata": {
    "file_name": "malware.exe",
    "file_path": "/path/to/malware.exe",
    "scan_date": "2025-01-09T15:30:45Z",
    "scanner_version": "1.0.0",
    "scan_duration_seconds": 2.34
  },
  
  "file_info": {
    "size_bytes": 245760,
    "file_type": "PE32 executable (GUI) Intel 80386",
    "mime_type": "application/x-dosexec",
    "hashes": {
      "md5": "5d41402abc4b2a76b9719d911017c592",
      "sha1": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
      "sha256": "2c26b46b68ffc68ff99b453c1d30413413422d706...",
      "sha512": "f7fbba6e0636f890e56fbbf3283e524c6fa3204ae..."
    }
  },
  
  "verdict": {
    "classification": "malicious",
    "risk_score": 87,
    "confidence_score": 92.5,
    "severity": "critical"
  },
  
  "detection_details": {
    "yara_matches": [
      {
        "rule_name": "Code_Injection_APIs",
        "namespace": "malware_detection",
        "tags": ["injection", "process"],
        "meta": {
          "description": "Detecta APIs de inyección de código",
          "severity": "high"
        },
        "strings_matched": [
          "VirtualAllocEx",
          "WriteProcessMemory"
        ]
      }
    ],
    
    "behavioral_indicators": {
      "code_injection": {
        "detected": true,
        "confidence": 0.95,
        "apis": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
        "mitre_attack": ["T1055"]
      },
      "persistence": {
        "detected": true,
        "confidence": 0.80,
        "mechanisms": ["Registry Run key"],
        "mitre_attack": ["T1547.001"]
      }
    },
    
    "ml_predictions": {
      "consensus": {
        "probability": 0.89,
        "classification": "malicious"
      },
      "models": {
        "heuristic": 0.85,
        "xgboost": 0.92,
        "random_forest": 0.87
      }
    }
  },
  
  "capabilities": [
    {
      "name": "Inyección de Código",
      "description": "Puede inyectar código en procesos remotos",
      "danger_level": 95,
      "mitre_attack": "T1055"
    }
  ],
  
  "iocs": {
    "domains": ["malicious.example.com", "c2.badguy.tk"],
    "ips": ["192.0.2.1", "198.51.100.42"],
    "urls": ["http://malicious.example.com/payload.exe"],
    "registry_keys": [
      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Backdoor"
    ],
    "file_paths": ["C:\\Windows\\Temp\\malware.dll"],
    "mutexes": ["Global\\UniqueMalwareMutex"]
  },
  
  "recommended_actions": [
    "⚠️ CRÍTICO: Aislar inmediatamente la máquina de la red",
    "🔒 Bloquear IOCs en firewall y IDS/IPS",
    "🔍 Realizar análisis forense completo del sistema",
    "📋 Documentar todos los hallazgos para reporte de incidente"
  ]
}
```

---

## ⚙️ Configuración Avanzada

### Crear Reglas YARA Personalizadas

Crea archivo `custom_rules.yar` en `isviruspy/rules/`:

```yara
import "pe"
import "math"

rule Custom_Ransomware_2025 {
    meta:
        description = "Detecta variante de ransomware 2025"
        author = "Tu Nombre"
        date = "2025-01-09"
        reference = "https://example.com/analysis"
        severity = "critical"
    
    strings:
        $ransom_note = "All your files are encrypted" nocase
        $bitcoin_address = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/
        $onion_url = /[a-z2-7]{16}\.onion/
        
        $crypto_api1 = "CryptEncrypt" ascii
        $crypto_api2 = "CryptAcquireContext" ascii
        
        $file_ext1 = ".locked" ascii
        $file_ext2 = ".encrypted" ascii
    
    condition:
        uint16(0) == 0x5A4D and  // MZ header
        pe.number_of_sections > 2 and
        math.entropy(0, filesize) > 7.2 and
        (
            $ransom_note or
            ($bitcoin_address and $onion_url)
        ) and
        2 of ($crypto_api*) and
        any of ($file_ext*)
}
```

### Entrenar Modelo de ML Personalizado

```python
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

df = pd.read_csv('training_data.csv')

X = df.drop('is_malware', axis=1)
y = df['is_malware']

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

model = XGBClassifier(
    max_depth=6,
    learning_rate=0.1,
    n_estimators=100,
    objective='binary:logistic'
)

model.fit(X_train, y_train)

accuracy = model.score(X_test, y_test)
print(f"Accuracy: {accuracy:.2%}")

joblib.dump(model, 'isviruspy/models/custom_xgboost.pkl')
```

---

## 💡 Ejemplos Prácticos

### Caso 1: Análisis de Ejecutable Sospechoso

```bash
isviruspy scan suspicious.exe --json report.json
```

### Caso 2: Batch Analysis de Múltiples Muestras

```bash
for file in samples/*.exe; do
    isviruspy scan "$file" --json "reports/$(basename $file).json"
done
```

### Caso 3: Integración con Pipeline CI/CD

```yaml
# .github/workflows/malware-scan.yml
name: Malware Scan
on: [push]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Install IsVirusPY
        run: pip install isviruspy
      - name: Scan binaries
        run: isviruspy scan-dir ./dist --output-dir ./scan-reports
```

---

## 📚 API y Módulos

### Uso Programático

```python
from isviruspy.modules.static_analyzer import StaticAnalyzer
from isviruspy.modules.yara_engine import YaraEngine
from isviruspy.modules.ml_detector import MLDetector

analyzer = StaticAnalyzer()
static_data = analyzer.analyze('malware.exe')

yara = YaraEngine()
yara_results = yara.scan('malware.exe')

ml = MLDetector()
prediction = ml.analyze(static_data, yara_results, {})

print(f"Probability: {prediction['probability']:.2%}")
```

---

## 🤝 Contribuir

Las contribuciones son bienvenidas. Por favor:
1. Fork el proyecto
2. Crea una rama feature (`git checkout -b feature/nueva-funcionalidad`)
3. Commit tus cambios (`git commit -m 'Agregar nueva funcionalidad'`)
4. Push a la rama (`git push origin feature/nueva-funcionalidad`)
5. Abre un Pull Request

---

## ❓ Preguntas Frecuentes

**P: ¿IsVirusPY ejecuta malware?**  
R: No. Todo el análisis es estático y simulado. No hay ejecución de código.

**P: ¿Qué tan preciso es?**  
R: Depende del malware. Malware simple: 85-95%. Malware avanzado: 60-80%.

**P: ¿Puedo usarlo en producción?**  
R: No se recomienda como única solución. Úsalo como herramienta complementaria.

**P: ¿Es legal analizar malware?**  
R: Depende de tu jurisdicción. Consulta las leyes locales.

---

## 📖 Recursos

- **YARA Documentation**: https://yara.readthedocs.io/
- **pefile**: https://github.com/erocarrera/pefile
- **MITRE ATT&CK**: https://attack.mitre.org/
- **Malware Bazaar**: https://bazaar.abuse.ch/
- **VirusTotal**: https://www.virustotal.com/
- **Hybrid Analysis**: https://www.hybrid-analysis.com/

---

<div align="center">
  <p><strong>⚠️ Disclaimer</strong></p>
  <p>Esta herramienta NO debe ser utilizada para actividades ilegales.<br/>
  El análisis de malware debe realizarse solo en entornos controlados<br/>
  y con autorización adecuada.</p>
  
  <p>Desarrollado con ❤️ para la comunidad de ciberseguridad</p>
</div>
