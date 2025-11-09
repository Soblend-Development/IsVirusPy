import argparse
import sys
import os
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from isviruspy.modules.static_analyzer import StaticAnalyzer
from isviruspy.modules.yara_engine import YaraEngine
from isviruspy.modules.sandbox_analyzer import SandboxAnalyzer
from isviruspy.modules.ml_detector import MLDetector
from isviruspy.modules.report_generator import ReportGenerator
from isviruspy.modules.threat_intel import ThreatIntelligence

console = Console()

BANNER = """
╔═══════════════════════════════════════════════════════════╗
║                      IsVirusPY v1.0                        ║
║         Herramienta de Análisis de Malware en Python       ║
╚═══════════════════════════════════════════════════════════╝

[bold yellow]⚠️  ADVERTENCIA LEGAL:[/bold yellow]
• Solo para fines educativos y de investigación de seguridad
• NO ejecuta archivos maliciosos en el sistema host
• Puede generar falsos positivos/negativos
• NO reemplaza análisis profesional de seguridad
• Consultar leyes locales sobre posesión de malware
"""

def print_banner():
    console.print(BANNER)

def scan_file(file_path: str, output_json: str = None, verbose: bool = False) -> dict:
    if not os.path.exists(file_path):
        console.print(f"[red]Error: Archivo no encontrado: {file_path}[/red]")
        return None
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        
        task1 = progress.add_task("[cyan]Análisis estático...", total=None)
        static_analyzer = StaticAnalyzer()
        static_data = static_analyzer.analyze(file_path)
        progress.update(task1, completed=True)
        
        task2 = progress.add_task("[cyan]Escaneo YARA...", total=None)
        yara_engine = YaraEngine()
        yara_data = yara_engine.scan(file_path)
        progress.update(task2, completed=True)
        
        task3 = progress.add_task("[cyan]Análisis de comportamiento...", total=None)
        sandbox_analyzer = SandboxAnalyzer()
        sandbox_data = sandbox_analyzer.analyze(static_data)
        progress.update(task3, completed=True)
        
        task4 = progress.add_task("[cyan]Detección Multi-Modelo ML...", total=None)
        ml_detector = MLDetector()
        ml_data = ml_detector.analyze(static_data, yara_data, sandbox_data)
        progress.update(task4, completed=True)
        
        task5 = progress.add_task("[cyan]Consultando Threat Intelligence...", total=None)
        threat_intel = ThreatIntelligence()
        file_hashes = {
            "md5": static_data.get("hashes", {}).get("md5", ""),
            "sha1": static_data.get("hashes", {}).get("sha1", ""),
            "sha256": static_data.get("hashes", {}).get("sha256", "")
        }
        threat_intel_data = threat_intel.generate_threat_intel_report(
            file_hashes, static_data, sandbox_data
        )
        progress.update(task5, completed=True)
        
        task6 = progress.add_task("[cyan]Generando reporte...", total=None)
        report_gen = ReportGenerator()
        report = report_gen.generate_report(file_path, static_data, yara_data, 
                                           sandbox_data, ml_data)
        
        # Agregar threat intelligence al reporte
        report["threat_intelligence"] = threat_intel_data
        
        progress.update(task6, completed=True)
    
    console.print("\n")
    report_gen.print_summary(report)
    
    if output_json:
        report_gen.save_json_report(report, output_json)
        console.print(f"\n[green]Reporte JSON guardado en: {output_json}[/green]")
    
    if verbose:
        console.print("\n[bold]Detalles Completos:[/bold]")
        import json
        console.print(json.dumps(report, indent=2, ensure_ascii=False))
    
    return report

def scan_directory(dir_path: str, output_dir: str = None, recursive: bool = False):
    if not os.path.exists(dir_path):
        console.print(f"[red]Error: Directorio no encontrado: {dir_path}[/red]")
        return
    
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    files_to_scan = []
    
    if recursive:
        for root, dirs, files in os.walk(dir_path):
            for file in files:
                files_to_scan.append(os.path.join(root, file))
    else:
        files_to_scan = [os.path.join(dir_path, f) for f in os.listdir(dir_path) 
                        if os.path.isfile(os.path.join(dir_path, f))]
    
    console.print(f"[cyan]Escaneando {len(files_to_scan)} archivos...[/cyan]\n")
    
    results = []
    for i, file_path in enumerate(files_to_scan, 1):
        console.print(f"\n[bold]Archivo {i}/{len(files_to_scan)}: {os.path.basename(file_path)}[/bold]")
        
        output_json = None
        if output_dir:
            json_name = f"{os.path.basename(file_path)}_report.json"
            output_json = os.path.join(output_dir, json_name)
        
        report = scan_file(file_path, output_json=output_json)
        if report:
            results.append(report)
    
    console.print(f"\n[green]Escaneo completado: {len(results)} archivos analizados[/green]")
    
    malicious = sum(1 for r in results if r.get("verdict") == "malicious")
    suspicious = sum(1 for r in results if r.get("verdict") == "suspicious")
    
    console.print(f"[red]Maliciosos: {malicious}[/red] | "
                 f"[yellow]Sospechosos: {suspicious}[/yellow] | "
                 f"[green]Limpios/Desconocidos: {len(results) - malicious - suspicious}[/green]")

def check_hash(hash_value: str):
    console.print(f"[yellow]Buscando hash: {hash_value}[/yellow]")
    console.print("[dim]Esta funcionalidad requiere integración con bases de datos de hashes conocidos[/dim]")
    console.print("[dim]Sugerencia: Verificar en VirusTotal, MalwareBazaar, o bases internas[/dim]")

def main():
    parser = argparse.ArgumentParser(
        description="IsVirusPY - Análisis y detección de malware",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  isviruspy scan archivo.exe
  isviruspy scan archivo.exe --json reporte.json
  isviruspy scan-dir /path/to/samples --output-dir reports/
  isviruspy scan-dir /path/to/samples --recursive
  isviruspy check-hash 5d41402abc4b2a76b9719d911017c592
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Comandos disponibles')
    
    scan_parser = subparsers.add_parser('scan', help='Escanear un archivo')
    scan_parser.add_argument('file', help='Ruta del archivo a escanear')
    scan_parser.add_argument('--json', dest='output_json', help='Guardar reporte en JSON')
    scan_parser.add_argument('--verbose', '-v', action='store_true', help='Salida detallada')
    
    scan_dir_parser = subparsers.add_parser('scan-dir', help='Escanear directorio')
    scan_dir_parser.add_argument('directory', help='Ruta del directorio')
    scan_dir_parser.add_argument('--output-dir', help='Directorio para reportes JSON')
    scan_dir_parser.add_argument('--recursive', '-r', action='store_true', 
                                help='Escanear subdirectorios recursivamente')
    
    hash_parser = subparsers.add_parser('check-hash', help='Verificar hash')
    hash_parser.add_argument('hash', help='Hash MD5/SHA1/SHA256 a verificar')
    
    parser.add_argument('--no-banner', action='store_true', help='No mostrar banner')
    
    args = parser.parse_args()
    
    if not args.no_banner:
        print_banner()
    
    if not args.command:
        parser.print_help()
        return 0
    
    if args.command == 'scan':
        scan_file(args.file, output_json=args.output_json, verbose=args.verbose)
    
    elif args.command == 'scan-dir':
        scan_directory(args.directory, output_dir=args.output_dir, 
                      recursive=args.recursive)
    
    elif args.command == 'check-hash':
        check_hash(args.hash)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
