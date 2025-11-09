import json
from datetime import datetime
from typing import Dict, Any, List

class ReportGenerator:
    def generate_report(self, file_path: str, static_data: Dict, yara_data: Dict,
                       sandbox_data: Dict, ml_data: Dict) -> Dict[str, Any]:
        risk_score = self._calculate_risk_score(static_data, yara_data, sandbox_data, ml_data)
        verdict = self._determine_verdict(risk_score, yara_data, ml_data)
        detection_reasons = self._compile_detection_reasons(yara_data, sandbox_data, ml_data)
        confidence = self._calculate_confidence(detection_reasons, ml_data)

        report = {
            "file_name": static_data.get("file_info", {}).get("file_name", "unknown"),
            "file_path": file_path,
            "sha256": static_data.get("hashes", {}).get("sha256", ""),
            "md5": static_data.get("hashes", {}).get("md5", ""),
            "sha1": static_data.get("hashes", {}).get("sha1", ""),
            "file_type": static_data.get("format_specific", {}).get("type", "Unknown"),
            "size_bytes": static_data.get("file_info", {}).get("size_bytes", 0),
            "scan_date": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "risk_score": risk_score,
            "verdict": verdict,
            "detection_reasons": detection_reasons,
            "iocs": sandbox_data.get("iocs", {}),
            "recommended_actions": self._generate_recommendations(verdict, risk_score, detection_reasons),
            "confidence_score": confidence,
            "limitations": "Esta herramienta puede generar falsos positivos con empaquetadores legítimos y software ofuscado. NO reemplaza un análisis humano profesional o un equipo SOC. El análisis dinámico es SIMULADO (sin ejecución real).",
            "static_analysis": {
                "entropy": static_data.get("entropy", 0),
                "strings_found": len(static_data.get("strings", {}).get("all_strings", [])),
                "suspicious_imports": len(static_data.get("format_specific", {}).get("suspicious_characteristics", []))
            },
            "yara_analysis": {
                "rules_matched": yara_data.get("total_matches", 0),
                "matches": yara_data.get("matches", [])
            },
            "behavioral_analysis": {
                "disclaimer": sandbox_data.get("disclaimer", ""),
                "indicators": sandbox_data.get("behavioral_indicators", {}),
                "risk_factors": sandbox_data.get("risk_factors", [])
            },
            "ml_analysis": ml_data
        }

        return report

    def _calculate_risk_score(self, static_data: Dict, yara_data: Dict,
                              sandbox_data: Dict, ml_data: Dict) -> int:
        score = 0.0

        ml_prob = ml_data.get("consensus_probability", ml_data.get("probability", 0))
        score += ml_prob * 60

        yara_matches = yara_data.get("total_matches", 0)
        score += min(yara_matches * 20, 25)

        behavioral_count = len(sandbox_data.get("behavioral_indicators", {}))
        if behavioral_count >= 5:
            score += 25
        elif behavioral_count >= 3:
            score += 15
        elif behavioral_count > 0:
            score += 10

        risk_factors = len(sandbox_data.get("risk_factors", []))
        score += min(risk_factors * 3, 15)

        format_data = static_data.get("format_specific", {})
        suspicious_chars = len(format_data.get("suspicious_characteristics", []))
        if suspicious_chars > 5:
            score += 20
        elif suspicious_chars > 2:
            score += 10
        elif suspicious_chars > 0:
            score += 5

        entropy = static_data.get("entropy", 0)
        if entropy > 7.5:
            score += 10
        elif entropy > 7.0:
            score += 5

        return min(int(score), 100)

    def _determine_verdict(self, risk_score: int, yara_data: Dict, ml_data: Dict) -> str:
        if risk_score >= 80:
            return "malicious"
        elif risk_score >= 55:
            return "suspicious"
        elif risk_score >= 30:
            return "unknown"
        else:
            return "clean"

    def _compile_detection_reasons(self, yara_data: Dict, sandbox_data: Dict,
                                   ml_data: Dict) -> List[Dict[str, Any]]:
        reasons = []

        for match in yara_data.get("matches", []):
            reasons.append({
                "type": "yara",
                "rule": match.get("rule", "unknown"),
                "confidence": 0.85,
                "description": f"Regla YARA '{match.get('rule')}' coincidió"
            })

        behavioral = sandbox_data.get("behavioral_indicators", {})
        for category, data in behavioral.items():
            reasons.append({
                "type": "behavioral",
                "behavior": category,
                "confidence": 0.75,
                "description": f"Indicadores de {category} detectados: {', '.join(data.get('indicators', [])[:3])}"
            })

        model_results = ml_data.get("model_results", [])
        consensus_prob = ml_data.get("consensus_probability", 0)

        if model_results:
            reasons.append({
                "type": "ml_consensus",
                "model": f"{len(model_results)} modelos consultados",
                "probability": consensus_prob,
                "confidence": ml_data.get("confidence", 0.5),
                "description": f"Consenso de {len(model_results)} modelos: {consensus_prob*100:.1f}% probabilidad de malware"
            })

        return reasons

    def _calculate_confidence(self, detection_reasons: List[Dict], ml_data: Dict) -> float:
        if not detection_reasons:
            return 0.3

        confidences = [r.get("confidence", 0.5) for r in detection_reasons]
        avg_confidence = sum(confidences) / len(confidences)

        if len(detection_reasons) >= 3:
            avg_confidence = min(avg_confidence * 1.2, 1.0)

        return round(avg_confidence, 2)

    def _generate_recommendations(self, verdict: str, risk_score: int,
                                 detection_reasons: List[Dict]) -> List[str]:
        recommendations = []

        if verdict == "malicious":
            recommendations.append("⚠️ CRÍTICO: Aislar inmediatamente la máquina de la red")
            recommendations.append("Eliminar el archivo y colocarlo en cuarentena")
            recommendations.append("Realizar escaneo completo del sistema")
            recommendations.append("Verificar persistencia en registro y tareas programadas")
            recommendations.append("Bloquear IOCs (dominios/IPs) en firewall y proxy")
            recommendations.append("Enviar muestra a equipo SOC para análisis profesional")

        elif verdict == "suspicious":
            recommendations.append("Colocar archivo en cuarentena preventiva")
            recommendations.append("Enviar a análisis dinámico en sandbox aislado")
            recommendations.append("Revisar contexto de origen del archivo")
            recommendations.append("Consultar con equipo de seguridad")
            recommendations.append("No ejecutar sin verificación adicional")

        elif verdict == "unknown":
            recommendations.append("Verificar firma digital y certificado del archivo")
            recommendations.append("Investigar origen y propósito legítimo")
            recommendations.append("Comparar hash con bases de datos públicas")
            recommendations.append("Considerar análisis manual si es crítico")

        else:
            recommendations.append("El archivo parece seguro según análisis actual")
            recommendations.append("Mantener vigilancia en sistemas de monitoreo")
            recommendations.append("Actualizar regularmente firmas de detección")

        any_yara = any(r.get("type") == "yara" for r in detection_reasons)
        if any_yara:
            recommendations.insert(0, "Coincidencia con reglas YARA - revisar detalles en reporte")

        return recommendations

    def save_json_report(self, report: Dict[str, Any], output_path: str):
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

    def print_summary(self, report: Dict[str, Any]):
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
        from rich.layout import Layout
        from rich.align import Align
        from rich.text import Text
        from rich import box

        console = Console()

        verdict = report["verdict"]
        verdict_colors = {
            "malicious": "red",
            "suspicious": "yellow",
            "unknown": "blue",
            "clean": "green"
        }
        color = verdict_colors.get(verdict, "white")

        logo = """
╔═══════════════════════════════════════════════════════════╗
║  ██╗███████╗██╗   ██╗██╗██████╗ ██╗   ██╗███████╗██████╗ ║
║  ██║██╔════╝██║   ██║██║██╔══██╗██║   ██║██╔════╝██╔══██╗║
║  ██║███████╗██║   ██║██║██████╔╝██║   ██║███████╗██████╔╝║
║  ██║╚════██║╚██╗ ██╔╝██║██╔══██╗██║   ██║╚════██║██╔═══╝ ║
║  ██║███████║ ╚████╔╝ ██║██║  ██║╚██████╔╝███████║██║     ║
║  ╚═╝╚══════╝  ╚═══╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝     ║
╚═══════════════════════════════════════════════════════════╝
        """
        console.print(f"[cyan]{logo}[/cyan]")

        ml_analysis = report.get("ml_analysis", {})
        malware_probability = ml_data.get("consensus_probability", 0) * 100

        verdict_emoji = {
            "malicious": "☠️ ",
            "suspicious": "⚠️ ",
            "unknown": "❓",
            "clean": "✅"
        }

        title_text = Text()
        title_text.append(f"{verdict_emoji.get(verdict, '')} ", style="bold")
        title_text.append(verdict.upper(), style=f"bold {color}")

        stats_text = (
            f"[bold white]Risk Score:[/bold white] [{color}]{report['risk_score']}/100[/{color}] | "
            f"[bold white]Malware Prob:[/bold white] [{color}]{malware_probability:.1f}%[/{color}] | "
            f"[bold white]Confidence:[/bold white] [{color}]{report['confidence_score']:.0%}[/{color}]"
        )

        title = Panel(
            Align.center(f"{title_text.markup}\n\n{stats_text}"),
            title=f"[bold cyan]═══ SCAN RESULT: {report['file_name']} ═══[/bold cyan]",
            border_style=color,
            box=box.DOUBLE
        )
        console.print(title)

        table = Table(
            title="[bold cyan]╔═══ FILE INFORMATION ═══╗[/bold cyan]",
            box=box.DOUBLE_EDGE,
            show_header=True,
            header_style="bold magenta",
            border_style="cyan"
        )
        table.add_column("🔍 FIELD", style="bold yellow", width=15)
        table.add_column("📊 VALUE", style="white", width=50)

        table.add_row("SHA-256", f"[dim]{report['sha256']}[/dim]")
        table.add_row("File Type", f"[green]{report['file_type']}[/green]")
        table.add_row("Size", f"[cyan]{report['size_bytes']:,}[/cyan] bytes")
        table.add_row("Scan Time", f"[blue]{report['scan_date']}[/blue]")

        console.print("\n")
        console.print(table)
        console.print("\n")

        capabilities = self._extract_capabilities(report)

        cap_panel = Panel(
            f"[bold red]{'═' * 55}[/bold red]",
            title="[bold red]☠️  DETECTED CAPABILITIES & THREAT ACTIONS  ☠️[/bold red]",
            border_style="red",
            box=box.HEAVY
        )
        console.print(cap_panel)

        if capabilities:
            console.print(f"\n[bold yellow]⚡ Found {len(capabilities)} malicious capabilities[/bold yellow]\n")

            for i, cap in enumerate(capabilities, 1):
                danger_level = cap["danger_level"]
                danger_color = self._get_danger_color(danger_level)
                bar = self._create_danger_bar(danger_level)

                emoji = "🔴" if danger_level >= 90 else "🟠" if danger_level >= 75 else "🟡" if danger_level >= 60 else "🟢"

                cap_content = (
                    f"[bold white]{cap['action']}[/bold white]\n"
                    f"[dim italic]{cap['description']}[/dim italic]\n\n"
                    f"[bold]Danger Level:[/bold] {bar} [{danger_color}]{danger_level}/100[/{danger_color}]"
                )

                if cap.get("details"):
                    cap_content += f"\n\n[bold yellow]🔎 Indicators Found:[/bold yellow]"
                    for detail in cap["details"]:
                        cap_content += f"\n  [dim]▸[/dim] {detail}"

                cap_box = Panel(
                    cap_content,
                    title=f"[bold]{emoji} #{i}[/bold]",
                    border_style=danger_color,
                    box=box.ROUNDED
                )
                console.print(cap_box)
        else:
            success_panel = Panel(
                "[bold green]✅ No malicious capabilities detected[/bold green]\n"
                "[dim]The file appears clean from behavioral perspective[/dim]",
                border_style="green",
                box=box.ROUNDED
            )
            console.print(success_panel)

        ml_analysis = report.get("ml_analysis", {})
        if ml_analysis.get("models_consulted", 0) > 0:
            consensus = ml_analysis.get('consensus_probability', 0)*100
            consensus_color = "red" if consensus > 70 else "yellow" if consensus > 40 else "green"

            ml_content = (
                f"[bold]Models Consulted:[/bold] [cyan]{ml_analysis['models_consulted']}[/cyan]\n"
                f"[bold]Consensus:[/bold] [{consensus_color}]{consensus:.1f}% MALWARE probability[/{consensus_color}]\n"
                f"[bold]Analysis Confidence:[/bold] [magenta]{ml_analysis.get('confidence', 0)*100:.1f}%[/magenta]\n\n"
                f"[bold yellow]═══ Model Results ═══[/bold yellow]"
            )

            model_results = ml_analysis.get("model_results", [])
            for result in model_results[:5]:
                prob = result["probability"] * 100
                model_name = result["model"]
                color = "red" if prob > 70 else "yellow" if prob > 40 else "green"

                bar_len = int((prob / 100) * 30)
                bar = f"[{color}]{'█' * bar_len}{'░' * (30 - bar_len)}[/{color}]"
                ml_content += f"\n{bar} [{color}]{model_name}: {prob:.1f}%[/{color}]"

            ml_panel = Panel(
                ml_content,
                title="[bold magenta]🤖 MACHINE LEARNING ANALYSIS 🤖[/bold magenta]",
                border_style="magenta",
                box=box.HEAVY
            )
            console.print("\n")
            console.print(ml_panel)

        threat_intel = report.get("threat_intelligence", {})
        if threat_intel:
            ti_content = f"[bold]Sources Consulted:[/bold] [cyan]{threat_intel.get('sources_consulted', 0)}[/cyan]\n\n"

            hash_rep = threat_intel.get("hash_reputation", {})
            if hash_rep.get("hash_found"):
                ti_content += "[bold red]🚨 HASH FOUND IN MALWARE DATABASES 🚨[/bold red]\n"
                for detection in hash_rep.get("detections", []):
                    severity_emoji = "🔴" if detection['severity'] == "high" else "🟠" if detection['severity'] == "medium" else "🟡"
                    ti_content += f"{severity_emoji} [red]{detection['source']}:[/red] {detection['malware_name']} ([yellow]{detection['severity']}[/yellow])\n"
                ti_content += "\n"

            file_rep = threat_intel.get("file_reputation", {})
            trust_score = file_rep.get("trust_score", 50)
            trust_color = "green" if trust_score > 70 else "yellow" if trust_score > 40 else "red"
            trust_bar = self._create_danger_bar(trust_score)
            ti_content += f"[bold]Trust Score:[/bold] {trust_bar} [{trust_color}]{trust_score}/100[/{trust_color}]\n"

            if file_rep.get("observations"):
                ti_content += "\n[bold yellow]📋 Observations:[/bold yellow]\n"
                for obs in file_rep["observations"][:3]:
                    ti_content += f"  [dim]▸[/dim] {obs}\n"

            threat_context = threat_intel.get("threat_context", {})
            if threat_context.get("threat_categories"):
                ti_content += f"\n[bold]🏷️  Categories:[/bold] [cyan]{', '.join(threat_context['threat_categories'])}[/cyan]"
            if threat_context.get("mitre_tactics"):
                ti_content += f"\n[bold]⚔️  MITRE ATT&CK:[/bold] [red]{len(threat_context['mitre_tactics'])} tactics detected[/red]"

            ti_panel = Panel(
                ti_content,
                title="[bold cyan]🌐 THREAT INTELLIGENCE 🌐[/bold cyan]",
                border_style="cyan",
                box=box.HEAVY
            )
            console.print("\n")
            console.print(ti_panel)

        if report["detection_reasons"]:
            reasons_content = ""
            for i, reason in enumerate(report["detection_reasons"][:5], 1):
                type_emoji = "🎯" if reason['type'] == "yara" else "🧠" if reason['type'] == "ml_consensus" else "⚙️"
                reasons_content += f"{type_emoji} [bold yellow]#{i}[/bold yellow] [[cyan]{reason['type']}[/cyan]] {reason.get('description', '')}\n"

            reasons_panel = Panel(
                reasons_content,
                title="[bold yellow]📋 DETECTION REASONS 📋[/bold yellow]",
                border_style="yellow",
                box=box.HEAVY
            )
            console.print("\n")
            console.print(reasons_panel)

        if report["recommended_actions"]:
            actions_content = ""
            for i, action in enumerate(report["recommended_actions"], 1):
                emoji = "🚨" if "CRÍTICO" in action or "CRITICAL" in action else "⚠️" if i <= 2 else "💡"
                actions_content += f"{emoji} {action}\n"

            actions_panel = Panel(
                actions_content,
                title="[bold cyan]⚡ RECOMMENDED ACTIONS ⚡[/bold cyan]",
                border_style="cyan",
                box=box.HEAVY
            )
            console.print("\n")
            console.print(actions_panel)

        footer = Panel(
            f"[dim italic]{report['limitations']}[/dim italic]",
            title="[bold red]⚠️  DISCLAIMER ⚠️[/bold red]",
            border_style="red",
            box=box.ROUNDED
        )
        console.print("\n")
        console.print(footer)
        console.print("\n[bold cyan]═══════════════════════════════════════════════════════════[/bold cyan]\n")

    def _extract_capabilities(self, report: Dict[str, Any]) -> List[Dict[str, Any]]:
        capabilities = []
        behavioral = report.get("behavioral_analysis", {}).get("indicators", {})

        capability_map = {
            "network": {
                "action": "Comunicación de Red",
                "description": "Puede conectarse a servidores remotos, enviar/recibir datos",
                "danger": 60
            },
            "file_operations": {
                "action": "Manipulación de Archivos",
                "description": "Puede crear, modificar o eliminar archivos en el sistema",
                "danger": 70
            },
            "registry": {
                "action": "Modificación del Registro",
                "description": "Puede cambiar configuraciones del sistema en el Registro de Windows",
                "danger": 75
            },
            "process": {
                "action": "Gestión de Procesos",
                "description": "Puede crear, terminar o inyectar código en otros procesos",
                "danger": 85
            },
            "persistence": {
                "action": "Persistencia en el Sistema",
                "description": "Intenta ejecutarse automáticamente al iniciar Windows",
                "danger": 80
            },
            "anti_analysis": {
                "action": "Evasión de Análisis",
                "description": "Usa técnicas para evitar detección (anti-debugger, anti-VM)",
                "danger": 90
            },
            "cryptography": {
                "action": "Cifrado/Descifrado",
                "description": "Puede cifrar archivos o comunicaciones (posible ransomware)",
                "danger": 95
            },
            "keylogging": {
                "action": "Captura de Teclado",
                "description": "Puede registrar teclas presionadas (robo de contraseñas)",
                "danger": 100
            },
            "code_injection": {
                "action": "Inyección de Código",
                "description": "Puede inyectar código malicioso en procesos legítimos",
                "danger": 95
            },
            "privilege_escalation": {
                "action": "Elevación de Privilegios",
                "description": "Intenta obtener permisos de administrador",
                "danger": 90
            }
        }

        for indicator_type, data in behavioral.items():
            if indicator_type in capability_map:
                cap_info = capability_map[indicator_type]
                indicators_found = data.get("indicators", [])

                if indicators_found:
                    capabilities.append({
                        "action": cap_info["action"],
                        "description": cap_info["description"],
                        "danger_level": cap_info["danger"],
                        "details": indicators_found[:3]
                    })

        capabilities.sort(key=lambda x: x["danger_level"], reverse=True)

        return capabilities

    def _get_danger_color(self, danger_level: int) -> str:
        if danger_level >= 90:
            return "bright_red"
        elif danger_level >= 75:
            return "red"
        elif danger_level >= 60:
            return "yellow"
        elif danger_level >= 40:
            return "cyan"
        else:
            return "green"

    def _create_danger_bar(self, danger_level: int) -> str:
        bar_length = 20
        filled = int((danger_level / 100) * bar_length)
        empty = bar_length - filled

        color = self._get_danger_color(danger_level)
        bar = f"[{color}]{'█' * filled}[/{color}]{'░' * empty}"

        return bar