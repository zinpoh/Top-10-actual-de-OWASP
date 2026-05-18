# 🔬 Lab Técnico: Explotación de Path Traversal (OWASP A01:2021) y Telemetría de Endpoint en Entornos IIS/.NET

## 📋 Descripción del Escenario
Este laboratorio práctico documenta el despliegue, explotación y posterior análisis forense de una vulnerabilidad de **Control de Acceso Roto (Broken Access Control)**, específicamente un **Path Traversal / Arbitrary File Read (CWE-22 / CWE-73)**. 

El objetivo es simular el ciclo de vida completo de un ataque controlado en un entorno empresarial basado en la pila tecnológica de Microsoft, aplicando metodologías ofensivas y recolectando telemetría avanzada mediante **Sysmon** para emular las capacidades de un analista SOC / Incident Responder de nivel corporativo.

---

## 🗺️ Matriz de Mapeo de Threat Intelligence

| Componente | Identificador / Framework | Clasificación / Táctica |
| :--- | :--- | :--- |
| **Categoría OWASP** | Top 10:2021 - A01 | Broken Access Control |
| **Debilidad Mitre** | CWE-22 / CWE-73 | Path Traversal / File Access |
| **Framework NIST** | SP 800-53 Rev. 5 | AC-3 (Access Enforcement) / AU-6 (Audit Review) |
| **Táctica MITRE ATT&CK (Red)** | T1190 / T1083 | Exploit Public-Facing Application / File & Directory Discovery |
| **Táctica MITRE ATT&CK (Blue)** | T1078 / DS0009 | Valid Accounts / Process Creation Logs (Sysmon) |

---

## 🛠️ Fase 1: Despliegue de la Infraestructura e Ingeniería de Red

Para contener los artefactos ofensivos y evitar fugas de tráfico hacia la red doméstica o Internet, la arquitectura se despliega en un entorno de red lógicamente aislado.
