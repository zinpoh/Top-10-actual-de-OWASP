# Lab A01:2021 – Control de Acceso Roto (Broken Access Control)

## 1. Identificación y Mapeo del Escenario
Este laboratorio práctico documenta la explotación y posterior detección de una vulnerabilidad de Control de Acceso Roto, clasificada como la posición #1 en el OWASP Top 10.

*   **ID OWASP:** A01:2021 – Broken Access Control
*   **Asociación CWE:** CWE-22 (Improper Limitation of a Pathname to a Restricted Directory / Path Traversal) o CWE-639 (Insecure Direct Object References - IDOR). *(Nota: Ajustar según el exploit exacto que uses, ej: IDOR o Path Traversal)*.
*   **Mapeo NIST SP 800-53:** AC-3 (Access Enforcement), AC-4 (Information Flow Enforcement).
*   **Táctica MITRE ATT&CK:** 
    *   **Atacante:** T1566 (Phishing) / T1190 (Exploit Public-Facing Application).
    *   **Defensor:** T1078 (Valid Accounts - Detección de abuso de cuentas).

---

## 2. Arquitectura y Despliegue del Laboratorio (Setup)

### 2.1. Máquina Atacante
*   **SO:** Kali Linux / Parrot OS.
*   **Herramientas clave:** Burp Suite Community/Pro, Curl, FFUF/Gobuster.

### 2.2. Máquina Víctima
*   **Entorno:** OWASP Juice Shop / DVWA (Desplegado en Docker o VM local).
*   **Telemetría activa:** Sysmon (Windows) o Auditd (Linux), además de logs del servidor web (Apache/Nginx) centralizados.
