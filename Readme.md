
🛡️ Proyecto de Solución de Ciberseguridad para el Sector Financiero
Análisis y Mitigación de un Ataque Complejo Basado en el Caso BCP
📄 Resumen Ejecutivo

Este proyecto presenta una solución de ciberseguridad integral y de extremo a extremo, diseñada para proteger a una institución financiera contra ciberataques modernos y multifacéticos. Tomando como base un caso de estudio realista que involucra spear-phishing, movimiento lateral y ransomware, se propone una arquitectura de Defensa en Profundidad utilizando herramientas líderes del cuadrante de Gartner ("Best-of-Breed").

La solución no solo detalla la selección e implementación de tecnologías, sino que también aborda mejoras cruciales en políticas y procedimientos, alineándose con los principales frameworks de la industria como NIST CSF y MITRE ATT&CK®.

El entregable principal es una arquitectura documentada y justificada, acompañada de una simulación interactiva en HTML que visualiza cómo esta defensa integrada neutraliza el ataque en tiempo real.

💥 El Caso de Estudio: Un Ataque en Múltiples Fases

El escenario se basa en un ataque devastador contra una entidad financiera (Banco Global / BCP), cuya cadena de ataque se resume en los siguientes pasos:

Entrada Inicial: Un correo de spear-phishing dirigido a un empleado, con un enlace que redirige a un sitio web malicioso.

Compromiso del Endpoint: Al hacer clic, se explota una vulnerabilidad del navegador que instala un backdoor en el sistema del empleado.

Robo de Credenciales: Los atacantes utilizan el backdoor para robar las credenciales del empleado.

Movimiento Lateral: Usando las credenciales robadas ("Valid Accounts"), los atacantes acceden a la red interna a través de "Remote Services".

Escalada de Privilegios: Explotan vulnerabilidades en la configuración de la nube y sistemas IAM para obtener control de administrador.

Impacto Final: Despliegan ransomware en servidores críticos y exfiltran datos sensibles, causando un impacto económico y reputacional masivo.

💡 Arquitectura de Solución Propuesta: Defensa en Profundidad

La solución se fundamenta en el principio de Defensa en Profundidad, creando múltiples barreras de seguridad para asegurar que, si una falla, otras puedan contener la amenaza.

Capa 1: Perímetro y Email

Objetivo: Bloquear la entrada inicial de amenazas.

Herramientas Clave: Microsoft Defender for Office 365.

Capa 2: Endpoint y Web

Objetivo: Proteger las estaciones de trabajo y controlar la navegación.

Herramientas Clave: CrowdStrike Falcon (EDR/XDR), Netskope SSE (SWG).

Capa 3: Identidad (Zero Trust)

Objetivo: Asegurar que solo usuarios verificados accedan a los recursos correctos.

Herramientas Clave: Microsoft Entra ID (Azure AD).

Capa 4: Red Interna

Objetivo: Segmentar la red para contener la propagación de amenazas.

Herramientas Clave: Palo Alto Networks NGFW.

Capa 5: Correlación y Respuesta (XDR)

Objetivo: Centralizar la visibilidad, correlacionar alertas y automatizar la respuesta.

Herramientas Clave: Microsoft Sentinel (SIEM/XDR).

🏛️ Fundamentos del Modelo de Seguridad Propuesto

Este diseño de capas no es arbitrario; se sustenta en principios y marcos de ciberseguridad universalmente aceptados.

1. Defensa en Profundidad (Defense in Depth - DiD)

Es una estrategia que asume que ningún control de seguridad es perfecto. Por ello, se implementan múltiples capas de defensa. Si un atacante logra superar la primera barrera (ej. el filtro de email), se encontrará con la segunda (el EDR en el endpoint), y luego con la tercera (los controles de identidad con MFA), y así sucesivamente. Esto aumenta exponencialmente la dificultad del ataque y la probabilidad de detección.

2. Alineación con Frameworks (NIST e ISO 27001)

El modelo se alinea directamente con los principales marcos de la industria:

NIST Cybersecurity Framework (CSF): Nuestras capas implementan las funciones clave de Proteger (controles en el perímetro, endpoint e identidad) y Detectar (EDR, NGFW, SIEM). La automatización con un SOAR (Sentinel) materializa la función de Responder.

ISO/IEC 27001: Los controles implementados en cada capa (control de acceso, seguridad de red, protección contra malware) ayudan a cumplir directamente con los requisitos del Anexo A de la norma.

3. Mapeo contra Modelos de Ataque (MITRE ATT&CK®)

La arquitectura está diseñada para interrumpir la cadena de un ataque moderno. Cada capa y herramienta mitiga Tácticas, Técnicas y Procedimientos (TTPs) específicos del framework MITRE ATT&CK:

T1566.002 (Spearphishing Link): Mitigado por la Capa 1 (Defender for O365).

T1059 (Command and Scripting Interpreter): Mitigado por la Capa 2 (CrowdStrike Falcon).

T1078 (Valid Accounts): Mitigado por la Capa 3 (Entra ID con MFA).

T1486 (Data Encrypted for Impact): Mitigado preventivamente por todas las capas anteriores.

📊 Desglose Detallado de la Solución
Actividad 1: Diseño de Infraestructura y Herramientas

El diseño se detalla en la sección de Arquitectura anterior. Las herramientas seleccionadas representan a los líderes en sus respectivas categorías según analistas como Gartner, asegurando una protección de clase mundial.

Actividad 2: Capacidades de Protección por Herramienta (Pilares CID)
Herramienta	Confidencialidad	Integridad	Disponibilidad
Microsoft Defender for O365	Evita el robo de credenciales (Safe Links) y previene la fuga de datos por email (DLP).	Analiza adjuntos en sandbox para que no contengan malware que altere datos.	Filtra spam masivo y ataques DoS, manteniendo la comunicación operativa.
CrowdStrike Falcon	Previene que el ransomware cifre datos. Detecta el robo de credenciales en memoria.	Previene la modificación no autorizada de archivos y procesos críticos del sistema.	Aísla hosts infectados en segundos, minimizando el downtime y la propagación.
Microsoft Entra ID	Exige MFA, garantizando que solo usuarios autorizados accedan a datos, incluso con contraseñas robadas.	Asegura la autenticidad del usuario, previniendo suplantaciones que puedan corromper datos.	Protege contra ataques de bloqueo de cuentas y centraliza la gestión del acceso.
Palo Alto Networks NGFW	Segmenta la red para que una brecha en una zona no exponga datos confidenciales de otra.	Su IPS previene exploits de red que buscan comprometer la integridad de los servidores.	Ofrece protección contra DoS/DDoS y alta disponibilidad para la conectividad de la red.
Netskope SSE	Impide la subida de datos sensibles a aplicaciones cloud no autorizadas (Shadow IT).	Inspecciona el tráfico web para prevenir la descarga de malware.	Asegura el acceso seguro y de alto rendimiento a aplicaciones web y en la nube.
Actividad 3: Procedimientos para Asegurar la Optimización Continua

Gestión de Vulnerabilidades Basada en Riesgo: Utilizar plataformas como Tenable.io para escanear y priorizar la remediación de vulnerabilidades en función del riesgo real para el negocio, no solo de su severidad técnica.

Validación Continua de Controles (BAS): Implementar herramientas de Simulación de Brechas y Ataques (BAS) como Mandiant Security Validation para probar de forma segura y automatizada si los controles de seguridad están configurados correctamente para detener las últimas TTPs de los atacantes.

Caza Proactiva de Amenazas (Threat Hunting): El equipo de seguridad debe usar el lenguaje de consulta KQL en Microsoft Sentinel para buscar proactivamente indicadores de compromiso sutiles que no hayan generado una alerta automática.

Actividad 4: Propuesta de Mejoras en Políticas y Procesos

Adopción Formal de una Arquitectura Zero Trust: Ir más allá de las herramientas e implementar la filosofía "nunca confiar, siempre verificar". Todo acceso debe ser autenticado, autorizado y cifrado, basándose en la identidad, el estado del dispositivo y otros contextos.

Programa de Concienciación de Seguridad de Nueva Generación: Utilizar plataformas como KnowBe4 para ejecutar campañas de phishing simuladas y formación personalizada, convirtiendo a los empleados de un eslabón débil a una primera línea de defensa humana.

Plan de Respuesta a Incidentes (IR) con Retainer: Formalizar los playbooks de respuesta en Microsoft Sentinel SOAR y establecer un contrato de "retainer" con una firma experta en IR (ej. Mandiant) para garantizar apoyo especializado en caso de una crisis mayor.

💻 Simulación Interactiva de la Defensa

Para visualizar cómo esta arquitectura neutraliza el ataque descrito, se ha creado una simulación en HTML y JavaScript.

¿Cómo usarla?

Copia todo el código del bloque inferior.

Guárdalo en un archivo con el nombre simulation.html.

Abre el archivo simulation.html en un navegador web moderno (Chrome, Firefox, Edge).

La simulación se ejecutará automáticamente, mostrando la ruta del ataque y cómo cada capa de seguridad lo detecta y lo bloquea, con alertas que aparecen en tiempo real en el panel lateral.

code
Html
download
content_copy
expand_less

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Solución de Seguridad "Best-of-Breed" para BCP - Diagrama v2</title>
    <style>
        :root {
            --bg-color: #f4f7fa;
            --layer-line-color: #dfe8f1;
            --text-color: #333;
            --header-color: #0033a0;
            --label-bg: #e9f2ff;
            --label-border: #0056b3;
            --attack-red: #d92d20;
            --alert-info-bg: #e0f2fe;
            --alert-info-border: #0ea5e9;
            --alert-warning-bg: #fffbeb;
            --alert-warning-border: #f59e0b;
            --alert-critical-bg: #fff1f2;
            --alert-critical-border: #f43f5e;
            --impact-bg: #1e3a8a;
            --success-green: #16a34a;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: var(--bg-color); color: var(--text-color); overflow: hidden; }
        .container { display: flex; flex-direction: column; width: 100vw; height: 100vh; }

        .header {
            text-align: center;
            padding: 15px;
            background: #fff;
            border-bottom: 1px solid var(--layer-line-color);
            z-index: 1000;
        }
        .header h1 { font-size: 1.5rem; color: var(--header-color); }
        .header p { color: #555; font-size: 0.9rem; }

        .main-content { display: flex; flex: 1; overflow: hidden; }

        .diagram-area { flex: 1; position: relative; padding: 20px; }
        .alert-area { width: 420px; background-color: #fff; border-left: 1px solid var(--layer-line-color); display: flex; flex-direction: column; }
        
        .alert-header { padding: 15px; font-weight: bold; font-size: 1.1rem; color: var(--header-color); border-bottom: 1px solid var(--layer-line-color); text-align: center; }
        .alert-panel { flex: 1; overflow-y: auto; padding: 15px; }

        .security-layer { position: absolute; width: 100%; border-bottom: 2px dashed var(--layer-line-color); }
        .layer-1 { top: 12%; } .layer-2 { top: 32%; } .layer-3 { top: 52%; }
        .layer-4 { top: 72%; } .layer-5 { top: 92%; }

        .layer-label {
            position: absolute; top: -18px; left: 20px; background: var(--label-bg);
            padding: 8px 15px; border-radius: 20px; font-weight: 600; font-size: 0.9rem; color: var(--label-border);
            border: 1px solid var(--label-border);
        }

        .component { position: absolute; display: flex; flex-direction: column; align-items: center; z-index: 10; transform-origin: center; }
        .component-icon {
            width: 50px; height: 50px; border-radius: 12px; display: flex; align-items: center; justify-content: center;
            font-size: 24px; background: #fff; border: 1px solid #ccc; box-shadow: 0 4px 12px rgba(0,0,0,0.1); position: relative;
        }
        .component-label { margin-top: 8px; font-size: 0.8rem; font-weight: 600; color: #444; text-align: center; }
        .status-indicator {
            position: absolute; top: -5px; right: -5px; width: 16px; height: 16px; border-radius: 50%;
            background: #2ecc71; border: 2px solid #fff; animation: pulse-ok 2s infinite;
        }
        .compromised { background: var(--attack-red) !important; animation: pulse-danger 1s infinite; }
        .detected { background: #0ea5e9 !important; animation: pulse-detected 1.2s infinite; }
        .contained { background: #9b59b6 !important; animation: pulse-contained 1.5s infinite; }

        /* Posiciones de los componentes en el diagrama */
        .attacker { top: 8%; left: 5%; }
        .perimeter-label-container { top: 8%; left: 20%; }
        .perimeter-label-container .component-label { font-weight: normal; font-size: 0.85rem; }
        .employee-pc { top: 28%; left: 30%; }
        .netskope-sse { top: 28%; left: 60%; }
        .entra-id { top: 48%; left: 45%; }
        .palo-alto-fw { top: 68%; left: 55%; }
        .critical-server { top: 68%; left: 80%; }
        
        .connection {
            position: absolute; height: 3px; background-image: linear-gradient(to right, var(--attack-red) 50%, transparent 50%);
            background-size: 16px 3px; transform-origin: left center; z-index: 1;
            opacity: 0; transition: opacity 0.5s ease;
        }
        .connection.active { opacity: 1; }
        
        .block-x {
            position: absolute; width: 24px; height: 24px; background-color: var(--attack-red);
            border-radius: 50%; display: flex; align-items: center; justify-content: center;
            box-shadow: 0 0 10px rgba(217, 45, 32, 0.7);
            opacity: 0; transform: scale(0.5); transition: all 0.3s ease-out; z-index: 20;
        }
        .block-x.show { opacity: 1; transform: scale(1); }
        .block-x::before, .block-x::after {
            content: ''; position: absolute; width: 14px; height: 2px; background-color: white;
        }
        .block-x::before { transform: rotate(45deg); }
        .block-x::after { transform: rotate(-45deg); }
        #email-block { top: 8%; left: 16%; }

        .alert { margin-bottom: 15px; border-radius: 8px; padding: 15px; opacity: 0; transform: translateY(20px); animation: fadeIn 0.5s forwards; }
        .alert-info { background: var(--alert-info-bg); border-left: 4px solid var(--alert-info-border); }
        .alert-warning { background: var(--alert-warning-bg); border-left: 4px solid var(--alert-warning-border); }
        .alert-critical { background: var(--alert-critical-bg); border-left: 4px solid var(--alert-critical-border); }
        .alert-title { font-weight: bold; margin-bottom: 5px; display: flex; align-items: center; font-size: 0.9rem; }
        .alert-info .alert-title { color: var(--alert-info-border); }
        .alert-warning .alert-title { color: var(--alert-warning-border); }
        .alert-critical .alert-title { color: var(--alert-critical-border); }
        .alert-time { font-size: 0.75rem; color: #777; margin-bottom: 8px; }
        .alert-details { font-size: 0.85rem; color: #555; line-height: 1.5; }

        .impact-container { position: absolute; bottom: 10%; left: 55%; transform: translateX(-50%); display: flex; flex-direction: column; align-items: center; }
        .impact-panel {
            background: var(--impact-bg); color: white; padding: 15px 30px; border-radius: 15px; text-align: center; opacity: 0;
            transition: all 0.5s ease; border: 2px solid var(--success-green); width: 100%; max-width: 600px;
            position: relative;
        }
        .impact-container.show .impact-panel { opacity: 1; }
        .impact-title { font-size: 1.1rem; font-weight: bold; color: var(--success-green); margin-bottom: 10px; }
        .impact-stats { display: flex; justify-content: space-around; }
        .impact-stat { text-align: center; }
        .impact-number { font-size: 1.6rem; font-weight: bold; color: #fff; }
        .impact-label { font-size: 0.8rem; color: #bdc3c7; }
        .final-result { position: absolute; bottom: 8px; left: 50%; transform: translateX(-50%); width: 100%; font-weight: bold; font-size: 0.8rem; }
        .siem-sublabel { font-size: 0.8rem; color: #555; margin-top: 8px; opacity: 0; transition: opacity 0.5s 0.3s ease; }
        .impact-container.show .siem-sublabel { opacity: 1; }

        @keyframes fadeIn { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes pulse-ok { 0%, 100% { transform: scale(1); } 50% { transform: scale(1.1); } }
        @keyframes pulse-danger { 0%, 100% { box-shadow: 0 0 0 0 rgba(217, 45, 32, 0.7); } 70% { box-shadow: 0 0 0 10px rgba(217, 45, 32, 0); } }
        @keyframes pulse-detected { 0%, 100% { box-shadow: 0 0 0 0 rgba(14, 165, 233, 0.7); } 70% { box-shadow: 0 0 0 10px rgba(14, 165, 233, 0); } }
        @keyframes pulse-contained { 0%, 100% { box-shadow: 0 0 0 0 rgba(155, 89, 182, 0.7); } 70% { box-shadow: 0 0 0 10px rgba(155, 89, 182, 0); } }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Solución de Seguridad "Best-of-Breed" para BCP</h1>
            <p>Simulación de Defensa Integrada con Microsoft, CrowdStrike, Netskope y Palo Alto Networks</p>
        </div>
        <main class="main-content">
            <div class="diagram-area" id="diagram-area">
                <!-- Capas -->
                <div class="security-layer layer-1"><div class="layer-label">Capa 1: Perímetro y Email</div></div>
                <div class="security-layer layer-2"><div class="layer-label">Capa 2: Endpoint y Web</div></div>
                <div class="security-layer layer-3"><div class="layer-label">Capa 3: Identidad (Zero Trust)</div></div>
                <div class="security-layer layer-4"><div class="layer-label">Capa 4: Red Interna</div></div>
                <div class="security-layer layer-5"><div class="layer-label">Capa 5: Correlación y Respuesta (XDR)</div></div>

                <!-- Componentes -->
                <div class="component attacker"><div class="component-icon">🏴‍☠️<div class="status-indicator compromised"></div></div><div class="component-label">Atacante</div></div>
                <div class="component perimeter-label-container"><div class="component-label">Perímetro y Email</div></div>
                <div class="component employee-pc"><div class="component-icon">🦅<div class="status-indicator" id="status-crowdstrike"></div></div><div class="component-label">PC Empleado<br>(CrowdStrike Falcon)</div></div>
                <div class="component netskope-sse"><div class="component-icon">🌐<div class="status-indicator" id="status-netskope"></div></div><div class="component-label">Netskope SSE</div></div>
                <div class="component entra-id"><div class="component-icon">🔑<div class="status-indicator" id="status-entra"></div></div><div class="component-label">Microsoft Entra ID</div></div>
                <div class="component palo-alto-fw"><div class="component-icon">🧱<div class="status-indicator" id="status-paloalto"></div></div><div class="component-label">Palo Alto Networks NGFW</div></div>
                <div class="component critical-server"><div class="component-icon">🏦<div class="status-indicator" id="status-server"></div></div><div class="component-label">Servidor Crítico</div></div>
                
                <!-- Símbolo de bloqueo -->
                <div class="block-x" id="email-block"></div>

                <!-- Conexiones -->
                <div class="connection" id="conn1"></div>
                <div class="connection" id="conn2"></div>
                <div class="connection" id="conn3"></div>
                <div class="connection" id="conn4"></div>

                <!-- Panel de Impacto Final -->
                <div class="impact-container" id="impact-container">
                    <div class="impact-panel">
                        <div class="impact-title">✅ ATAQUE COMPLETAMENTE NEUTRALIZADO</div>
                        <div class="impact-stats">
                            <div class="impact-stat"><div class="impact-number">0</div><div class="impact-label">Sistemas Comprometidos</div></div>
                            <div class="impact-stat"><div class="impact-number">$0</div><div class="impact-label">Pérdidas Financieras</div></div>
                            <div class="impact-stat"><div class="impact-number">&lt; 1 min</div><div class="impact-label">Tiempo de Contención</div></div>
                            <div class="impact-stat"><div class="impact-number">100%</div><div class="impact-label">Visibilidad del Incidente</div></div>
                        </div>
                        <div class="final-result">RESULTADO: El ataque es contenido en múltiples capas. Incidente neutralizado.</div>
                    </div>
                    <div class="siem-sublabel">(SIEM/XDR)</div>
                </div>
            </div>
            <div class="alert-area">
                <div class="alert-header">ETAPAS DEL INCIDENTE</div>
                <div class="alert-panel" id="alert-panel"></div>
            </div>
        </main>
    </div>

    <script>
        const alertsData = [
            { time: "T+00:00:02", title: "MS Defender: AMENAZA BLOQUEADA", details: "Email de 'soporte-urgente' bloqueado. La tecnología Safe Links identificó el enlace como malicioso y previno la entrega.", severity: "info" },
            { time: "T+00:00:06", title: "Netskope: ACCESO DENEGADO", details: "El PC del empleado intentó acceder a 'bancoxyz-seguridad.com'. URL clasificada como Phishing y bloqueada por política de SWG.", severity: "warning" },
            { time: "T+00:00:11", title: "CrowdStrike: AMENAZA CRÍTICA DETECTADA", details: "Se ha detectado y bloqueado un comportamiento malicioso (T1059.001) en el host del empleado. El host ha sido aislado de la red por prevención.", severity: "critical" },
            { time: "T+00:00:16", title: "Entra ID: INICIO DE SESIÓN RIESGOSO", details: "Intento de acceso al Servidor Crítico desde una sesión de riesgo. Acceso bloqueado por política de Acceso Condicional que requiere MFA.", severity: "critical" },
            { time: "T+00:00:20", title: "ETAPA CREADO", details: "Se correlacionaron 4 alertas de Defender, Netskope, CrowdStrike y Entra ID. Se ha abierto el Incidente IR-2024-101 y se ha ejecutado el playbook de respuesta automática.", severity: "critical" }
        ];

        function showAlert(alertData, delay) {
            setTimeout(() => {
                const panel = document.getElementById('alert-panel');
                const alertDiv = document.createElement('div');
                const severityClass = { 'info': 'alert-info', 'warning': 'alert-warning', 'critical': 'alert-critical' }[alertData.severity];
                const icon = {'info': 'ℹ️', 'warning': '⚠️', 'critical': '🚨'}[alertData.severity];
                alertDiv.className = `alert ${severityClass}`;
                alertDiv.innerHTML = `<div class="alert-title">${icon} ${alertData.title}</div><div class="alert-time">${alertData.time}</div><div class="alert-details">${alertData.details}</div>`;
                panel.prepend(alertDiv);
            }, delay);
        }

        function updateStatus(id, status, delay) {
            setTimeout(() => {
                const indicator = document.getElementById(`status-${id}`);
                if (indicator) {
                    indicator.className = 'status-indicator';
                    if (status) indicator.classList.add(status);
                }
            }, delay);
        }

        function drawConnection(id, fromSelector, toSelector) {
            const conn = document.getElementById(id);
            const fromEl = document.querySelector(fromSelector);
            const toEl = document.querySelector(toSelector);
            const diagramArea = document.getElementById('diagram-area');
            if (!conn || !fromEl || !toEl || !diagramArea) return;

            const diagramRect = diagramArea.getBoundingClientRect();
            const fromRect = fromEl.getBoundingClientRect();
            const toRect = toEl.getBoundingClientRect();

            const x1 = fromRect.left - diagramRect.left + fromRect.width / 2;
            const y1 = fromRect.top - diagramRect.top + fromRect.height / 2;
            const x2 = toRect.left - diagramRect.left + toRect.width / 2;
            const y2 = toRect.top - diagramRect.top + toRect.height / 2;

            const length = Math.sqrt((x2 - x1) ** 2 + (y2 - y1) ** 2);
            const angle = Math.atan2(y2 - y1, x2 - x1) * (180 / Math.PI);

            conn.style.width = `${length}px`;
            conn.style.left = `${x1}px`;
            conn.style.top = `${y1}px`;
            conn.style.transform = `rotate(${angle}deg)`;
        }

        function activateElement(selector, className, delay) {
            setTimeout(() => {
                const el = document.querySelector(selector);
                if (el) el.classList.add(className);
            }, delay);
        }

        function startSimulation() {
            // Reset UI
            document.getElementById('alert-panel').innerHTML = '';
            document.querySelector('.impact-container').classList.remove('show');
            document.getElementById('email-block').classList.remove('show');
            ['crowdstrike', 'netskope', 'entra', 'paloalto', 'server'].forEach(id => updateStatus(id, '', 0));
            ['conn1', 'conn2', 'conn3', 'conn4'].forEach(id => document.getElementById(id).classList.remove('active'));

            // Draw all connections
            drawConnection('conn1', '.attacker', '.perimeter-label-container');
            drawConnection('conn2', '.employee-pc', '.netskope-sse');
            drawConnection('conn3', '.employee-pc', '.entra-id');
            drawConnection('conn4', '.entra-id', '.critical-server');

            // --- SIMULATION SEQUENCE ---
            // 1. Attack starts
            activateElement('#conn1', 'active', 1000);
            
            // 2. Email Blocked
            showAlert(alertsData[0], 2000);
            activateElement('#email-block', 'show', 2000);

            // 3. Web Access Blocked (Simulated)
            activateElement('#conn2', 'active', 3500);
            showAlert(alertsData[1], 4500);
            updateStatus('netskope', 'detected', 4500);

            // 4. Endpoint Threat Contained (Simulated)
            showAlert(alertsData[2], 6000);
            updateStatus('crowdstrike', 'contained', 6000);
            
            // 5. Risky Sign-in Blocked (Simulated)
            activateElement('#conn3', 'active', 7500);
            activateElement('#conn4', 'active', 7500);
            showAlert(alertsData[3], 8500);
            updateStatus('entra', 'detected', 8500);

            // 6. Incident Correlated in SIEM
            showAlert(alertsData[4], 10000);
            
            // 7. Show Final Impact Panel
            activateElement('.impact-container', 'show', 11000);
        }

        window.addEventListener('load', startSimulation);
        window.addEventListener('resize', () => {
             drawConnection('conn1', '.attacker', '.perimeter-label-container');
             drawConnection('conn2', '.employee-pc', '.netskope-sse');
             drawConnection('conn3', '.employee-pc', '.entra-id');
             drawConnection('conn4', '.entra-id', '.critical-server');
        });
    </script>
</body>
</html>