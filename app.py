from flask import Flask, render_template_string, redirect, url_for, request, send_from_directory
from threading import Thread
from scapy.all import sniff, IP, TCP, UDP, Raw
from scapy.sessions import TCPSession
from datetime import datetime
import queue
import csv
import os
import re
import magic  # Necesitarás instalar python-magic: pip install python-magic
import hashlib
import threading

app = Flask(__name__)

# Variables globales
capturando = False
detener_sniffer = False
ip_monitoreada = None
paquetes_capturados = queue.Queue()
flujos_tcp = {}
archivos_capturados = []
carpeta_archivos = "archivos_capturados"

# Variables globales adicionales para análisis de archivos
archivos_temporales = {}  # Almacenará contenido binario para análisis
archivo_actual_analisis = None  # Para la vista de análisis detallado
MAX_ARCHIVOS_TEMPORALES = 20  # Límite para evitar consumo excesivo de memoria

# Asegurar que exista la carpeta para guardar archivos
os.makedirs(carpeta_archivos, exist_ok=True)

# HTML - Página de inicio
html_inicio = """
<!doctype html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>NetCapture - Sniffer de Red</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        :root {
            --primary: #2c3e50;
            --secondary: #e74c3c;
            --accent: #3498db;
            --light: #ecf0f1;
            --dark: #121212;
            --success: #27ae60;
        }
        
        body {
            background-color: var(--light);
            color: var(--dark);
            font-family: 'Poppins', sans-serif;
            min-height: 100vh;
            background-image: 
                radial-gradient(circle at 25% 10%, rgba(52, 152, 219, 0.1), transparent 400px),
                radial-gradient(circle at 75% 75%, rgba(231, 76, 60, 0.1), transparent 400px);
        }
        
        .main-container {
            max-width: 1000px;
            margin: 0 auto;
            padding-top: 40px;
        }
        
        .header {
            text-align: center;
            margin-bottom: 50px;
        }
        
        .header h1 {
            font-weight: 800;
            color: var(--primary);
            font-size: 3rem;
            margin-bottom: 10px;
            position: relative;
            display: inline-block;
        }
        
        .header h1::after {
            content: '';
            position: absolute;
            bottom: -10px;
            left: 50%;
            transform: translateX(-50%);
            width: 80px;
            height: 4px;
            background: var(--secondary);
            border-radius: 2px;
        }
        
        .header p {
            color: #555;
            font-size: 1.2rem;
            max-width: 600px;
            margin: 20px auto;
        }
        
        .card-container {
            background-color: white;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.08);
            overflow: hidden;
            transition: transform 0.3s, box-shadow 0.3s;
        }
        
        .card-container:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.12);
        }
        
        .card-header {
            background-color: var(--primary);
            color: white;
            padding: 25px;
            text-align: center;
        }
        
        .card-header .icon {
            font-size: 4rem;
            margin-bottom: 15px;
            color: var(--light);
            text-shadow: 0 2px 10px rgba(0, 0, 0, 0.2);
        }
        
        .card-body {
            padding: 30px;
        }
        
        .btn-action {
            background-color: var(--primary);
            color: white;
            border: none;
            border-radius: 30px;
            padding: 12px 30px;
            font-weight: 600;
            letter-spacing: 0.5px;
            transition: all 0.3s;
            position: relative;
            overflow: hidden;
            z-index: 1;
        }
        
        .btn-action::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), transparent);
            transition: all 0.6s;
            z-index: -1;
        }
        
        .btn-action:hover {
            background-color: var(--secondary);
            color: white;
            box-shadow: 0 5px 15px rgba(231, 76, 60, 0.4);
        }
        
        .btn-action:hover::before {
            left: 100%;
        }
        
        .input-ip {
            border: 2px solid #ddd;
            border-radius: 8px;
            padding: 12px 15px;
            font-size: 1rem;
            transition: all 0.3s;
        }
        
        .input-ip:focus {
            border-color: var(--accent);
            box-shadow: 0 0 0 3px rgba(52, 152, 219, 0.2);
        }
        
        .monitor-status {
            display: inline-flex;
            align-items: center;
            background-color: rgba(39, 174, 96, 0.1);
            padding: 8px 16px;
            border-radius: 20px;
            margin-bottom: 20px;
        }
        
        .status-dot {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 8px;
        }
        
        .status-active {
            background-color: var(--success);
            box-shadow: 0 0 0 4px rgba(39, 174, 96, 0.2);
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0% { box-shadow: 0 0 0 0 rgba(39, 174, 96, 0.6); }
            70% { box-shadow: 0 0 0 10px rgba(39, 174, 96, 0); }
            100% { box-shadow: 0 0 0 0 rgba(39, 174, 96, 0); }
        }
        
        .option-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
            margin-top: 30px;
        }
        
        .option-card {
            background-color: white;
            border-radius: 12px;
            padding: 30px;
            text-align: center;
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.06);
            transition: all 0.3s;
        }
        
        .option-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 12px 25px rgba(0, 0, 0, 0.1);
        }
        
        .option-icon {
            font-size: 3rem;
            margin-bottom: 20px;
            color: var(--accent);
        }
        
        .option-title {
            font-size: 1.4rem;
            font-weight: 700;
            margin-bottom: 15px;
            color: var(--primary);
        }
        
        .option-desc {
            color: #666;
            margin-bottom: 20px;
            font-size: 0.95rem;
        }
        
        @media (max-width: 768px) {
            .option-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="main-container">
        <div class="header">
            <h1><i class="fas fa-network-wired me-2"></i>NetCapture</h1>
            <p>Monitor avanzado de tráfico de red con análisis en tiempo real</p>
        </div>
        
        <div class="card-container">
            {% if not capturando %}
            <div class="card-body">
                <div class="option-grid">
                    <div class="option-card">
                        <div class="option-icon">
                            <i class="fas fa-globe"></i>
                        </div>
                        <h3 class="option-title">Monitoreo completo</h3>
                        <p class="option-desc">Captura todo el tráfico de red que pasa por tu interfaz</p>
                        <form action="/iniciar" method="get">
                            <button type="submit" class="btn btn-action w-100">
                                <i class="fas fa-play me-2"></i>Iniciar monitoreo
                            </button>
                        </form>
                    </div>
                    
                    <div class="option-card">
                        <div class="option-icon">
                            <i class="fas fa-crosshairs"></i>
                        </div>
                        <h3 class="option-title">Monitoreo específico</h3>
                        <p class="option-desc">Observa solo el tráfico relacionado con una IP particular</p>
                        <form action="/iniciar" method="get">
                            <div class="mb-3">
                                <input type="text" class="form-control input-ip" name="ip" 
                                       placeholder="Ejemplo: 192.168.1.100" 
                                       pattern="^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$">
                            </div>
                            <button type="submit" class="btn btn-action w-100">
                                <i class="fas fa-search me-2"></i>Monitorear IP
                            </button>
                        </form>
                    </div>
                </div>
            </div>
            {% else %}
            <div class="card-body text-center">
                <div class="monitor-status">
                    <span class="status-dot status-active"></span>
                    <span class="fw-bold">Monitoreo activo</span>
                </div>
                <p class="mb-4">Hay una sesión activa de captura de paquetes en curso.</p>
                <a href="/sniffer" class="btn btn-action">
                    <i class="fas fa-chart-line me-2"></i>Ver análisis en tiempo real
                </a>
            </div>
            {% endif %}
        </div>
    </div>
</body>
</html>
"""

# HTML - Vista de paquetes
html_sniffer = """
<!doctype html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>NetCapture - Análisis en tiempo real</title>
    {% if capturando %}
        <meta http-equiv="refresh" content="5">
    {% endif %}
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        :root {
            --primary: #2c3e50;
            --secondary: #e74c3c;
            --accent: #3498db;
            --light: #ecf0f1;
            --dark: #121212;
            --success: #27ae60;
            --warning: #f39c12;
            --danger: #c0392b;
            --info: #16a085;
        }
        
        body {
            background-color: #f5f7fa;
            color: var(--dark);
            font-family: 'Inter', sans-serif;
        }
        
        .navbar {
            background-color: white;
            box-shadow: 0 2px 15px rgba(0, 0, 0, 0.05);
            padding: 15px 0;
        }
        
        .navbar-brand {
            font-weight: 800;
            color: var(--primary);
            display: flex;
            align-items: center;
        }
        
        .navbar-brand i {
            color: var(--accent);
            margin-right: 8px;
        }
        
        .btn-control {
            border-radius: 8px;
            padding: 8px 16px;
            font-weight: 600;
            transition: all 0.3s;
        }
        
        .btn-stop {
            background-color: var(--danger);
            color: white;
            border: none;
        }
        
        .btn-stop:hover {
            background-color: #a93226;
            color: white;
            box-shadow: 0 4px 12px rgba(192, 57, 43, 0.3);
        }
        
        .btn-restart {
            background-color: var(--accent);
            color: white;
            border: none.
        }
        
        .btn-restart:hover {
            background-color: #2980b9;
            color: white;
            box-shadow: 0 4px 12px rgba(52, 152, 219, 0.3);
        }
        
        .btn-home {
            background-color: var(--light);
            color: var(--dark);
            border: none;
        }
        
        .btn-home:hover {
            background-color: #d6dbdf;
            color: var(--dark);
        }
        
        .dashboard {
            padding: 30px 0;
        }
        
        .status-indicator {
            display: inline-flex;
            align-items: center;
            margin-right: 15px;
        }
        
        .status-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            margin-right: 6px;
        }
        
        .status-active {
            background-color: var(--success);
            box-shadow: 0 0 0 3px rgba(39, 174, 96, 0.2);
            animation: pulse 2s infinite;
        }
        
        .status-inactive {
            background-color: var(--danger);
        }
        
        @keyframes pulse {
            0% { box-shadow: 0 0 0 0 rgba(39, 174, 96, 0.6); }
            70% { box-shadow: 0 0 0 6px rgba(39, 174, 96, 0); }
            100% { box-shadow: 0 0 0 0 rgba(39, 174, 96, 0); }
        }
        
        .stats-container {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background-color: white;
            border-radius: 12px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.05);
            padding: 20px;
            display: flex;
            flex-direction: column;
        }
        
        .stat-title {
            color: #888;
            font-size: 0.9rem;
            margin-bottom: 8px;
        }
        
        .stat-value {
            font-size: 2rem;
            font-weight: 700;
            color: var(--primary);
            margin-bottom: 0;
        }
        
        .data-table {
            background-color: white;
            border-radius: 12px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.05);
            overflow: hidden;
        }
        
        .table {
            margin-bottom: 0;
        }
        
        .table thead {
            background-color: var(--primary);
            color: white;
        }
        
        .table thead th {
            padding: 15px;
            font-weight: 600;
            border-bottom: none;
        }
        
        .table tbody tr {
            transition: background-color 0.2s;
        }
        
        .table tbody tr:hover {
            background-color: rgba(52, 152, 219, 0.05);
        }
        
        .table tbody td {
            padding: 15px;
            vertical-align: middle;
            border-top: 1px solid #eee;
        }
        
        .ip-address {
            font-family: 'Roboto Mono', monospace;
            color: var(--primary);
            font-weight: 500;
        }
        
        .protocol-badge {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 30px;
            font-size: 0.75rem;
            font-weight: 700;
            color: white;
            text-transform: uppercase;
        }
        
        .badge-http { background-color: var(--accent); }
        .badge-https { background-color: var(--success); }
        .badge-tcp { background-color: var(--info); }
        .badge-udp { background-color: var(--warning); }
        .badge-icmp { background-color: var(--secondary); }
        .badge-other { background-color: #777; }
        
        .content-preview {
            background-color: #f8f9fa;
            border-radius: 6px;
            padding: 10px;
            font-family: 'Roboto Mono', monospace;
            font-size: 0.8rem;
            color: #555;
            max-height: 80px;
            overflow-y: auto;
        }
        
        .ip-filter-badge {
            display: inline-flex;
            align-items: center;
            background-color: rgba(52, 152, 219, 0.1);
            color: var(--accent);
            padding: 8px 15px;
            border-radius: 30px;
            font-weight: 600;
            font-size: 0.9rem;
            margin-bottom: 20px;
        }
        
        .ip-filter-badge i {
            margin-right: 6px;
            color: var(--accent);
        }
        
        .loading-container {
            text-align: center;
            padding: 30px 0;
        }
        
        .loading-spinner {
            width: 40px;
            height: 40px;
            border: 3px solid rgba(52, 152, 219, 0.2);
            border-top-color: var(--accent);
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 0 auto 15px;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        @media (max-width: 992px) {
            .stats-container {
                grid-template-columns: repeat(2, 1fr);
            }
        }
        
        @media (max-width: 576px) {
            .stats-container {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <nav class="navbar">
        <div class="container">
            <a class="navbar-brand" href="/">
                <i class="fas fa-network-wired"></i>NetCapture
            </a>
            <div class="d-flex align-items-center">
                <div class="status-indicator">
                    <span class="status-dot {% if capturando %}status-active{% else %}status-inactive{% endif %}"></span>
                    <span class="fw-semibold">{% if capturando %}Activo{% else %}Inactivo{% endif %}</span>
                </div>
                
                {% if capturando %}
                    <a href="/detener" class="btn btn-control btn-stop me-2">
                        <i class="fas fa-stop me-1"></i> Detener
                    </a>
                {% else %}
                    <a href="/iniciar" class="btn btn-control btn-restart me-2">
                        <i class="fas fa-play me-1"></i> Reiniciar
                    </a>
                {% endif %}
                
                <a href="/" class="btn btn-control btn-home">
                    <i class="fas fa-home me-1"></i> Inicio
                </a>
            </div>
        </div>
    </nav>
    
    <div class="dashboard">
        <div class="container">
            {% if ip_monitoreada %}
            <div class="ip-filter-badge">
                <i class="fas fa-filter"></i> Filtrando por IP: <span class="ip-address ms-2">{{ ip_monitoreada }}</span>
                <a href="/iniciar" class="btn btn-sm btn-light ms-3">
                    Ver todo el tráfico
                </a>
            </div>
            {% endif %}
            
            <div class="stats-container">
                <div class="stat-card">
                    <div class="stat-title">Paquetes capturados</div>
                    <h2 class="stat-value">{{ paquetes|length }}</h2>
                </div>
                <div class="stat-card">
                    <div class="stat-title">Orígenes únicos</div>
                    <h2 class="stat-value">{{ origenes_unicos }}</h2>
                </div>
                <div class="stat-card">
                    <div class="stat-title">Destinos únicos</div>
                    <h2 class="stat-value">{{ destinos_unicos }}</h2>
                </div>
                <div class="stat-card">
                    <div class="stat-title">Actualización</div>
                    <h2 class="stat-value">{{ ultima_actualizacion }}</h2>
                </div>
            </div>
            
            <div class="data-table">
                <table class="table">
                    <thead>
                        <tr>
                            <th><i class="far fa-clock me-1"></i> Tiempo</th>
                            <th><i class="fas fa-upload me-1"></i> Origen</th>
                            <th><i class="fas fa-download me-1"></i> Destino</th>
                            <th><i class="fas fa-tags me-1"></i> Protocolo</th>
                            <th><i class="fas fa-database me-1"></i> Tamaño</th>
                            <th><i class="fas fa-file-alt me-1"></i> Contenido</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for paquete in paquetes %}
                        <tr>
                            <td>{{ paquete.hora }}</td>
                            <td><span class="ip-address">{{ paquete.origen }}</span></td>
                            <td><span class="ip-address">{{ paquete.destino }}</span></td>
                            <td>
                                <span class="protocol-badge badge-{{ paquete.protocolo|lower }}">
                                    {{ paquete.protocolo }}
                                </span>
                            </td>
                            <td>{{ paquete.tamano }} bytes</td>
                            <td>
                                {% if paquete.contenido %}
                                    <div class="content-preview">{{ paquete.contenido[:150] }}{% if paquete.contenido|length > 150 %}...{% endif %}</div>
                                {% else %}
                                    <span class="text-muted">Sin contenido</span>
                                {% endif %}
                            </td>
                        </tr>
                        {% else %}
                        <tr>
                            <td colspan="6" class="text-center py-5">
                                <i class="fas fa-radar fs-2 mb-3 text-muted"></i>
                                <div>No se han capturado paquetes todavía</div>
                                <div class="text-muted small mt-1">Espere a que comience la captura de tráfico</div>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            
            {% if capturando %}
            <div class="loading-container">
                <div class="loading-spinner"></div>
                <div class="text-muted">Capturando tráfico en tiempo real...</div>
                <div class="mt-2">
                    <a href="/archivos" class="btn btn-sm btn-outline-primary">
                        <i class="fas fa-file me-1"></i> Ver archivos capturados
                    </a>
                </div>
            </div>
            {% endif %}
        </div>
    </div>
</body>
</html>
"""

# HTML - Vista de análisis de archivos
html_analisis = """
<!doctype html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>NetCapture - Análisis de Archivo</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        :root {
            --primary: #2c3e50;
            --secondary: #e74c3c;
            --accent: #3498db;
            --light: #ecf0f1;
            --dark: #121212;
            --success: #27ae60;
            --warning: #f39c12;
            --danger: #c0392b;
            --info: #16a085;
        }
        
        body {
            background-color: #f5f7fa;
            color: var(--dark);
            font-family: 'Inter', sans-serif;
        }
        
        .navbar {
            background-color: white;
            box-shadow: 0 2px 15px rgba(0, 0, 0, 0.05);
            padding: 15px 0;
        }
        
        .navbar-brand {
            font-weight: 800;
            color: var(--primary);
            display: flex;
            align-items: center;
        }
        
        .navbar-brand i {
            color: var(--accent);
            margin-right: 8px;
        }
        
        .btn-control {
            border-radius: 8px;
            padding: 8px 16px;
            font-weight: 600;
            transition: all 0.3s;
        }
        
        .dashboard {
            padding: 30px 0;
        }
        
        .analysis-header {
            background-color: white;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 30px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.05);
        }
        
        .file-meta-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }
        
        .file-meta-item {
            background-color: #f8f9fa;
            padding: 10px 15px;
            border-radius: 8px;
        }
        
        .file-meta-label {
            font-size: 0.8rem;
            color: #666;
            margin-bottom: 5px;
        }
        
        .file-meta-value {
            font-weight: 600;
            color: var(--primary);
            font-family: 'Roboto Mono', monospace;
            word-break: break-all;
        }
        
        .analysis-section {
            background-color: white;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.05);
        }
        
        .section-title {
            display: flex;
            align-items: center;
            margin-bottom: 15px;
            color: var(--primary);
            font-weight: 700;
        }
        
        .section-title i {
            margin-right: 10px;
            color: var(--accent);
        }
        
        .hex-view {
            font-family: 'Roboto Mono', monospace;
            font-size: 0.9rem;
            background-color: #f8f9fa;
            border-radius: 8px;
            padding: 15px;
            white-space: pre-wrap;
            word-break: break-all;
            max-height: 300px;
            overflow-y: auto;
        }
        
        .text-view {
            font-family: 'Roboto Mono', monospace;
            font-size: 0.9rem;
            background-color: #f8f9fa;
            border-radius: 8px;
            padding: 15px;
            white-space: pre-wrap;
            word-break: break-all;
            max-height: 300px;
            overflow-y: auto;
        }
        
        .hex-byte {
            display: inline-block;
            width: 25px;
            margin-right: 5px;
            color: #555;
        }
        
        .hex-offset {
            color: var(--accent);
            margin-right: 10px;
            font-weight: 700;
        }
        
        .signature-match {
            background-color: rgba(39, 174, 96, 0.2);
            border-radius: 4px;
            padding: 2px;
        }
        
        .format-badge {
            display: inline-block;
            background-color: var(--info);
            color: white;
            font-size: 0.8rem;
            padding: 5px 10px;
            border-radius: 30px;
            margin-left: 10px;
        }
    </style>
</head>
<body>
    <nav class="navbar">
        <div class="container">
            <a class="navbar-brand" href="/">
                <i class="fas fa-network-wired"></i>NetCapture
            </a>
            <div class="d-flex align-items-center gap-2">
                <a href="/" class="btn btn-sm btn-outline-secondary">
                    <i class="fas fa-home me-1"></i> Inicio
                </a>
                <a href="/sniffer" class="btn btn-sm btn-outline-primary">
                    <i class="fas fa-chart-line me-1"></i> Tráfico
                </a>
                <a href="/archivos" class="btn btn-sm btn-outline-success">
                    <i class="fas fa-file me-1"></i> Archivos
                </a>
            </div>
        </div>
    </nav>
    
    <div class="dashboard">
        <div class="container">
            <div class="analysis-header">
                <div class="d-flex justify-content-between align-items-start">
                    <div>
                        <h2>Análisis de Archivo</h2>
                        <h4>{{ archivo.nombre }} <span class="format-badge">{{ analisis.formato_detectado }}</span></h4>
                    </div>
                    <div>
                        <a href="/archivos/{{ archivo.nombre }}" download class="btn btn-success">
                            <i class="fas fa-download me-1"></i> Descargar archivo
                        </a>
                        <a href="/archivos" class="btn btn-outline-secondary ms-2">
                            <i class="fas fa-arrow-left me-1"></i> Volver
                        </a>
                    </div>
                </div>
                
                <div class="file-meta-grid">
                    <div class="file-meta-item">
                        <div class="file-meta-label">Tipo MIME</div>
                        <div class="file-meta-value">{{ archivo.tipo }}</div>
                    </div>
                    <div class="file-meta-item">
                        <div class="file-meta-label">Tamaño</div>
                        <div class="file-meta-value">{{ archivo.tamaño }} bytes</div>
                    </div>
                    <div class="file-meta-item">
                        <div class="file-meta-label">Hash MD5</div>
                        <div class="file-meta-value">{{ archivo.hash }}</div>
                    </div>
                    <div class="file-meta-item">
                        <div class="file-meta-label">Capturado</div>
                        <div class="file-meta-value">{{ archivo.timestamp }}</div>
                    </div>
                    {% if archivo.metadatos.dimensiones %}
                    <div class="file-meta-item">
                        <div class="file-meta-label">Dimensiones</div>
                        <div class="file-meta-value">{{ archivo.metadatos.dimensiones }}</div>
                    </div>
                    {% endif %}
                    {% if archivo.metadatos.version_pdf %}
                    <div class="file-meta-item">
                        <div class="file-meta-label">Versión PDF</div>
                        <div class="file-meta-value">{{ archivo.metadatos.version_pdf }}</div>
                    </div>
                    {% endif %}
                </div>
            </div>
            
            <div class="analysis-section">
                <div class="section-title">
                    <i class="fas fa-fingerprint"></i> Firma del archivo
                </div>
                <div class="hex-view">
                    <div><span class="hex-offset">0000:</span> {{ analisis.encabezado }}</div>
                </div>
                <div class="mt-3">
                    <strong>Interpretación:</strong> 
                    {% if analisis.formato_detectado != "Desconocido" %}
                    <span class="text-success">Se detectó un archivo de tipo {{ analisis.formato_detectado }}</span>
                    {% else %}
                    <span class="text-warning">Formato no reconocido</span>
                    {% endif %}
                </div>
            </div>
            
            <div class="analysis-section">
                <div class="section-title">
                    <i class="fas fa-code"></i> Vista hexadecimal
                </div>
                <div class="hex-view">
                {% set chars = datos_hex|batch(2)|list %}
                {% for i in range(0, chars|length, 16) %}
                    <div>
                        <span class="hex-offset">{{ '%04x' % (i) }}:</span>
                        {% for j in range(i, i+16) %}
                            {% if j < chars|length %}
                                <span class="hex-byte">{{ chars[j][0] }}{{ chars[j][1] }}</span>
                            {% endif %}
                        {% endfor %}
                    </div>
                {% endfor %}
                </div>
            </div>
            
            <div class="analysis-section">
                <div class="section-title">
                    <i class="fas fa-font"></i> Vista de texto
                </div>
                <div class="text-view">{{ analisis.vista_texto }}</div>
            </div>
            
        </div>
    </div>
</body>
</html>
"""
# Función mejorada para detectar y analizar archivos
def detectar_archivos(flujo_datos, flujo_id=None):
    if isinstance(flujo_datos, str):
        flujo_datos = flujo_datos.encode('utf-8', errors='ignore')
    
    mime = magic.Magic(mime=True)
    tipo_archivo = mime.from_buffer(flujo_datos[:4096])
    
    if tipo_archivo.startswith(('text/plain', 'text/html', 'application/x-empty')):
        return None
    
    tipos_archivos = {
        'image/jpeg': {'ext': '.jpg', 'firma': b'\xFF\xD8\xFF'},
        'image/png': {'ext': '.png', 'firma': b'\x89PNG\r\n\x1A\n'},
        'image/gif': {'ext': '.gif', 'firma': b'GIF8'},
        'application/pdf': {'ext': '.pdf', 'firma': b'%PDF'},
        'application/zip': {'ext': '.zip', 'firma': b'PK\x03\x04'},
        'application/x-rar': {'ext': '.rar', 'firma': b'Rar!\x1A\x07'},
        'application/msword': {'ext': '.doc', 'firma': b'\xD0\xCF\x11\xE0'},
        'application/vnd.openxmlformats-officedocument': {'ext': '.docx', 'firma': b'PK\x03\x04'},
    }
    
    for mime_tipo, info in tipos_archivos.items():
        if tipo_archivo.startswith(mime_tipo) or (flujo_datos.startswith(info['firma'])):
            # Generar identificadores únicos
            hash_md5 = hashlib.md5(flujo_datos).hexdigest()
            hash_corto = hash_md5[:12]
            extension = info['ext']
            nombre_archivo = f"{hash_corto}{extension}"
            ruta_completa = os.path.join(carpeta_archivos, nombre_archivo)
            
            # Extraer metadatos según el tipo de archivo
            metadatos = analizar_metadatos(flujo_datos, tipo_archivo)
            
            # Almacenar en memoria temporal para análisis posterior
            if len(archivos_temporales) >= MAX_ARCHIVOS_TEMPORALES:
                # Eliminar el archivo temporal más antiguo
                clave_antigua = next(iter(archivos_temporales))
                del archivos_temporales[clave_antigua]
                
            # Guardar una copia para análisis
            archivos_temporales[hash_md5] = {
                'datos': flujo_datos,
                'flujo_id': flujo_id,
                'tipo': tipo_archivo,
                'hora_captura': datetime.now()
            }
            
            # Guardar el archivo en disco
            with open(ruta_completa, 'wb') as f:
                f.write(flujo_datos)
            
            # Crear registro del archivo
            archivo_info = {
                'nombre': nombre_archivo,
                'tipo': tipo_archivo,
                'tamaño': len(flujo_datos),
                'ruta': ruta_completa,
                'hash': hash_md5,
                'hash_corto': hash_corto,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'metadatos': metadatos,
                'origen_flujo': flujo_id
            }
            
            return archivo_info
    
    return None

# Función para extraer metadatos según el tipo de archivo
def analizar_metadatos(datos, tipo):
    metadatos = {}
    
    try:
        # Análisis básico para todos los archivos
        metadatos['tamaño'] = len(datos)
        metadatos['primeros_bytes'] = datos[:20].hex()
        
        # Análisis específico por tipo
        if tipo.startswith('image/'):
            # Intentar extraer dimensiones de imágenes
            if tipo == 'image/jpeg' and datos[6:10] in (b'JFIF', b'Exif'):
                metadatos['formato'] = 'JPEG/JFIF'
                # Aquí se podría añadir más análisis específico de JPEG
            
            elif tipo == 'image/png' and datos.startswith(b'\x89PNG\r\n\x1A\n'):
                # Para PNG, las dimensiones están en bytes específicos
                if len(datos) > 24:
                    try:
                        ancho = int.from_bytes(datos[16:20], byteorder='big')
                        alto = int.from_bytes(datos[20:24], byteorder='big')
                        metadatos['dimensiones'] = f"{ancho}x{alto}"
                    except:
                        pass
        
        elif tipo == 'application/pdf' and datos.startswith(b'%PDF'):
            # Extraer versión de PDF
            try:
                version_linea = datos[:16].decode('ascii', errors='ignore')
                if '%PDF-' in version_linea:
                    metadatos['version_pdf'] = version_linea.split('%PDF-')[1][:3]
            except:
                pass
            
        elif tipo.startswith('application/') and b'PK\x03\x04' in datos[:10]:
            metadatos['formato'] = 'Archivo ZIP/Office'
            
    except Exception as e:
        metadatos['error_analisis'] = str(e)
    
    return metadatos

# Función para manejar cada paquete
def manejar_paquete(pkt, ip_monitoreada=None):
    if detener_sniffer:
        return False

    origen = "N/A"
    destino = "N/A"
    puerto_origen = "N/A"
    puerto_destino = "N/A"
    protocolo = "Ethernet"
    
    if pkt.haslayer("IP"):
        ip_layer = pkt["IP"]
        origen = ip_layer.src
        destino = ip_layer.dst
        
        if ip_monitoreada and (origen != ip_monitoreada and destino != ip_monitoreada):
            return
        
        if pkt.haslayer("TCP"):
            tcp_layer = pkt["TCP"]
            puerto_origen = tcp_layer.sport
            puerto_destino = tcp_layer.dport
            protocolo = "TCP"
            
            flujo_id = f"{min(origen, destino)}:{min(puerto_origen, puerto_destino)}-{max(origen, destino)}:{max(puerto_origen, puerto_destino)}"
            
            if flujo_id not in flujos_tcp:
                flujos_tcp[flujo_id] = {
                    'datos': b'',
                    'ultimo_acceso': datetime.now(),
                    'paquetes': 0
                }
                
            if pkt.haslayer("Raw"):
                flujos_tcp[flujo_id]['datos'] += pkt["Raw"].load
                flujos_tcp[flujo_id]['paquetes'] += 1
                flujos_tcp[flujo_id]['ultimo_acceso'] = datetime.now()
                
                if len(flujos_tcp[flujo_id]['datos']) > 8192 and flujos_tcp[flujo_id]['paquetes'] > 5:
                    archivo = detectar_archivos(flujos_tcp[flujo_id]['datos'], flujo_id)
                    if archivo:
                        archivos_capturados.append(archivo)
                        if len(archivos_capturados) > 50:
                            archivos_capturados.pop(0)
                        flujos_tcp[flujo_id]['datos'] = b''
            
            if puerto_destino in (80, 8080) or puerto_origen in (80, 8080):
                protocolo = "HTTP"
            elif puerto_destino == 443 or puerto_origen == 443:
                protocolo = "HTTPS"
                
    origen_completo = f"{origen}:{puerto_origen}" if puerto_origen != "N/A" else origen
    destino_completo = f"{destino}:{puerto_destino}" if puerto_destino != "N/A" else destino

    data = {
        "hora": datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "origen": origen_completo,
        "destino": destino_completo,
        "protocolo": protocolo,
        "tamano": len(pkt),
        "contenido": None
    }

    if pkt.haslayer("Raw"):
        try:
            contenido = pkt["Raw"].load.decode("utf-8", errors="ignore")
            data["contenido"] = contenido
        except:
            data["contenido"] = f"[Datos binarios: {len(pkt['Raw'].load)} bytes]"

    paquetes_capturados.put(data)
    if paquetes_capturados.qsize() > 100:
        paquetes_capturados.get()

# Limpieza periódica de flujos TCP antiguos
def limpiar_flujos_tcp():
    tiempo_actual = datetime.now()
    flujos_a_eliminar = []
    
    for flujo_id, info in flujos_tcp.items():
        if (tiempo_actual - info['ultimo_acceso']).total_seconds() > 300:
            flujos_a_eliminar.append(flujo_id)
    
    for flujo_id in flujos_a_eliminar:
        del flujos_tcp[flujo_id]
    
    threading.Timer(60, limpiar_flujos_tcp).start()

threading.Timer(60, limpiar_flujos_tcp).start()

# Hilo para captura
def capturar_paquetes(ip_monitoreada=None):
    global capturando, detener_sniffer
    
    filter_str = f"host {ip_monitoreada}" if ip_monitoreada else "ip or ip6"
    
    sniff(prn=lambda pkt: manejar_paquete(pkt, ip_monitoreada), 
          store=0, 
          iface="wlan0",  # Cambia "wlan0" por el nombre de tu interfaz (eth0 o similar)
          filter=filter_str,
          session=TCPSession)
    capturando = False

# Guardar log en CSV
def guardar_log():
    if paquetes_capturados.empty():
        return

    fecha = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    nombre_archivo = f"logs/log_{fecha}.csv"
    os.makedirs("logs", exist_ok=True)

    with open(nombre_archivo, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(
            f,
            quoting=csv.QUOTE_ALL,
            quotechar='"',
            escapechar='\\',
            doublequote=True
        )
        writer.writerow(["Hora", "Origen", "Destino", "Protocolo", "Tamaño", "Contenido"])

        for pkt in list(paquetes_capturados.queue):
            writer.writerow([
                pkt["hora"],
                pkt["origen"],
                pkt["destino"],
                pkt["protocolo"],
                pkt["tamano"],
                pkt["contenido"] or ""
            ])

    print(f"✅ Log guardado en {nombre_archivo}")

# Rutas Flask
@app.route("/")
def inicio():
    return render_template_string(html_inicio, capturando=capturando)

@app.route("/iniciar")
def iniciar():
    global capturando, detener_sniffer, ip_monitoreada
    
    ip_monitoreada = request.args.get('ip', None)
    
    if ip_monitoreada:
        ip_pattern = re.compile(r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
        if not ip_pattern.match(ip_monitoreada):
            ip_monitoreada = None
    
    if not capturando:
        capturando = True
        detener_sniffer = False
        hilo = Thread(target=capturar_paquetes, args=(ip_monitoreada,), daemon=True)
        hilo.start()
    return redirect(url_for("sniffer"))

@app.route("/detener")
def detener():
    global detener_sniffer, capturando
    detener_sniffer = True
    capturando = False
    guardar_log()
    return redirect(url_for("sniffer"))

@app.route("/sniffer")
def sniffer():
    paquetes = list(paquetes_capturados.queue)[-100:]
    
    origenes = set(p["origen"] for p in paquetes if p["origen"] != "N/A")
    destinos = set(p["destino"] for p in paquetes if p["destino"] != "N/A")
    
    paquetes_ordenados = list(reversed(paquetes))
    
    return render_template_string(
        html_sniffer, 
        paquetes=paquetes_ordenados,
        capturando=capturando,
        origenes_unicos=len(origenes),
        destinos_unicos=len(destinos),
        ultima_actualizacion=datetime.now().strftime("%H:%M:%S"),
        ip_monitoreada=ip_monitoreada
    )

@app.route("/archivos")
def ver_archivos():
    # Definición local de la plantilla HTML
    html_archivos_template = """
<!doctype html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>NetCapture - Archivos Capturados</title>
    {% if capturando %}
        <meta http-equiv="refresh" content="10">
    {% endif %}
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        :root {
            --primary: #2c3e50;
            --secondary: #e74c3c;
            --accent: #3498db;
            --light: #ecf0f1;
            --dark: #121212;
            --success: #27ae60;
            --warning: #f39c12;
            --danger: #c0392b;
            --info: #16a085;
        }
        
        body {
            background-color: #f5f7fa;
            color: var(--dark);
            font-family: 'Inter', sans-serif;
        }
        
        .navbar {
            background-color: white;
            box-shadow: 0 2px 15px rgba(0, 0, 0, 0.05);
            padding: 15px 0;
        }
        
        .navbar-brand {
            font-weight: 800;
            color: var(--primary);
            display: flex;
            align-items: center;
        }
        
        .navbar-brand i {
            color: var(--accent);
            margin-right: 8px;
        }
        
        .btn-control {
            border-radius: 8px;
            padding: 8px 16px;
            font-weight: 600;
            transition: all 0.3s;
        }
        
        .dashboard {
            padding: 30px 0;
        }
        
        .file-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
            gap: 20px;
            margin-top: 30px;
        }
        
        .file-card {
            background: white;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.05);
            transition: transform 0.3s, box-shadow 0.3s;
        }
        
        .file-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 12px 25px rgba(0, 0, 0, 0.1);
        }
        
        .file-preview {
            height: 150px;
            display: flex;
            align-items: center;
            justify-content: center;
            overflow: hidden;
            background-color: #f8f9fa;
            border-bottom: 1px solid #eee;
        }
        
        .file-preview img {
            max-width: 100%;
            max-height: 150px;
            object-fit: contain;
        }
        
        .file-icon {
            font-size: 3rem;
            color: var(--accent);
        }
        
        .file-info {
            padding: 15px;
        }
        
        .file-name {
            font-weight: 600;
            margin-bottom: 5px;
            color: var(--primary);
            word-break: break-all;
        }
        
        .file-meta {
            font-size: 0.8rem;
            color: #777;
            margin-bottom: 15px;
        }
        
        .file-meta div {
            margin-bottom: 2px;
        }
        
        .file-actions {
            display: flex;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 5px;
        }
        
        .empty-state {
            text-align: center;
            padding: 50px 0;
            color: #777;
        }
        
        .empty-state i {
            font-size: 4rem;
            margin-bottom: 20px;
            color: #ddd;
        }
        
        .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        
        .stats-badge {
            background-color: var(--primary);
            color: white;
            font-size: 0.85rem;
            padding: 5px 15px;
            border-radius: 30px;
        }
    </style>
</head>
<body>
    <nav class="navbar">
        <div class="container">
            <a class="navbar-brand" href="/">
                <i class="fas fa-network-wired"></i>NetCapture
            </a>
            <div class="d-flex align-items-center gap-2">
                <a href="/" class="btn btn-sm btn-outline-secondary">
                    <i class="fas fa-home me-1"></i> Inicio
                </a>
                <a href="/sniffer" class="btn btn-sm btn-outline-primary">
                    <i class="fas fa-chart-line me-1"></i> Tráfico
                </a>
                <a href="/archivos" class="btn btn-sm btn-primary">
                    <i class="fas fa-file me-1"></i> Archivos
                </a>
            </div>
        </div>
    </nav>
    
    <div class="dashboard">
        <div class="container">
            <div class="section-header">
                <h2>Archivos Capturados</h2>
                <div class="stats-badge">
                    <i class="fas fa-file me-1"></i> {{ archivos|length }} archivos
                </div>
            </div>
            
            {% if archivos %}
            <div class="file-grid">
                {% for archivo in archivos|reverse %}
                <div class="file-card">
                    <div class="file-preview">
                        {% if archivo.tipo.startswith('image/') %}
                            <img src="/archivos/{{ archivo.nombre }}" alt="{{ archivo.nombre }}">
                        {% elif archivo.tipo.startswith('application/pdf') %}
                            <i class="fas fa-file-pdf file-icon"></i>
                        {% elif 'word' in archivo.tipo or 'document' in archivo.tipo %}
                            <i class="fas fa-file-word file-icon"></i>
                        {% elif 'excel' in archivo.tipo or 'spreadsheet' in archivo.tipo %}
                            <i class="fas fa-file-excel file-icon"></i>
                        {% elif 'zip' in archivo.tipo or 'compressed' in archivo.tipo or 'rar' in archivo.tipo %}
                            <i class="fas fa-file-archive file-icon"></i>
                        {% else %}
                            <i class="fas fa-file file-icon"></i>
                        {% endif %}
                    </div>
                    <div class="file-info">
                        <div class="file-name">{{ archivo.nombre }}</div>
                        <div class="file-meta">
                            <div><i class="fas fa-info-circle me-1"></i> {{ archivo.tipo }}</div>
                            <div><i class="fas fa-weight me-1"></i> {{ (archivo.tamaño / 1024)|round(1) }} KB</div>
                            <div><i class="far fa-clock me-1"></i> {{ archivo.timestamp }}</div>
                        </div>
                        <div class="file-actions">
                            <a href="/archivos/{{ archivo.nombre }}" download class="btn btn-sm btn-success">
                                <i class="fas fa-download me-1"></i> Descargar
                            </a>
                            <a href="/analisis/{{ archivo.hash }}" class="btn btn-sm btn-info">
                                <i class="fas fa-microscope me-1"></i> Analizar
                            </a>
                            <a href="/archivos/{{ archivo.nombre }}" target="_blank" class="btn btn-sm btn-outline-primary">
                                <i class="fas fa-eye me-1"></i> Ver
                            </a>
                        </div>
                    </div>
                </div>
                {% endfor %}
            </div>
            {% else %}
            <div class="empty-state">
                <i class="fas fa-folder-open"></i>
                <h3>No hay archivos capturados</h3>
                <p>Los archivos detectados en el tráfico de red aparecerán aquí</p>
            </div>
            {% endif %}
        </div>
    </div>
</body>
</html>
    """
    
    return render_template_string(html_archivos_template,
                                 archivos=archivos_capturados,
                                 capturando=capturando)

@app.route("/archivos/<nombre>")
def servir_archivo(nombre):
    return send_from_directory(carpeta_archivos, nombre)

@app.route("/analisis/<hash_archivo>")
def analizar_archivo(hash_archivo):
    # Buscar en archivos temporales primero
    if hash_archivo in archivos_temporales:
        global archivo_actual_analisis
        archivo_actual_analisis = archivos_temporales[hash_archivo]
        
        # Buscar información completa en archivos_capturados
        info_archivo = None
        for archivo in archivos_capturados:
            if archivo['hash'] == hash_archivo:
                info_archivo = archivo
                break
        
        if not info_archivo:
            # Crear información básica si no existe en archivos_capturados
            info_archivo = {
                'nombre': f"{hash_archivo[:12]}.bin",
                'tipo': archivo_actual_analisis['tipo'],
                'tamaño': len(archivo_actual_analisis['datos']),
                'timestamp': archivo_actual_analisis['hora_captura'].strftime("%Y-%m-%d %H:%M:%S"),
                'metadatos': analizar_metadatos(archivo_actual_analisis['datos'], archivo_actual_analisis['tipo'])
            }
        
        # Crear análisis de bytes y contenido
        analisis = {}
        datos = archivo_actual_analisis['datos']
        
        # Mapa de bytes (primeros 256 bytes en formato hexadecimal)
        analisis['mapa_bytes'] = ' '.join(f"{byte:02x}" for byte in datos[:256])
        
        # Intento de decodificación como texto (primeros 1024 bytes)
        try:
            analisis['vista_texto'] = datos[:1024].decode('utf-8', errors='replace')
        except:
            analisis['vista_texto'] = "No se puede mostrar como texto"
        
        # Análisis de encabezado
        analisis['encabezado'] = ' '.join(f"{byte:02x}" for byte in datos[:32])
        
        # Identificación de formato basada en firmas
        formato = "Desconocido"
        firmas = {
            b'\xFF\xD8\xFF': "JPEG",
            b'\x89PNG\r\n\x1A\n': "PNG",
            b'GIF8': "GIF",
            b'%PDF': "PDF",
            b'PK\x03\x04': "ZIP/Office",
            b'Rar!\x1A\x07': "RAR",
            b'\xD0\xCF\x11\xE0': "Documento MS Office"
        }
        
        for firma, nombre in firmas.items():
            if datos.startswith(firma):
                formato = nombre
                break
        
        analisis['formato_detectado'] = formato
        
        return render_template_string(html_analisis, 
                                     archivo=info_archivo, 
                                     analisis=analisis,
                                     datos_hex=datos[:512].hex())
    else:
        # Si no está en archivos temporales, buscar en los archivos capturados
        for archivo in archivos_capturados:
            if archivo['hash'] == hash_archivo:
                try:
                    with open(archivo['ruta'], 'rb') as f:
                        datos = f.read()
                        
                    # Guardar temporalmente para análisis
                    archivos_temporales[hash_archivo] = {
                        'datos': datos,
                        'tipo': archivo['tipo'],
                        'hora_captura': datetime.now()
                    }
                    
                    # Redireccionar al mismo endpoint para análisis
                    return redirect(url_for('analizar_archivo', hash_archivo=hash_archivo))
                except:
                    return "Error al leer el archivo para análisis"
                
        return "Archivo no encontrado en memoria temporal ni en disco"

# Ejecutar app
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)