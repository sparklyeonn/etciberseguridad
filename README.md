# 🛡️ Evaluación Transversal – Análisis y Corrección de Vulnerabilidades en Aplicación Flask

Este repositorio contiene el análisis, documentación y corrección de vulnerabilidades encontradas en una aplicación web desarrollada con **Flask**, como parte de la asignatura **Ciberseguridad en Desarrollo**.

El proyecto aborda fallos comunes según el estándar OWASP, implementa medidas defensivas y presenta evidencia del proceso de auditoría.

---

## 📌 Objetivo del Proyecto
Identificar, explicar y mitigar vulnerabilidades críticas presentes en una aplicación Flask que incluye autenticación, sesiones, módulo de comentarios y un panel de administración.

---

## 🔍 Vulnerabilidades Detectadas

### 1. Inyección SQL
Concatenación insegura en consultas SQL que permitía ejecutar código malicioso.

### 2. Hash de Contraseñas Inseguro
Uso de SHA-256 sin *salt* ni factor de costo.

### 3. XSS Almacenado
Renderizado directo del contenido del usuario sin sanitización.

### 4. Ausencia de CSRF
Los formularios no incorporaban tokens de verificación.

### 5. Manejo Inseguro de Sesiones
`SECRET_KEY` generado dinámicamente y cookies sin atributos de seguridad.

### 6. Aplicación en modo debug
`debug=True` exponía trazas internas y el debugger interactivo.

---

## 🛠️ Medidas Correctivas

### ✔️ Consultas Parametrizadas
Evita la manipulación de SQL por parte de entradas maliciosas.

### ✔️ Hash Seguro (PBKDF2)
Implementado mediante `generate_password_hash()` y `check_password_hash()`.

### ✔️ Mitigación de XSS
- Migración a `render_template`
- Escape automático
- Uso de `{{ variable | e }}` cuando corresponde

### ✔️ Protección CSRF
Integración de `Flask-WTF` y `CSRFProtect`.

### ✔️ Fortalecimiento de Sesiones
Configuración de:
```python
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Strict"
)

