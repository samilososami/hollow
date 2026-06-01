<p align="center">
<img src="https://img.shields.io/badge/python-3.13-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python 3.13">
<img src="https://img.shields.io/badge/Ollama-000000?style=flat-square&logo=ollama&logoColor=white" alt="Ollama">
<img src="https://img.shields.io/badge/httpx-0.27+-00A4BD?style=flat-square" alt="httpx">
<img src="https://img.shields.io/badge/Rich-13+-E9B35D?style=flat-square" alt="Rich">
<img src="https://img.shields.io/badge/prompt--toolkit-3+-FFD429?style=flat-square" alt="prompt-toolkit">
</p>

<br>

<p align="center">
<code>
&nbsp;&nbsp;&nbsp;&nbsp;__&nbsp;&nbsp;______&nbsp;&nbsp;__&nbsp;&nbsp;&nbsp;&nbsp;__&nbsp;&nbsp;&nbsp;&nbsp;____&nbsp;_&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;__<br>
&nbsp;&nbsp;&nbsp;/&nbsp;/&nbsp;/&nbsp;/&nbsp;__&nbsp;\/&nbsp;/&nbsp;&nbsp;&nbsp;/&nbsp;/&nbsp;&nbsp;&nbsp;/&nbsp;__&nbsp;\&nbsp;|&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;/&nbsp;/<br>
&nbsp;&nbsp;/&nbsp;/_/&nbsp;/&nbsp;/&nbsp;/&nbsp;/&nbsp;/&nbsp;&nbsp;&nbsp;/&nbsp;/&nbsp;&nbsp;&nbsp;/&nbsp;/&nbsp;/&nbsp;/|&nbsp;/|&nbsp;/&nbsp;/&nbsp;<br>
&nbsp;/&nbsp;__&nbsp;&nbsp;/&nbsp;/_/&nbsp;/&nbsp;/___/&nbsp;/___/&nbsp;/_/&nbsp;/|&nbsp;|/&nbsp;|/&nbsp;/&nbsp;&nbsp;<br>
/__/&nbsp;/_/\____/_____/_____/\____/&nbsp;|__/|__/&nbsp;&nbsp;&nbsp;
</code>
</p>

<h1 align="center">Hollow</h1>

<p align="center">
<strong>Agente de pentesting impulsado por IA. Autonomo, agresivo, implacable.<br>
Ejecuta, no sugiere.</strong>
</p>

<br>

---

Hollow es un agente de pentesting interactivo que ejecuta comandos directamente en tu sistema, impulsado por modelos de lenguaje locales o en la nube a traves de Ollama. No es un asistente que sugiere comandos -- es un operador que los ejecuta.

Construido para profesionales de ciberseguridad que necesitan automatizar escaneos, explotaciones y escalada de privilegios sin intermediarios.

---

### Caracteristicas

- **Agente autonomo** -- Ejecuta comandos via etiquetas `[CMD]`, busca la web via `[SEARCH]`, itera hasta completar la tarea
- **PWNME** -- Modo de escalada de privilegios exhaustivo con deteccion automatica de OS (Linux/Windows)
- **Ollama Cloud** -- Usa modelos en la nube sin instalar Ollama localmente, via API key
- **Consciencia del entorno** -- Sabe en que OS, distro, kernel y usuario esta corriendo
- **Streaming en tiempo real** -- Respuestas con renderizado Markdown y spinner de actividad
- **Modo compacto PWNME** -- Salida minima, accion maxima
- **Filtro de pensamiento** -- Elimina bloques `<think>` automaticamente
- **Busqueda web integrada** -- DuckDuckGo Search para vulnerabilidades y exploits
- **Windows Defender aware** -- PWNME para Windows evade antivirus automaticamente
- **Permisos interactivos** -- Confirma, permite o deniega cada comando
- **Modo unrestricted** -- `--skip-permissions` o `/skip-permissions` para sin confirmaciones

---

### Instalacion

```bash
git clone https://github.com/samilososami/hollow.git
cd hollow
pip install -r requirements.txt
```

**Dependencias:**

| Paquete | Version | Uso |
|---------|---------|-----|
| httpx | 0.27+ | Cliente HTTP para API de Ollama |
| Rich | 13+ | Interfaz de terminal (Markdown, tablas, paneles) |
| prompt-toolkit | 3+ | Prompt interactivo con historial y autocompletado |
| ddgs | 9+ | Busqueda web via DuckDuckGo |

**Ollama** debe estar instalado y ejecutandose, o bien usar una API key de Ollama Cloud:

```bash
# Opcion 1: Ollama local
ollama serve

# Opcion 2: Ollama Cloud (sin instalacion local)
python3 hollowpc.py --ollama-api TU_API_KEY
```

---

### Uso

```bash
# Inicio normal
python3 hollowpc.py

# Modo PWNME directo (escalada de privilegios)
python3 hollowpc.py --pwnme

# Con modelo especifico
python3 hollowpc.py --model qwen3:4b

# Sin confirmaciones de comando
python3 hollowpc.py --skip-permissions

# Con API key de Ollama Cloud
python3 hollowpc.py --ollama-api sk-xxxxxxxx
```

**Dentro de Hollow:**

```
hollow > escanea los puertos abiertos de 192.168.1.1
hollow > /pwnme                          # escalada de privilegios
hollow > /ollama-api sk-xxxxxxxx         # configurar API cloud
hollow > /model qwen3:4b                 # cambiar modelo
hollow > /search exploit CVE-2024-1234   # busqueda web
hollow > /help                           # ver comandos
```

---

### PWNME -- Escalada de Privilegios

PWNME es el modo autonomo de escalada de privilegios. Detecta el OS automaticamente y sigue una metodologia ordenada por dificultad:

**Linux:**

| Paso | Vector | Dificultad |
|------|--------|------------|
| 1 | Contrasenas default | Facil |
| 2 | Sudo misconfiguration | Facil |
| 3 | SUID/SGID binaries | Media |
| 4 | Capabilities | Media |
| 5 | Cron jobs & scripts | Media |
| 6 | Exploits por version | Dificil |
| 7 | Deep search | Dificil |

**Windows:**

| Paso | Vector | Dificultad |
|------|--------|------------|
| 1 | Who am I? | Facil |
| 2 | Quick wins | Facil |
| 3 | Misconfiguraciones | Media |
| 4 | Exploits por version | Dificil |
| 5 | Deep recon | Dificil |

PWNME incluye evasion automatica de Windows Defender y antivirus.

**Menu de exito (Linux):**

1. Grant full permissions -- agregar al sudoers con NOPASSWD
2. Drop to root shell -- abrir shell interactiva como root
3. Continue as root -- relanzar Hollow como root directamente
4. Do nothing

**Menu de exito (Windows):**

1. Add to Administrators
2. Drop to admin shell
3. Do nothing

---

### Ollama Cloud

Hollow soporta modelos en la nube sin necesidad de instalar Ollama localmente:

```bash
# Via flag
python3 hollowpc.py --ollama-api TU_API_KEY

# Via variable de entorno
export OLLAMA_API_KEY=TU_API_KEY

# Via comando interactivo
hollow > /ollama-api TU_API_KEY

# Ver configuracion actual
hollow > /ollama-api
  Mode:     Ollama Cloud
  URL:      https://ollama.com/api
  API Key:  sk-x...xxxx
```

Obtén tu API key en [ollama.com/settings/keys](https://ollama.com/settings/keys).

---

### Arquitectura

```
hollowpc.py          # Unico archivo -- toda la logica
  |
  +-- CloudConfig     # Configuracion de Ollama Cloud (API key, URL, headers)
  +-- RuntimeState    # Estado en tiempo de ejecucion (OS, conexion, contexto)
  +-- SYSTEM_PROMPT   # Prompt del sistema con contexto del OS
  +-- PWNME_SYSTEM_PROMPT     # Prompt de escalada Linux
  +-- PWNME_WINDOWS_PROMPT    # Prompt de escalada Windows
  +-- stream_chat()   # Streaming con timeout, cancelacion, auth cloud
  +-- pwnme_mode()    # Bucle autonomo de escalada de privilegios
  +-- chat_loop()     # Bucle interactivo principal
  +-- handle_command() # Comandos slash /help /pwnme /ollama-api etc.
```

---

### Comandos

| Comando | Descripcion |
|---------|-------------|
| `/help` | Mostrar comandos disponibles |
| `/model <nombre>` | Cambiar modelo |
| `/skip-permissions` | Alternar modo sin confirmaciones |
| `/search <query>` | Buscar en la web |
| `/pwnme` | Escalada de privilegios |
| `/pwnme skip-anim` | PWNME sin animacion |
| `/ollama-api [key]` | Mostrar/configurar API key de Ollama Cloud |
| `/info` | Informacion del sistema |
| `/status` | Uso de tokens del contexto |
| `/auth` | Autenticarse como creador |
| `/clear` | Limpiar historial de conversacion |
| `/clearscreen` | Limpiar terminal |
| `/exit` | Salir |

---

### EULA

Hollow se proporciona exclusivamente para uso educativo y pentesting autorizado. Al ejecutar Hollow, aceptas que eres responsable de todas las acciones realizadas por la herramienta en cualquier sistema.

---

<p align="center">
<strong>Hollow</strong> -- Creado por <a href="https://samilososami.com">Sami Gonzalez Kamel</a> (<a href="https://github.com/samilososami">@samilososami</a>)
</p>