#!/usr/bin/env python3
"""
Kali Linux MCP Server - Powerful Edition
Supports: Recon, Web, Exploit, Post-Exploit, Raw Shell
"""

import subprocess
import shutil
import logging
import os
import json
from flask import Flask, request, jsonify

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

# ─── Tool definitions ───────────────────────────────────────────────────────

TOOLS = {
    # RECON
    "nmap":        {"desc": "Network scanner",              "check": "nmap"},
    "nuclei":      {"desc": "Vulnerability scanner",        "check": "nuclei"},
    "dirsearch":   {"desc": "Web path scanner",             "check": "dirsearch"},
    "ffuf":        {"desc": "Web fuzzer",                   "check": "ffuf"},
    "gobuster":    {"desc": "Dir/DNS brute forcer",         "check": "gobuster"},
    "subfinder":   {"desc": "Subdomain discovery",          "check": "subfinder"},
    "amass":       {"desc": "Attack surface mapping",       "check": "amass"},
    "whatweb":     {"desc": "Web tech fingerprint",         "check": "whatweb"},
    "wafw00f":     {"desc": "WAF detector",                 "check": "wafw00f"},
    "theHarvester":{"desc": "Email/domain harvester",       "check": "theHarvester"},
    # WEB
    "nikto":       {"desc": "Web vulnerability scanner",    "check": "nikto"},
    "sqlmap":      {"desc": "SQL injection tool",           "check": "sqlmap"},
    "wpscan":      {"desc": "WordPress scanner",            "check": "wpscan"},
    "feroxbuster": {"desc": "Fast content discovery",       "check": "feroxbuster"},
    # EXPLOIT
    "searchsploit":{"desc": "Exploit search (ExploitDB)",   "check": "searchsploit"},
    "msfconsole":  {"desc": "Metasploit framework",         "check": "msfconsole"},
    # POST-EXPLOIT
    "hydra":       {"desc": "Password brute forcer",        "check": "hydra"},
    "john":        {"desc": "John the Ripper",              "check": "john"},
    "hashcat":     {"desc": "GPU hash cracker",             "check": "hashcat"},
    "enum4linux":  {"desc": "SMB/SAMBA enumeration",        "check": "enum4linux"},
    "smbclient":   {"desc": "SMB client",                   "check": "smbclient"},
    "crackmapexec":{"desc": "Network pentesting swiss knife","check": "crackmapexec"},
    "netexec":     {"desc": "Network execution tool",       "check": "netexec"},
    "impacket-secretsdump": {"desc": "Dump credentials",   "check": "impacket-secretsdump"},
}

def tool_available(tool_name):
    return shutil.which(tool_name) is not None

def run_command(cmd, timeout=300):
    """Run a shell command and return output."""
    try:
        logger.info(f"Running: {cmd}")
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=timeout, env={**os.environ, "TERM": "dumb"}
        )
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
            "success": result.returncode == 0
        }
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": f"Command timed out after {timeout}s", "returncode": -1, "success": False}
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "returncode": -1, "success": False}

# ─── Routes ──────────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    tools_status = {name: tool_available(info["check"]) for name, info in TOOLS.items()}
    all_ok = all(tools_status.values())
    return jsonify({
        "status": "healthy",
        "message": "Kali Linux MCP Server (Powerful Edition) is running",
        "all_tools_available": all_ok,
        "tools_status": tools_status
    })

@app.route("/tools")
def list_tools():
    tools_list = []
    for name, info in TOOLS.items():
        tools_list.append({
            "name": name,
            "description": info["desc"],
            "available": tool_available(info["check"])
        })
    return jsonify({"tools": tools_list})

@app.route("/run", methods=["POST"])
def run_tool():
    """Run any predefined tool with arguments."""
    data = request.get_json()
    tool = data.get("tool", "").strip()
    args = data.get("args", "").strip()
    timeout = data.get("timeout", 300)

    if not tool:
        return jsonify({"error": "Missing 'tool' parameter"}), 400
    if tool not in TOOLS:
        return jsonify({"error": f"Unknown tool '{tool}'. Use /tools to list available tools."}), 400
    if not tool_available(TOOLS[tool]["check"]):
        return jsonify({"error": f"Tool '{tool}' is not installed. Run: sudo apt install {tool}"}), 400

    cmd = f"{tool} {args}" if args else tool
    result = run_command(cmd, timeout=timeout)
    return jsonify(result)

@app.route("/shell", methods=["POST"])
def raw_shell():
    """Execute any raw shell command."""
    data = request.get_json()
    command = data.get("command", "").strip()
    timeout = data.get("timeout", 300)

    if not command:
        return jsonify({"error": "Missing 'command' parameter"}), 400

    result = run_command(command, timeout=timeout)
    return jsonify(result)

# ─── Shortcut routes ─────────────────────────────────────────────────────────

@app.route("/nmap", methods=["POST"])
def nmap_scan():
    data = request.get_json()
    target = data.get("target", "")
    args = data.get("args", "-sV -sC")
    if not target:
        return jsonify({"error": "Missing 'target'"}), 400
    return jsonify(run_command(f"nmap {args} {target}"))

@app.route("/nuclei", methods=["POST"])
def nuclei_scan():
    data = request.get_json()
    target = data.get("target", "")
    args = data.get("args", "")
    if not target:
        return jsonify({"error": "Missing 'target'"}), 400
    return jsonify(run_command(f"nuclei -u {target} {args}"))

@app.route("/dirsearch", methods=["POST"])
def dirsearch_scan():
    data = request.get_json()
    target = data.get("target", "")
    args = data.get("args", "")
    if not target:
        return jsonify({"error": "Missing 'target'"}), 400
    return jsonify(run_command(f"dirsearch -u {target} {args}"))

@app.route("/ffuf", methods=["POST"])
def ffuf_scan():
    data = request.get_json()
    target = data.get("target", "")
    wordlist = data.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
    args = data.get("args", "")
    if not target:
        return jsonify({"error": "Missing 'target'"}), 400
    return jsonify(run_command(f"ffuf -u {target}/FUZZ -w {wordlist} {args}"))

@app.route("/gobuster", methods=["POST"])
def gobuster_scan():
    data = request.get_json()
    target = data.get("target", "")
    wordlist = data.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
    mode = data.get("mode", "dir")
    args = data.get("args", "")
    if not target:
        return jsonify({"error": "Missing 'target'"}), 400
    return jsonify(run_command(f"gobuster {mode} -u {target} -w {wordlist} {args}"))

@app.route("/sqlmap", methods=["POST"])
def sqlmap_scan():
    data = request.get_json()
    target = data.get("target", "")
    args = data.get("args", "--batch")
    if not target:
        return jsonify({"error": "Missing 'target'"}), 400
    return jsonify(run_command(f"sqlmap -u {target} {args}", timeout=600))

@app.route("/nikto", methods=["POST"])
def nikto_scan():
    data = request.get_json()
    target = data.get("target", "")
    args = data.get("args", "")
    if not target:
        return jsonify({"error": "Missing 'target'"}), 400
    return jsonify(run_command(f"nikto -h {target} {args}"))

@app.route("/hydra", methods=["POST"])
def hydra_attack():
    data = request.get_json()
    target = data.get("target", "")
    service = data.get("service", "ssh")
    userlist = data.get("userlist", "")
    passlist = data.get("passlist", "/usr/share/wordlists/rockyou.txt")
    args = data.get("args", "")
    if not target:
        return jsonify({"error": "Missing 'target'"}), 400
    user_arg = f"-L {userlist}" if userlist else "-l admin"
    return jsonify(run_command(f"hydra {user_arg} -P {passlist} {target} {service} {args}", timeout=600))

@app.route("/searchsploit", methods=["POST"])
def searchsploit_query():
    data = request.get_json()
    query = data.get("query", "")
    args = data.get("args", "")
    if not query:
        return jsonify({"error": "Missing 'query'"}), 400
    return jsonify(run_command(f"searchsploit {args} {query}"))

@app.route("/subfinder", methods=["POST"])
def subfinder_scan():
    data = request.get_json()
    domain = data.get("domain", "")
    args = data.get("args", "")
    if not domain:
        return jsonify({"error": "Missing 'domain'"}), 400
    return jsonify(run_command(f"subfinder -d {domain} {args}"))

@app.route("/whatweb", methods=["POST"])
def whatweb_scan():
    data = request.get_json()
    target = data.get("target", "")
    args = data.get("args", "")
    if not target:
        return jsonify({"error": "Missing 'target'"}), 400
    return jsonify(run_command(f"whatweb {target} {args}"))

@app.route("/wpscan", methods=["POST"])
def wpscan_scan():
    data = request.get_json()
    target = data.get("target", "")
    args = data.get("args", "")
    if not target:
        return jsonify({"error": "Missing 'target'"}), 400
    return jsonify(run_command(f"wpscan --url {target} {args}", timeout=600))

@app.route("/enum4linux", methods=["POST"])
def enum4linux_scan():
    data = request.get_json()
    target = data.get("target", "")
    args = data.get("args", "-a")
    if not target:
        return jsonify({"error": "Missing 'target'"}), 400
    return jsonify(run_command(f"enum4linux {args} {target}"))

# ─── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Kali MCP Server - Powerful Edition")
    parser.add_argument("--ip", default="127.0.0.1", help="Bind IP (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000, help="Port (default: 5000)")
    parser.add_argument("--debug", action="store_true", help="Debug mode")
    args = parser.parse_args()

    logger.info(f"Starting Kali MCP Server (Powerful Edition) on {args.ip}:{args.port}")
    logger.info("Endpoints: /health /tools /run /shell /nmap /nuclei /dirsearch /ffuf /gobuster /sqlmap /nikto /hydra /searchsploit /subfinder /whatweb /wpscan /enum4linux")
    app.run(host=args.ip, port=args.port, debug=args.debug)
