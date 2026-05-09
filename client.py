#!/usr/bin/env python3
"""
Kali MCP Client - Windows side (stdio MCP bridge)
Connects 5ire/Claude Desktop to the Kali MCP Server via HTTP
"""

import sys
import json
import urllib.request
import urllib.error
import argparse

def http_post(base_url, path, data):
    url = f"{base_url}{path}"
    body = json.dumps(data).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=600) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return {"error": e.read().decode(), "success": False}
    except Exception as e:
        return {"error": str(e), "success": False}

def http_get(base_url, path):
    url = f"{base_url}{path}"
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            return json.loads(resp.read())
    except Exception as e:
        return {"error": str(e)}

def format_result(result):
    if "error" in result and not result.get("stdout"):
        return f"Error: {result['error']}"
    out = []
    if result.get("stdout"):
        out.append(result["stdout"])
    if result.get("stderr"):
        out.append(f"[stderr]: {result['stderr']}")
    if not out:
        return "Command completed with no output."
    return "\n".join(out)

TOOLS_SCHEMA = [
    {
        "name": "kali_shell",
        "description": "Execute any raw shell command on Kali Linux. Use for any command not covered by specific tools.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Shell command to run"},
                "timeout": {"type": "integer", "description": "Timeout in seconds (default 300)", "default": 300}
            },
            "required": ["command"]
        }
    },
    {
        "name": "kali_run_tool",
        "description": "Run a specific Kali tool by name with arguments. Use /tools endpoint to see available tools.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "tool": {"type": "string", "description": "Tool name (e.g. nmap, nuclei, sqlmap)"},
                "args": {"type": "string", "description": "Arguments to pass to the tool"},
                "timeout": {"type": "integer", "description": "Timeout in seconds", "default": 300}
            },
            "required": ["tool"]
        }
    },
    {
        "name": "kali_nmap",
        "description": "Run nmap network scan against a target",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname"},
                "args": {"type": "string", "description": "Nmap arguments (default: -sV -sC)", "default": "-sV -sC"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "kali_nuclei",
        "description": "Run nuclei vulnerability scanner against a target URL",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "args": {"type": "string", "description": "Extra nuclei arguments"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "kali_dirsearch",
        "description": "Run dirsearch web path scanner against a target URL",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "args": {"type": "string", "description": "Extra dirsearch arguments"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "kali_ffuf",
        "description": "Run ffuf web fuzzer against a target",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL (FUZZ keyword will be appended)"},
                "wordlist": {"type": "string", "description": "Path to wordlist", "default": "/usr/share/wordlists/dirb/common.txt"},
                "args": {"type": "string", "description": "Extra ffuf arguments"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "kali_gobuster",
        "description": "Run gobuster directory/DNS brute forcer",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "mode": {"type": "string", "description": "Mode: dir, dns, vhost", "default": "dir"},
                "wordlist": {"type": "string", "description": "Wordlist path", "default": "/usr/share/wordlists/dirb/common.txt"},
                "args": {"type": "string", "description": "Extra gobuster arguments"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "kali_sqlmap",
        "description": "Run sqlmap SQL injection scanner",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "args": {"type": "string", "description": "Extra sqlmap arguments", "default": "--batch"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "kali_nikto",
        "description": "Run nikto web vulnerability scanner",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL or IP"},
                "args": {"type": "string", "description": "Extra nikto arguments"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "kali_hydra",
        "description": "Run hydra password brute forcer",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname"},
                "service": {"type": "string", "description": "Service (ssh, ftp, http-post-form, etc)", "default": "ssh"},
                "userlist": {"type": "string", "description": "Path to username list"},
                "passlist": {"type": "string", "description": "Path to password list", "default": "/usr/share/wordlists/rockyou.txt"},
                "args": {"type": "string", "description": "Extra hydra arguments"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "kali_searchsploit",
        "description": "Search ExploitDB for exploits",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query (e.g. 'apache 2.4', 'wordpress 5.6')"},
                "args": {"type": "string", "description": "Extra searchsploit arguments"}
            },
            "required": ["query"]
        }
    },
    {
        "name": "kali_subfinder",
        "description": "Run subfinder subdomain discovery",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Target domain"},
                "args": {"type": "string", "description": "Extra subfinder arguments"}
            },
            "required": ["domain"]
        }
    },
    {
        "name": "kali_whatweb",
        "description": "Fingerprint web technologies on a target",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "args": {"type": "string", "description": "Extra whatweb arguments"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "kali_wpscan",
        "description": "Run WPScan WordPress vulnerability scanner",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target WordPress URL"},
                "args": {"type": "string", "description": "Extra wpscan arguments"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "kali_enum4linux",
        "description": "Run enum4linux SMB/Samba enumeration",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP"},
                "args": {"type": "string", "description": "Extra arguments", "default": "-a"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "kali_health",
        "description": "Check which tools are available on the Kali server",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    }
]

def handle_tool_call(base_url, name, arguments):
    if name == "kali_shell":
        result = http_post(base_url, "/shell", {"command": arguments["command"], "timeout": arguments.get("timeout", 300)})
        return format_result(result)
    elif name == "kali_run_tool":
        result = http_post(base_url, "/run", arguments)
        return format_result(result)
    elif name == "kali_nmap":
        result = http_post(base_url, "/nmap", arguments)
        return format_result(result)
    elif name == "kali_nuclei":
        result = http_post(base_url, "/nuclei", arguments)
        return format_result(result)
    elif name == "kali_dirsearch":
        result = http_post(base_url, "/dirsearch", arguments)
        return format_result(result)
    elif name == "kali_ffuf":
        result = http_post(base_url, "/ffuf", arguments)
        return format_result(result)
    elif name == "kali_gobuster":
        result = http_post(base_url, "/gobuster", arguments)
        return format_result(result)
    elif name == "kali_sqlmap":
        result = http_post(base_url, "/sqlmap", arguments)
        return format_result(result)
    elif name == "kali_nikto":
        result = http_post(base_url, "/nikto", arguments)
        return format_result(result)
    elif name == "kali_hydra":
        result = http_post(base_url, "/hydra", arguments)
        return format_result(result)
    elif name == "kali_searchsploit":
        result = http_post(base_url, "/searchsploit", arguments)
        return format_result(result)
    elif name == "kali_subfinder":
        result = http_post(base_url, "/subfinder", arguments)
        return format_result(result)
    elif name == "kali_whatweb":
        result = http_post(base_url, "/whatweb", arguments)
        return format_result(result)
    elif name == "kali_wpscan":
        result = http_post(base_url, "/wpscan", arguments)
        return format_result(result)
    elif name == "kali_enum4linux":
        result = http_post(base_url, "/enum4linux", arguments)
        return format_result(result)
    elif name == "kali_health":
        result = http_get(base_url, "/health")
        return json.dumps(result, indent=2)
    else:
        return f"Unknown tool: {name}"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", default="http://127.0.0.1:5000", help="Kali server URL")
    args = parser.parse_args()
    base_url = args.server.rstrip("/")

    def send(obj):
        sys.stdout.write(json.dumps(obj) + "\n")
        sys.stdout.flush()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue

        method = msg.get("method", "")
        msg_id = msg.get("id")

        if method == "initialize":
            send({"jsonrpc": "2.0", "id": msg_id, "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "kali-mcp-powerful", "version": "2.0"}
            }})

        elif method == "tools/list":
            send({"jsonrpc": "2.0", "id": msg_id, "result": {"tools": TOOLS_SCHEMA}})

        elif method == "tools/call":
            params = msg.get("params", {})
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {})
            result_text = handle_tool_call(base_url, tool_name, arguments)
            send({"jsonrpc": "2.0", "id": msg_id, "result": {
                "content": [{"type": "text", "text": result_text}]
            }})

        elif method == "notifications/initialized":
            pass

        else:
            if msg_id is not None:
                send({"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32601, "message": f"Method not found: {method}"}})

if __name__ == "__main__":
    main()
