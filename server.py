"""
MalwSentinel Web Backend Server
Built with Starlette & Uvicorn, integrating the Google Antigravity Malware Triage Agent.
"""

import os
import sys
import re
import json
import shutil
import tempfile
import asyncio
from typing import Dict, Any, List

from starlette.applications import Starlette
from starlette.responses import JSONResponse, FileResponse
from starlette.routing import Route, Mount
from starlette.staticfiles import StaticFiles
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware

# Import static toolkit and policy hooks from core agent
from malware_triage_agent import (
    get_file_hashes,
    calculate_entropy,
    analyze_pe_structure,
    extract_iocs,
    prevent_execution_hook,
    create_dummy_sample_if_missing,
    config,
    load_api_key,
)

from llm_engine import UnifiedTriageAgent, get_provider_metadata, PROVIDER_PRESETS

try:
    from google.antigravity import Agent
except ImportError:
    Agent = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
IS_VERCEL = bool(os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"))

# Ensure default sample exists
DEFAULT_SAMPLE = os.path.join(BASE_DIR, "suspicious_sample.exe")
if not os.path.exists(DEFAULT_SAMPLE):
    try:
        create_dummy_sample_if_missing(DEFAULT_SAMPLE)
    except Exception:
        DEFAULT_SAMPLE = "/tmp/suspicious_sample.exe"
        create_dummy_sample_if_missing(DEFAULT_SAMPLE)

STATIC_DIR = os.path.join(BASE_DIR, "static")
UPLOAD_DIR = "/tmp/uploads" if IS_VERCEL else os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)


async def home(request):
    """Serves the main frontend dashboard."""
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return JSONResponse({"status": "Frontend building..."})


async def get_presets(request):
    """Returns available sample presets for 1-click demonstration."""
    calc_path = r"C:\Windows\System32\calc.exe"
    presets = [
        {
            "id": "suspicious_sample",
            "name": "Simulated Backdoor Loader (Default)",
            "path": DEFAULT_SAMPLE,
            "description": "PE binary with embedded C2 URLs, public IPs, and persistence registry keys.",
            "category": "High Risk",
        }
    ]
    if os.path.exists(calc_path):
        presets.append({
            "id": "clean_calc",
            "name": "Clean Windows Binary (calc.exe)",
            "path": calc_path,
            "description": "Standard Microsoft Windows Calculator executable.",
            "category": "Benign",
        })
    return JSONResponse({"presets": presets})


async def get_providers(request):
    """Returns available AI agent providers and their active status."""
    return JSONResponse({"providers": get_provider_metadata()})


import uuid
import datetime

def generate_yara_rule(file_name: str, hashes: dict, pe_info: dict, iocs: dict) -> str:
    clean_name = re.sub(r'[^a-zA-Z0-9_]', '_', file_name).strip('_')
    rule_name = f"MalwSentinel_{clean_name or 'Sample'}"
    
    sha256 = hashes.get("sha256", "")
    md5 = hashes.get("md5", "")
    today = datetime.date.today().isoformat()
    
    strings_def = []
    condition_parts = ["uint16(0) == 0x5A4D"]
    
    str_idx = 0
    for url in iocs.get("url_indicators", [])[:5]:
        strings_def.append(f'        $url_{str_idx} = "{url}" ascii wide nocase')
        str_idx += 1
        
    for ip in iocs.get("ipv4_indicators", [])[:5]:
        strings_def.append(f'        $ip_{str_idx} = "{ip}" ascii wide')
        str_idx += 1

    for reg in iocs.get("registry_keys", [])[:5]:
        escaped_reg = reg.replace("\\", "\\\\")
        strings_def.append(f'        $reg_{str_idx} = "{escaped_reg}" ascii wide nocase')
        str_idx += 1
        
    for imp in pe_info.get("suspicious_imports", [])[:6]:
        api = imp.get("api")
        if api:
            strings_def.append(f'        $api_{str_idx} = "{api}" ascii')
            str_idx += 1

    if strings_def:
        condition_parts.append("(any of ($url*) or any of ($ip*) or any of ($reg*) or 2 of ($api*))")
    else:
        condition_parts.append("filesize < 15MB")
        
    yara_code = f"""rule {rule_name}
{{
    meta:
        description = "Auto-generated detection rule by MalwSentinel Tier-2 SOC Agent"
        author = "Antigravity SOC Analyst"
        date = "{today}"
        target_sample = "{file_name}"
        hash_md5 = "{md5}"
        hash_sha256 = "{sha256}"
        reference = "Internal SOC Threat Intel"

    strings:
{chr(10).join(strings_def) if strings_def else '        $mz = "MZ"'}

    condition:
        {' and '.join(condition_parts)}
}}"""
    return yara_code


def generate_stix_bundle(file_name: str, hashes: dict, iocs: dict, threat_score: int, threat_level: str) -> dict:
    bundle_id = f"bundle--{uuid.uuid4()}"
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    
    malware_id = f"malware--{uuid.uuid4()}"
    objects = []
    
    objects.append({
        "type": "malware",
        "spec_version": "2.1",
        "id": malware_id,
        "created": now,
        "modified": now,
        "name": file_name,
        "is_family": False,
        "description": f"Analyzed binary with threat severity {threat_score}/100 ({threat_level}).",
        "malware_types": ["backdoor", "trojan"] if threat_score >= 50 else ["suspicious-utility"],
        "labels": ["malwsentinel-triage", threat_level.lower()]
    })
    
    sha256 = hashes.get("sha256")
    if sha256:
        ind_id = f"indicator--{uuid.uuid4()}"
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": ind_id,
            "created": now,
            "modified": now,
            "name": f"File Hash SHA-256 for {file_name}",
            "pattern": f"[file:hashes.'SHA-256' = '{sha256}']",
            "pattern_type": "stix",
            "valid_from": now
        })
        objects.append({
            "type": "relationship",
            "spec_version": "2.1",
            "id": f"relationship--{uuid.uuid4()}",
            "created": now,
            "modified": now,
            "relationship_type": "indicates",
            "source_ref": ind_id,
            "target_ref": malware_id
        })

    for url in iocs.get("url_indicators", []):
        ind_id = f"indicator--{uuid.uuid4()}"
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": ind_id,
            "created": now,
            "modified": now,
            "name": f"C2 URL Indicator: {url}",
            "pattern": f"[url:value = '{url}']",
            "pattern_type": "stix",
            "valid_from": now
        })
        objects.append({
            "type": "relationship",
            "spec_version": "2.1",
            "id": f"relationship--{uuid.uuid4()}",
            "created": now,
            "modified": now,
            "relationship_type": "indicates",
            "source_ref": ind_id,
            "target_ref": malware_id
        })

    for ip in iocs.get("ipv4_indicators", []):
        ind_id = f"indicator--{uuid.uuid4()}"
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": ind_id,
            "created": now,
            "modified": now,
            "name": f"C2 IPv4 Indicator: {ip}",
            "pattern": f"[ipv4-addr:value = '{ip}']",
            "pattern_type": "stix",
            "valid_from": now
        })
        objects.append({
            "type": "relationship",
            "spec_version": "2.1",
            "id": f"relationship--{uuid.uuid4()}",
            "created": now,
            "modified": now,
            "relationship_type": "indicates",
            "source_ref": ind_id,
            "target_ref": malware_id
        })

    return {
        "type": "bundle",
        "id": bundle_id,
        "objects": objects
    }


def extract_sample_strings(file_path: str, max_count: int = 150) -> list:
    if not os.path.exists(file_path) or not os.path.isfile(file_path):
        return []
    try:
        with open(file_path, "rb") as f:
            raw = f.read(500000)
        strings = []
        for m in re.finditer(rb'[\x20-\x7e]{4,}', raw):
            try:
                s = m.group().decode("ascii")
                strings.append({"offset": hex(m.start()), "type": "ASCII", "string": s})
            except Exception:
                pass
            if len(strings) >= max_count // 2:
                break
        for m in re.finditer(rb'(?:[\x20-\x7e]\x00){4,}', raw):
            try:
                s = m.group().decode("utf-16le")
                strings.append({"offset": hex(m.start()), "type": "WIDE/UTF-16", "string": s})
            except Exception:
                pass
            if len(strings) >= max_count:
                break
        return strings
    except Exception:
        return []


def generate_mitre_mapping(pe_info: dict, iocs: dict) -> list:
    techniques = []
    imports = pe_info.get("suspicious_imports", [])
    api_names = [i.get("api", "").lower() for i in imports]
    
    if any(x in api_names for x in ["virtualalloc", "virtualallocex", "createremotethread", "writeprocessmemory"]):
        techniques.append({
            "id": "T1055",
            "tactic": "Defense Evasion, Privilege Escalation",
            "name": "Process Injection",
            "evidence": "Observed memory allocation and remote thread creation APIs in import table.",
            "severity": "CRITICAL"
        })
    if any(x in api_names for x in ["createprocessa", "createprocessw", "winexec", "shellexecutew"]):
        techniques.append({
            "id": "T1106",
            "tactic": "Execution",
            "name": "Execution through Native API",
            "evidence": "Direct invocation of process spawning functions (e.g. ShellExecuteW/WinExec).",
            "severity": "HIGH"
        })
    if any(x in api_names for x in ["gettickcount", "isdebuggerpresent", "checkremotedebuggerpresent"]):
        techniques.append({
            "id": "T1082 / T1497",
            "tactic": "Discovery, Defense Evasion",
            "name": "System Info Discovery & Anti-Debugging",
            "evidence": "Timing checks (GetTickCount) and debugger state queries detected.",
            "severity": "MEDIUM"
        })
    if iocs.get("registry_keys"):
        techniques.append({
            "id": "T1547.001",
            "tactic": "Persistence, Privilege Escalation",
            "name": "Boot or Logon Autostart Execution: Registry Run Keys",
            "evidence": f"Embedded persistence key: {iocs['registry_keys'][0]}",
            "severity": "HIGH"
        })
    if iocs.get("url_indicators"):
        techniques.append({
            "id": "T1071.001",
            "tactic": "Command and Control",
            "name": "Application Layer Protocol: Web Protocols",
            "evidence": f"Found {len(iocs['url_indicators'])} HTTP/S C2 communication endpoints in binary.",
            "severity": "CRITICAL"
        })
        
    return techniques


async def analyze_file(request):
    """
    Executes full static triage analysis on a targeted sample.
    Supports file uploads or preselected file paths.
    """
    try:
        sample_path = DEFAULT_SAMPLE
        form = await request.form()
        
        # Check if a file was uploaded
        if "file" in form and hasattr(form["file"], "filename") and form["file"].filename:
            upload = form["file"]
            filename = os.path.basename(upload.filename)
            sample_path = os.path.join(UPLOAD_DIR, filename)
            with open(sample_path, "wb") as buffer:
                content = await upload.read()
                buffer.write(content)
        elif "preset_path" in form and form["preset_path"]:
            preset_path = str(form["preset_path"]).strip()
            if os.path.exists(preset_path):
                sample_path = preset_path

        # Extract Provider and AI Model preferences
        provider = str(form.get("provider", "gemini")).strip().lower()
        model = str(form.get("model", "")).strip() or None
        custom_key = str(form.get("api_key", "")).strip() or None
        base_url = str(form.get("base_url", "")).strip() or None

        preset_info = PROVIDER_PRESETS.get(provider) or PROVIDER_PRESETS.get("openrouter") or list(PROVIDER_PRESETS.values())[0]
        provider_display = f"{preset_info['name']} ({model or preset_info['default_model']})"

        # 1. Evaluate Containment Policy for all static actions
        tools_to_run = [
            ("get_file_hashes", get_file_hashes),
            ("calculate_entropy", calculate_entropy),
            ("analyze_pe_structure", analyze_pe_structure),
            ("extract_iocs", extract_iocs),
        ]

        policy_audit_log = []
        tool_results = {}

        for tool_name, tool_fn in tools_to_run:
            action = {"tool_name": tool_name, "args": {"file_path": sample_path}}
            decision = prevent_execution_hook(action)
            is_allowed = getattr(decision, "allow", getattr(decision, "allowed", True))
            reason = getattr(decision, "message", getattr(decision, "reason", ""))

            audit_entry = {
                "tool_name": tool_name,
                "allowed": is_allowed,
                "reason": reason or ("Authorized static analysis tool." if is_allowed else "Blocked by containment policy."),
                "file_path": sample_path,
            }
            policy_audit_log.append(audit_entry)

            if is_allowed:
                tool_results[tool_name] = tool_fn(sample_path)
            else:
                tool_results[tool_name] = {"status": "error", "message": reason}

        # 2. Extract Agent Thoughts customized with model display
        thoughts = [
            f"Target acquired: {os.path.basename(sample_path)}. Initializing Tier 2 static triage protocol.",
            f"Agent Engine: {provider_display}",
            "Invoking MalwSentinel: Extracting MD5 & SHA-256 cryptographic fingerprints.",
            "Computing Shannon Byte Entropy to determine packing, obfuscation, or encryption density.",
            "Parsing Windows PE structure: section sizes, raw data alignments, and suspicious Win32 API imports.",
            "Scanning byte streams for Indicators of Compromise (C2 IPv4 addresses, URLs, Registry keys).",
            "Synthesizing threat telemetry into final SOC Threat Intelligence Report.",
        ]

        h = tool_results.get("get_file_hashes", {})
        e = tool_results.get("calculate_entropy", {})
        p = tool_results.get("analyze_pe_structure", {})
        i = tool_results.get("extract_iocs", {})

        is_packed = e.get("is_likely_packed", False)
        suspicious_imports_count = len(p.get("suspicious_imports", []))
        ioc_count = len(i.get("ipv4_indicators", [])) + len(i.get("url_indicators", [])) + len(i.get("registry_keys", []))

        # Determine overall threat score (0 to 100)
        threat_score = 15
        if is_packed:
            threat_score += 35
        threat_score += min(suspicious_imports_count * 15, 40)
        threat_score += min(ioc_count * 10, 30)
        threat_score = min(threat_score, 98)

        threat_level = "CRITICAL" if threat_score >= 75 else "SUSPICIOUS" if threat_score >= 40 else "LOW"

        # 3. Generate Extended Threat Intelligence Assets
        yara_rule = generate_yara_rule(os.path.basename(sample_path), h, p, i)
        stix_bundle = generate_stix_bundle(os.path.basename(sample_path), h, i, threat_score, threat_level)
        sample_strings = extract_sample_strings(sample_path, max_count=150)
        mitre_matrix = generate_mitre_mapping(p, i)

        # 4. Invoke Multi-Provider AI Agent
        agent = UnifiedTriageAgent(
            provider=provider,
            model=model,
            api_key=custom_key,
            base_url=base_url,
        )
        ai_res = await agent.generate_triage_report(
            sample_path=sample_path,
            hashes=h,
            entropy=e,
            pe_info=p,
            iocs=i,
            mitre_matrix=mitre_matrix,
            threat_score=threat_score,
            threat_level=threat_level,
        )
        live_agent_report = ai_res.get("report_markdown", "")

        response_data = {
            "status": "success",
            "file_info": {
                "file_name": os.path.basename(sample_path),
                "file_path": sample_path,
                "file_size": os.path.getsize(sample_path) if os.path.exists(sample_path) else 0,
            },
            "threat_score": threat_score,
            "threat_level": threat_level,
            "thoughts": thoughts,
            "policy_audit": policy_audit_log,
            "ai_metadata": {
                "provider": agent.provider,
                "model": agent.model,
                "agent_note": ai_res.get("agent_note", ""),
            },
            "results": {
                "hashes": h,
                "entropy": e,
                "pe_structure": p,
                "iocs": i,
            },
            "yara_rule": yara_rule,
            "stix_bundle": stix_bundle,
            "sample_strings": sample_strings,
            "mitre_matrix": mitre_matrix,
            "report_markdown": live_agent_report,
        }

        return JSONResponse(response_data)

    except Exception as exc:
        return JSONResponse({"status": "error", "message": str(exc)}, status_code=500)


async def test_violation(request):
    """
    Simulates a dynamic execution attempt (e.g. os.system or run_command)
    to visually demonstrate that the prevent_execution_hook strictly intercepts and denies it.
    """
    try:
        data = await request.json()
    except Exception:
        data = {}

    attempted_action = data.get("action", {
        "tool_name": "run_command",
        "command": "powershell.exe -ExecutionPolicy Bypass -File ./suspicious_sample.exe"
    })

    # Evaluate action with prevent_execution_hook
    decision = prevent_execution_hook(attempted_action)
    is_allowed = getattr(decision, "allow", getattr(decision, "allowed", False))
    reason = getattr(decision, "message", getattr(decision, "reason", "Security policy violation"))

    return JSONResponse({
        "attempted_action": attempted_action,
        "allowed": is_allowed,
        "decision": "ALLOW" if is_allowed else "DENY",
        "message": reason if not is_allowed else "Action allowed.",
        "hook_name": "prevent_execution_hook",
        "enforcement_status": "CONTAINMENT ACTIVE"
    })


routes = [
    Route("/", home),
    Route("/api/presets", get_presets, methods=["GET"]),
    Route("/api/providers", get_providers, methods=["GET"]),
    Route("/api/analyze", analyze_file, methods=["POST"]),
    Route("/api/test-violation", test_violation, methods=["POST"]),
    Mount("/static", StaticFiles(directory=STATIC_DIR), name="static"),
]

middleware = [
    Middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
]

app = Starlette(debug=True, routes=routes, middleware=middleware)


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    print(f"[*] Starting MalwSentinel SOC Console at http://127.0.0.1:{port}")
    uvicorn.run("server:app", host="127.0.0.1", port=port, reload=False)
