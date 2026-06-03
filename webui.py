#!/usr/bin/env python3
"""
DFIRLlama-SIFT — Web UI
========================
Interfaz web local para usar DFIRLlama-SIFT desde el navegador.
Muestra el EIL corriendo en tiempo real via Server-Sent Events.

Uso:
    python3 webui.py             # http://localhost:7860
    python3 webui.py --port 8080
"""

import argparse
import json
import os
import queue
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, Response, jsonify, render_template_string, request

sys.path.insert(0, str(Path(__file__).parent))

app = Flask(__name__)
app.secret_key = os.urandom(24)

# ── HTML completo inline ──────────────────────────────────────────────────────

HTML = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DFIRLlama-SIFT</title>
<style>
  :root {
    --bg:      #0d1117;
    --bg2:     #161b22;
    --bg3:     #21262d;
    --border:  #30363d;
    --text:    #c9d1d9;
    --muted:   #8b949e;
    --green:   #3fb950;
    --yellow:  #d29922;
    --red:     #f85149;
    --cyan:    #58a6ff;
    --magenta: #bc8cff;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; }

  header {
    background: var(--bg2);
    border-bottom: 1px solid var(--border);
    padding: 14px 24px;
    display: flex; align-items: center; gap: 12px;
  }
  header h1 { font-size: 18px; font-weight: 600; color: var(--cyan); }
  header .badge {
    background: var(--bg3); border: 1px solid var(--border);
    border-radius: 12px; padding: 2px 10px; font-size: 11px; color: var(--muted);
  }

  .layout { display: grid; grid-template-columns: 340px 1fr; height: calc(100vh - 53px); }

  .sidebar {
    background: var(--bg2); border-right: 1px solid var(--border);
    padding: 20px; overflow-y: auto; display: flex; flex-direction: column; gap: 16px;
  }

  .card {
    background: var(--bg3); border: 1px solid var(--border);
    border-radius: 8px; padding: 16px;
  }
  .card h3 { font-size: 12px; font-weight: 600; color: var(--muted);
             text-transform: uppercase; letter-spacing: .05em; margin-bottom: 12px; }

  label { display: block; font-size: 13px; color: var(--muted); margin-bottom: 4px; }
  input, select, textarea {
    width: 100%; background: var(--bg); border: 1px solid var(--border);
    border-radius: 6px; padding: 8px 10px; color: var(--text); font-size: 13px;
    outline: none; transition: border-color .15s;
  }
  input:focus, select:focus, textarea:focus { border-color: var(--cyan); }
  textarea { min-height: 80px; resize: vertical; font-family: monospace; font-size: 12px; }

  .btn {
    width: 100%; padding: 10px; border: none; border-radius: 6px;
    font-size: 14px; font-weight: 600; cursor: pointer; transition: opacity .15s;
  }
  .btn:hover { opacity: .85; }
  .btn-primary { background: var(--cyan); color: #0d1117; }
  .btn-secondary { background: var(--bg3); border: 1px solid var(--border); color: var(--text); }
  .btn-danger { background: var(--red); color: white; }
  .btn:disabled { opacity: .4; cursor: not-allowed; }

  .tabs { display: flex; border-bottom: 1px solid var(--border); }
  .tab {
    padding: 10px 18px; font-size: 13px; cursor: pointer; color: var(--muted);
    border-bottom: 2px solid transparent; transition: all .15s;
  }
  .tab.active { color: var(--cyan); border-bottom-color: var(--cyan); }

  .tab-content { display: none; padding: 16px; height: calc(100% - 43px); overflow-y: auto; }
  .tab-content.active { display: block; }

  .main { display: flex; flex-direction: column; overflow: hidden; }

  #terminal {
    background: #010409; font-family: 'JetBrains Mono', 'Fira Code', monospace;
    font-size: 12.5px; line-height: 1.6; padding: 16px;
    overflow-y: auto; flex: 1;
    white-space: pre-wrap; word-break: break-all;
  }

  .log-thought   { color: #bc8cff; }
  .log-action    { color: #58a6ff; font-weight: bold; }
  .log-obs       { color: #6e7681; }
  .log-finding   { color: #f85149; font-weight: bold; }
  .log-success   { color: #3fb950; }
  .log-phase     { color: #e3b341; font-weight: bold; font-size: 13px; }
  .log-info      { color: #c9d1d9; }
  .log-error     { color: #f85149; }
  .log-dim       { color: #6e7681; }

  .results-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  .stat-card {
    background: var(--bg3); border: 1px solid var(--border);
    border-radius: 8px; padding: 14px; text-align: center;
  }
  .stat-num { font-size: 28px; font-weight: 700; }
  .stat-label { font-size: 11px; color: var(--muted); margin-top: 2px; }
  .stat-green .stat-num { color: var(--green); }
  .stat-yellow .stat-num { color: var(--yellow); }
  .stat-red .stat-num { color: var(--red); }
  .stat-cyan .stat-num { color: var(--cyan); }

  .technique-item {
    background: var(--bg3); border: 1px solid var(--border);
    border-radius: 6px; padding: 10px 12px; margin-bottom: 8px;
  }
  .technique-id { font-family: monospace; font-weight: bold; color: var(--yellow); }
  .technique-name { font-size: 13px; margin: 2px 0; }
  .technique-tactic { font-size: 11px; color: var(--muted); }
  .conf-high   { color: var(--red); }
  .conf-medium { color: var(--yellow); }
  .conf-low    { color: var(--muted); }

  .finding-item {
    border-left: 3px solid var(--border); padding: 8px 12px; margin-bottom: 6px;
    font-size: 12px;
  }
  .finding-item.high   { border-color: var(--red); }
  .finding-item.medium { border-color: var(--yellow); }
  .finding-item.confirmed { border-color: var(--green); }

  .nlsql-result {
    background: #010409; border: 1px solid var(--border); border-radius: 6px;
    padding: 12px; font-family: monospace; font-size: 12px; margin-top: 8px;
    max-height: 300px; overflow-y: auto;
  }
  .sql-code { color: var(--cyan); margin-bottom: 8px; padding: 8px;
              background: var(--bg3); border-radius: 4px; }

  .pulse { animation: pulse 1.5s infinite; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }

  .status-bar {
    background: var(--bg2); border-top: 1px solid var(--border);
    padding: 6px 16px; font-size: 11px; color: var(--muted);
    display: flex; justify-content: space-between;
  }
  #status-text.running { color: var(--yellow); }
  #status-text.done    { color: var(--green); }
  #status-text.error   { color: var(--red); }
</style>
</head>
<body>

<header>
  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#58a6ff" stroke-width="2">
    <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>
  </svg>
  <h1>DFIRLlama-SIFT</h1>
  <span class="badge">SANS FIND EVIL! 2026</span>
  <span class="badge" id="backend-badge">backend: auto</span>
</header>

<div class="layout">

  <!-- ── Sidebar ── -->
  <div class="sidebar">

    <div class="card">
      <h3>🔍 Evidence Interrogation Loop</h3>
      <div style="margin-bottom:10px">
        <label>Case directory</label>
        <input type="text" id="case-dir" placeholder="/cases/IR-2024-0622"
               value="demo/data">
      </div>
      <div style="margin-bottom:10px">
        <label>Incident ID</label>
        <input type="text" id="incident-id" placeholder="IR-2024-0622"
               value="">
      </div>
      <div style="margin-bottom:12px">
        <label>Start phase</label>
        <select id="start-phase">
          <option value="inventory">1 — Inventory</option>
          <option value="orient">2 — Orient</option>
          <option value="interrogate" selected>3 — Interrogate</option>
          <option value="enrich">4 — Enrich</option>
          <option value="validate">5 — Validate</option>
          <option value="report">6 — Report</option>
        </select>
      </div>
      <button class="btn btn-primary" id="btn-eil" onclick="startEIL()">
        ▶ Run EIL (full investigation)
      </button>
      <button class="btn btn-secondary" style="margin-top:6px" id="btn-demo" onclick="runDemo()">
        🎬 Demo mode (RDP compromise dataset)
      </button>
    </div>

    <div class="card">
      <h3>🔎 NL→SQL Query</h3>
      <div style="margin-bottom:8px">
        <label>SQLite DB path</label>
        <input type="text" id="nlsql-db" placeholder="/tmp/dfirllama_Security.db"
               value="demo/data/tslsm_demo.db">
      </div>
      <div style="margin-bottom:10px">
        <label>Forensic question</label>
        <textarea id="nlsql-q" placeholder="Did the administrator connect from external IPs?">Did the administrator connect from more than one IP on the same day?</textarea>
      </div>
      <button class="btn btn-primary" onclick="runNLSQL()">⚡ Run query</button>
    </div>

    <div class="card">
      <h3>🦠 IOC Analyzer</h3>
      <div style="margin-bottom:8px">
        <label>IOC value</label>
        <input type="text" id="ioc-value" placeholder="IP, domain, hash, PowerShell...">
      </div>
      <div style="margin-bottom:10px">
        <label>Type</label>
        <select id="ioc-type">
          <option value="auto">auto-detect</option>
          <option value="ip">IP address</option>
          <option value="domain">Domain</option>
          <option value="url">URL</option>
          <option value="hash">Hash (MD5/SHA256)</option>
          <option value="powershell">PowerShell command</option>
        </select>
      </div>
      <button class="btn btn-primary" onclick="analyzeIOC()">🔍 Investigate IOC</button>
    </div>

    <div class="card">
      <h3>⚙️ Config</h3>
      <div style="font-size:12px; color: var(--muted); line-height: 1.6">
        <div>Backend: <span id="cfg-backend" style="color:var(--cyan)">detecting...</span></div>
        <div>Model: <span id="cfg-model" style="color:var(--cyan)">-</span></div>
        <div>Evidence root: <span id="cfg-root" style="color:var(--cyan)">-</span></div>
      </div>
    </div>

  </div>

  <!-- ── Main panel ── -->
  <div class="main">
    <div class="tabs">
      <div class="tab active" onclick="switchTab('terminal')">Terminal</div>
      <div class="tab" onclick="switchTab('results')">Findings</div>
      <div class="tab" onclick="switchTab('mitre')">ATT&CK</div>
      <div class="tab" onclick="switchTab('nlsql-tab')">NL→SQL</div>
    </div>

    <div id="tab-terminal" class="tab-content active" style="padding:0; display:flex; flex-direction:column">
      <div id="terminal">[DFIRLlama-SIFT] Ready. Select a case directory and click Run EIL.

Shortcuts:
  • Run EIL      → full autonomous investigation (6 phases)
  • Demo mode    → uses synthetic RDP compromise dataset (1,800 events)
  • NL→SQL       → ask forensic questions in natural language
  • IOC Analyzer → investigate IPs, domains, hashes with ReAct agent

</div>
    </div>

    <div id="tab-results" class="tab-content">
      <div class="results-grid" id="stats-grid" style="margin-bottom:16px">
        <div class="stat-card stat-cyan">
          <div class="stat-num" id="stat-findings">-</div>
          <div class="stat-label">Total Findings</div>
        </div>
        <div class="stat-card stat-yellow">
          <div class="stat-num" id="stat-iocs">-</div>
          <div class="stat-label">IOCs Investigated</div>
        </div>
        <div class="stat-card stat-red">
          <div class="stat-num" id="stat-techniques">-</div>
          <div class="stat-label">ATT&CK Techniques</div>
        </div>
        <div class="stat-card stat-green">
          <div class="stat-num" id="stat-score">-</div>
          <div class="stat-label">Hallucination Score</div>
        </div>
      </div>
      <h3 style="font-size:13px;color:var(--muted);margin-bottom:8px">FINDINGS</h3>
      <div id="findings-list">
        <div style="color:var(--muted);font-size:13px">Run an investigation to see findings.</div>
      </div>
    </div>

    <div id="tab-mitre" class="tab-content">
      <div style="margin-bottom:12px; display:flex; justify-content:space-between; align-items:center">
        <h3 style="font-size:13px;color:var(--muted)">MITRE ATT&CK TECHNIQUES</h3>
        <button class="btn btn-secondary" style="width:auto;padding:6px 12px;font-size:12px"
                onclick="openNavigator()">Open in Navigator ↗</button>
      </div>
      <div id="mitre-list">
        <div style="color:var(--muted);font-size:13px">Run an investigation to see techniques.</div>
      </div>
    </div>

    <div id="tab-nlsql-tab" class="tab-content">
      <div id="nlsql-output">
        <div style="color:var(--muted);font-size:13px">Run an NL→SQL query to see results here.</div>
      </div>
    </div>

    <div class="status-bar">
      <span id="status-text">Ready</span>
      <span id="status-time"></span>
    </div>
  </div>
</div>

<script>
let navigatorLayer = null;
let eventSource    = null;

// ── Config ────────────────────────────────────────────────────────────────────
fetch('/api/config').then(r => r.json()).then(d => {
  document.getElementById('cfg-backend').textContent = d.backend;
  document.getElementById('cfg-model').textContent   = d.model;
  document.getElementById('cfg-root').textContent    = d.evidence_root;
  document.getElementById('backend-badge').textContent = 'backend: ' + d.backend;
});

// ── Tab switching ─────────────────────────────────────────────────────────────
function switchTab(name) {
  document.querySelectorAll('.tab').forEach((t,i) => {
    const ids = ['terminal','results','mitre','nlsql-tab'];
    t.classList.toggle('active', ids[i] === name);
    document.getElementById('tab-' + ids[i]).classList.toggle('active', ids[i] === name);
  });
}

// ── Terminal helpers ──────────────────────────────────────────────────────────
function termAppend(html) {
  const t = document.getElementById('terminal');
  t.innerHTML += html + '\n';
  t.scrollTop  = t.scrollHeight;
}
function termClear() {
  document.getElementById('terminal').innerHTML = '';
}

function formatLine(data) {
  const e = (s) => s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  const msg = e(data.msg || '');
  switch(data.type) {
    case 'phase':    return `<span class="log-phase">━━━ ${msg} ━━━</span>`;
    case 'thought':  return `<span class="log-thought">  Thought: ${msg}</span>`;
    case 'action':   return `<span class="log-action">  → ${msg}</span>`;
    case 'obs':      return `<span class="log-obs">    Obs: ${msg}</span>`;
    case 'finding':  return `<span class="log-finding">★ HALLAZGO: ${msg}</span>`;
    case 'success':  return `<span class="log-success">${msg}</span>`;
    case 'error':    return `<span class="log-error">[ERR] ${msg}</span>`;
    case 'dim':      return `<span class="log-dim">${msg}</span>`;
    default:         return `<span class="log-info">${msg}</span>`;
  }
}

// ── EIL ──────────────────────────────────────────────────────────────────────
function startEIL() { _runEIL(false); }
function runDemo()   { _runEIL(true); }

function _runEIL(demo) {
  if (eventSource) { eventSource.close(); eventSource = null; }

  const caseDir    = document.getElementById('case-dir').value.trim();
  const incidentId = document.getElementById('incident-id').value.trim() ||
                     'IR-' + new Date().toISOString().slice(0,10).replace(/-/g,'');
  const phase      = document.getElementById('start-phase').value;

  termClear();
  termAppend(`<span class="log-dim">[${new Date().toISOString().slice(11,19)} UTC] Starting EIL...</span>`);
  termAppend(`<span class="log-dim">Case: ${caseDir} | ID: ${incidentId} | Phase: ${phase} | Demo: ${demo}</span>\n`);

  setStatus('running', 'Investigating...');
  document.getElementById('btn-eil').disabled  = true;
  document.getElementById('btn-demo').disabled = true;

  const params = new URLSearchParams({
    case_dir: caseDir, incident_id: incidentId,
    start_phase: phase, demo: demo ? '1' : '0'
  });

  switchTab('terminal');
  eventSource = new EventSource('/api/eil/stream?' + params);

  eventSource.onmessage = (e) => {
    const data = JSON.parse(e.data);
    if (data.type === 'done') {
      handleDone(data);
    } else {
      termAppend(formatLine(data));
    }
  };

  eventSource.onerror = () => {
    termAppend('<span class="log-error">[SSE] Connection closed.</span>');
    setStatus('error', 'Error');
    resetButtons();
    if (eventSource) { eventSource.close(); eventSource = null; }
  };
}

function handleDone(data) {
  if (eventSource) { eventSource.close(); eventSource = null; }
  resetButtons();
  setStatus('done', `Done in ${data.elapsed}s`);

  const r = data.report || {};
  document.getElementById('stat-findings').textContent   = r.total_findings || 0;
  document.getElementById('stat-iocs').textContent       = r.iocs_investigated || 0;
  document.getElementById('stat-techniques').textContent = r.technique_count || 0;
  document.getElementById('stat-score').textContent      = r.hallucination_score != null ?
    (r.hallucination_score * 100).toFixed(1) + '%' : '-';

  // Findings tab
  const fl = document.getElementById('findings-list');
  fl.innerHTML = '';
  (r.findings || []).slice(0,20).forEach(f => {
    const conf = f.confidence || 'medium';
    const desc = (f.description || '').slice(0, 120);
    fl.innerHTML += `<div class="finding-item ${conf}">
      <span style="color:var(--muted);font-size:11px">[${f.phase || ''}] [${conf}]</span>
      <div>${desc}</div>
    </div>`;
  });

  // MITRE tab
  const ml = document.getElementById('mitre-list');
  ml.innerHTML = '';
  (r.mitre_techniques || []).forEach(t => {
    const conf = t.confidence || 'medium';
    ml.innerHTML += `<div class="technique-item">
      <div>
        <span class="technique-id">${t.technique_id || ''}</span>
        ${t.sub_technique ? '.' + t.sub_technique : ''}
        <span class="conf-${conf}" style="float:right;font-size:11px">${conf}</span>
      </div>
      <div class="technique-name">${t.technique_name || ''}</div>
      <div class="technique-tactic">${t.tactic || ''} — ${(t.evidence||'').slice(0,80)}</div>
    </div>`;
  });

  if (r.navigator_layer) {
    navigatorLayer = r.navigator_layer;
  }
}

function openNavigator() {
  if (!navigatorLayer) { alert('Run an investigation first.'); return; }
  const url  = 'https://mitre-attack.github.io/attack-navigator/';
  const data = encodeURIComponent(JSON.stringify(navigatorLayer));
  window.open(url + '#layerURL=data:application/json,' + data, '_blank');
}

// ── NL→SQL ────────────────────────────────────────────────────────────────────
function runNLSQL() {
  const db = document.getElementById('nlsql-db').value.trim();
  const q  = document.getElementById('nlsql-q').value.trim();
  if (!db || !q) { alert('Fill in DB path and question.'); return; }

  const out = document.getElementById('nlsql-output');
  out.innerHTML = '<div style="color:var(--yellow)" class="pulse">⚡ Running NL→SQL...</div>';
  switchTab('nlsql-tab');

  fetch('/api/nlsql', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({db_path: db, question: q})
  })
  .then(r => r.json())
  .then(data => {
    if (!data.ok) {
      out.innerHTML = `<div class="log-error">Error: ${data.error}</div>`;
      return;
    }
    const rows = data.results || [];
    let html = `<div style="margin-bottom:12px">
      <div style="font-size:12px;color:var(--muted);margin-bottom:6px">Question:</div>
      <div style="font-size:14px;font-weight:600">${data.question}</div>
    </div>
    <div class="sql-code">SQL: ${data.sql}</div>
    <div style="font-size:12px;color:var(--muted);margin-bottom:8px">
      ${data.row_count} rows returned</div>
    <div class="nlsql-result">`;
    if (rows.length === 0) {
      html += '<div style="color:var(--muted)">No results.</div>';
    } else {
      const cols = Object.keys(rows[0]);
      html += '<table style="width:100%;border-collapse:collapse">';
      html += '<tr>' + cols.map(c =>
        `<th style="text-align:left;padding:4px 8px;border-bottom:1px solid var(--border);
                    color:var(--muted);font-size:11px">${c}</th>`
      ).join('') + '</tr>';
      rows.forEach(row => {
        html += '<tr>' + cols.map(c =>
          `<td style="padding:4px 8px;border-bottom:1px solid #161b22;font-size:12px">
            ${String(row[c]||'').slice(0,100)}</td>`
        ).join('') + '</tr>';
      });
      html += '</table>';
    }
    html += '</div>';
    out.innerHTML = html;
  })
  .catch(e => {
    out.innerHTML = `<div class="log-error">Request failed: ${e}</div>`;
  });
}

// ── IOC Analyzer ──────────────────────────────────────────────────────────────
function analyzeIOC() {
  const ioc  = document.getElementById('ioc-value').value.trim();
  const type = document.getElementById('ioc-type').value;
  if (!ioc) { alert('Enter an IOC value.'); return; }

  switchTab('terminal');
  termAppend(`<span class="log-phase">━━━ IOC ANALYSIS: ${ioc} ━━━</span>`);
  termAppend(`<span class="log-dim">Type: ${type} | Starting ReAct agent...</span>`);
  setStatus('running', 'Analyzing IOC...');

  fetch('/api/ioc', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ioc_value: ioc, ioc_type: type})
  })
  .then(r => r.json())
  .then(data => {
    if (data.ok) {
      (data.tool_calls || []).forEach(tc => {
        termAppend(`<span class="log-action">  → ${tc.tool}(${JSON.stringify(tc.args).slice(0,60)})</span>`);
        termAppend(`<span class="log-obs">    Obs: ${String(tc.result).slice(0,120)}</span>`);
      });
      termAppend(`<span class="log-success">\nVERDICT:\n${data.verdict}</span>`);
      setStatus('done', `IOC analyzed (${data.iterations} iterations)`);
    } else {
      termAppend(`<span class="log-error">Error: ${data.error}</span>`);
      setStatus('error', 'IOC analysis failed');
    }
  })
  .catch(e => {
    termAppend(`<span class="log-error">Request failed: ${e}</span>`);
    setStatus('error', 'Error');
  });
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function setStatus(state, msg) {
  const el = document.getElementById('status-text');
  el.textContent  = msg;
  el.className    = state;
  document.getElementById('status-time').textContent =
    new Date().toISOString().slice(11,19) + ' UTC';
}

function resetButtons() {
  document.getElementById('btn-eil').disabled  = false;
  document.getElementById('btn-demo').disabled = false;
}
</script>
</body>
</html>
"""

# ── Flask routes ──────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(HTML)


@app.route("/api/config")
def api_config():
    from llm.client import get_model_name, _get_backend
    return jsonify({
        "backend":       _get_backend(),
        "model":         get_model_name(),
        "evidence_root": os.getenv("EVIDENCE_ROOT", "/cases"),
    })


@app.route("/api/nlsql", methods=["POST"])
def api_nlsql():
    data = request.json or {}
    db   = data.get("db_path", "")
    q    = data.get("question", "")
    if not db or not q:
        return jsonify({"ok": False, "error": "db_path and question required"})
    from tools.nlsql import query_nl
    return jsonify(query_nl(db, q))


@app.route("/api/ioc", methods=["POST"])
def api_ioc():
    data = request.json or {}
    ioc  = data.get("ioc_value", "")
    typ  = data.get("ioc_type", "auto")
    if not ioc:
        return jsonify({"ok": False, "error": "ioc_value required"})
    from tools.ioc_tools import analyze_ioc
    return jsonify(analyze_ioc(ioc, typ))


@app.route("/api/eil/stream")
def api_eil_stream():
    """
    Server-Sent Events stream del EIL.
    Captura stdout del agente y lo convierte en eventos SSE estructurados.
    """
    case_dir    = request.args.get("case_dir", "demo/data")
    incident_id = request.args.get("incident_id", f"IR-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M')}")
    start_phase = request.args.get("start_phase", "inventory")
    demo        = request.args.get("demo", "0") == "1"

    if demo:
        demo_db = Path(__file__).parent / "demo" / "data" / "tslsm_demo.db"
        case_dir = str(demo_db.parent)

    msg_queue: queue.Queue = queue.Queue()

    def run_agent():
        """Corre el agente en un thread y mete eventos en la queue."""
        import io, contextlib

        # Monkey-patch para capturar prints del agente
        class QueueWriter(io.TextIOBase):
            def write(self, s):
                for line in s.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    msg_type = _classify_line(line)
                    msg_queue.put({"type": msg_type, "msg": _strip_ansi(line)})
                return len(s)
            def flush(self): pass

        old_stdout = sys.stdout
        sys.stdout = QueueWriter()
        try:
            from agent import EILAgent
            a = EILAgent(case_dir=case_dir, output_dir="./analysis")
            report = a.run(incident_id=incident_id, start_phase=start_phase)
            msg_queue.put({"type": "done", "report": _jsonify_report(report),
                           "elapsed": "?"})
        except Exception as e:
            msg_queue.put({"type": "error", "msg": str(e)})
            msg_queue.put({"type": "done", "report": {}, "elapsed": "?"})
        finally:
            sys.stdout = old_stdout

    thread = threading.Thread(target=run_agent, daemon=True)
    thread.start()

    def generate():
        while True:
            try:
                item = msg_queue.get(timeout=120)
                yield f"data: {json.dumps(item, ensure_ascii=False)}\n\n"
                if item.get("type") == "done":
                    break
            except queue.Empty:
                yield f"data: {json.dumps({'type':'error','msg':'Timeout'})}\n\n"
                break

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache",
                             "X-Accel-Buffering": "no"})


# ── Helpers ───────────────────────────────────────────────────────────────────

def _classify_line(line: str) -> str:
    l = line.lower()
    if "━" in line or "fase" in l or "phase" in l or "inventory" in l \
            or "orient" in l or "interrogate" in l or "enrich" in l \
            or "validate" in l or "report" in l:
        return "phase"
    if "thought:" in l:
        return "thought"
    if line.strip().startswith("→") or "action:" in l:
        return "action"
    if "obs:" in l or "observation:" in l:
        return "obs"
    if "hallazgo" in l or "★" in line or "finding" in l:
        return "finding"
    if any(w in l for w in ["ok", "completo", "listo", "guardado", "done", "✓"]):
        return "success"
    if "error" in l or "fail" in l:
        return "error"
    if line.startswith("[") or "dim" in l:
        return "dim"
    return "info"


import re as _re
_ANSI = _re.compile(r"\x1b\[[0-9;]*m")

def _strip_ansi(s: str) -> str:
    return _ANSI.sub("", s)


def _jsonify_report(report: dict) -> dict:
    """Limpia el reporte para que sea JSON serializable."""
    try:
        return json.loads(json.dumps(report, default=str))
    except Exception:
        return {"total_findings": 0, "technique_count": 0}


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description="DFIRLlama-SIFT Web UI")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=7860)
    p.add_argument("--public", action="store_true",
                   help="Bind to 0.0.0.0 (solo en redes de confianza)")
    args = p.parse_args()

    host = "0.0.0.0" if args.public else args.host
    print(f"[*] DFIRLlama-SIFT Web UI → http://{args.host}:{args.port}")
    print(f"[*] Evidence root: {os.getenv('EVIDENCE_ROOT', '/cases')}")
    print(f"[*] Press Ctrl+C to stop")
    app.run(host=host, port=args.port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
