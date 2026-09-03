/* ==========================================================================
   MALWSENTINEL // CLIENT APPLICATION LOGIC
   ========================================================================== */

document.addEventListener('DOMContentLoaded', () => {
  // State
  let currentFile = null;
  let currentPresetId = 'suspicious_sample';
  let activeIocTab = 'ips';
  let lastAnalysisData = null;
  let availableProviders = {};

  let aiSettings = {
    provider: 'gemini',
    model: 'gemini-2.5-flash',
    base_url: 'https://generativelanguage.googleapis.com',
    api_key: '',
  };

  try {
    const saved = localStorage.getItem('malwsentinel_ai_settings');
    if (saved) {
      aiSettings = Object.assign(aiSettings, JSON.parse(saved));
    }
  } catch (e) {}

  // DOM Elements
  const dropZone = document.getElementById('dropZone');
  const fileInput = document.getElementById('fileInput');
  const currentTargetText = document.getElementById('currentTargetText');
  const targetSizeText = document.getElementById('targetSizeText');
  const startAnalysisBtn = document.getElementById('startAnalysisBtn');
  const analysisSpinner = document.getElementById('analysisSpinner');
  const presetButtonsContainer = document.getElementById('presetButtonsContainer');

  // Terminal & Audit
  const terminalOutput = document.getElementById('terminalOutput');
  const auditList = document.getElementById('auditList');
  const auditCounter = document.getElementById('auditCounter');

  // Overview & Hashes
  const threatScoreNum = document.getElementById('threatScoreNum');
  const dialFill = document.getElementById('dialFill');
  const threatLevelBadge = document.getElementById('threatLevelBadge');
  const statPacking = document.getElementById('statPacking');
  const statApis = document.getElementById('statApis');
  const statIocs = document.getElementById('statIocs');
  const md5Val = document.getElementById('md5Val');
  const sha256Val = document.getElementById('sha256Val');

  // Entropy & Sections
  const entropyNumeric = document.getElementById('entropyNumeric');
  const entropyFill = document.getElementById('entropyFill');
  const entropyAnalysisText = document.getElementById('entropyAnalysisText');
  const sectionsCount = document.getElementById('sectionsCount');
  const peSectionsContainer = document.getElementById('peSectionsContainer');

  // Imports & IoCs
  const suspiciousCountBadge = document.getElementById('suspiciousCountBadge');
  const suspiciousImportsContainer = document.getElementById('suspiciousImportsContainer');
  const iocTabs = document.querySelectorAll('.ioc-tab-btn');
  const ipCount = document.getElementById('ipCount');
  const urlCount = document.getElementById('urlCount');
  const regCount = document.getElementById('regCount');
  const iocList = document.getElementById('iocList');
  const exportIocsBtn = document.getElementById('exportIocsBtn');

  // Report & Violation Modal
  const reportContentArea = document.getElementById('reportContentArea');
  const copyReportBtn = document.getElementById('copyReportBtn');
  const testViolationBtn = document.getElementById('testViolationBtn');
  const violationModal = document.getElementById('violationModal');
  const closeModalBtn = document.getElementById('closeModalBtn');
  const acknowledgeModalBtn = document.getElementById('acknowledgeModalBtn');
  const modalResultText = document.getElementById('modalResultText');

  // Extended Toolkit Elements & Modals
  const openYaraBtn = document.getElementById('openYaraBtn');
  const yaraModal = document.getElementById('yaraModal');
  const closeYaraModalBtn = document.getElementById('closeYaraModalBtn');
  const copyYaraBtn = document.getElementById('copyYaraBtn');
  const downloadYaraBtn = document.getElementById('downloadYaraBtn');
  const yaraCodeBlock = document.getElementById('yaraCodeBlock');

  const exportStixBtn = document.getElementById('exportStixBtn');

  const openStringsBtn = document.getElementById('openStringsBtn');
  const stringsModal = document.getElementById('stringsModal');
  const closeStringsModalBtn = document.getElementById('closeStringsModalBtn');
  const closeStringsBottomBtn = document.getElementById('closeStringsBottomBtn');
  const stringsSearchInput = document.getElementById('stringsSearchInput');
  const stringsFilteredCount = document.getElementById('stringsFilteredCount');
  const stringsTableBody = document.getElementById('stringsTableBody');
  const copyStringsBtn = document.getElementById('copyStringsBtn');

  const printReportBtn = document.getElementById('printReportBtn');
  const mitreMatrixContainer = document.getElementById('mitreMatrixContainer');
  const mitreCountBadge = document.getElementById('mitreCountBadge');

  // AI Model Settings Elements
  const openModelSettingsBtn = document.getElementById('openModelSettingsBtn');
  const modelStatus = document.getElementById('modelStatus');
  const modelSettingsModal = document.getElementById('modelSettingsModal');
  const closeModelModalBtn = document.getElementById('closeModelModalBtn');
  const cancelModelModalBtn = document.getElementById('cancelModelModalBtn');
  const saveModelSettingsBtn = document.getElementById('saveModelSettingsBtn');
  const providerSelect = document.getElementById('providerSelect');
  const modelNameInput = document.getElementById('modelNameInput');
  const baseUrlInput = document.getElementById('baseUrlInput');
  const apiKeyInput = document.getElementById('apiKeyInput');
  const toggleKeyVisibilityBtn = document.getElementById('toggleKeyVisibilityBtn');
  const envKeyStatusText = document.getElementById('envKeyStatusText');

  // Preset Mapping
  const presetMap = {
    'suspicious_sample': {
      name: 'Simulated Backdoor Loader',
      path: './suspicious_sample.exe'
    },
    'clean_calc': {
      name: 'Clean Windows Binary (calc.exe)',
      path: 'C:\\Windows\\System32\\calc.exe'
    }
  };

  // ------------------------------------------------------------------------
  // Preset Selection Handlers
  // ------------------------------------------------------------------------
  presetButtonsContainer.addEventListener('click', (e) => {
    const btn = e.target.closest('.preset-btn');
    if (!btn) return;

    document.querySelectorAll('.preset-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');

    currentPresetId = btn.dataset.presetId;
    currentFile = null;
    fileInput.value = '';

    const preset = presetMap[currentPresetId];
    if (preset) {
      currentTargetText.textContent = preset.path;
      targetSizeText.textContent = 'Demo Sample';
      logTerminal(`Target selected from presets: ${preset.name} (${preset.path})`, 'cyan');
    }
  });

  // ------------------------------------------------------------------------
  // File Ingestion & Drag/Drop
  // ------------------------------------------------------------------------
  dropZone.addEventListener('click', () => fileInput.click());

  dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('dragover');
  });

  dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('dragover');
  });

  dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleSelectedFile(e.dataTransfer.files[0]);
    }
  });

  fileInput.addEventListener('change', (e) => {
    if (e.target.files && e.target.files.length > 0) {
      handleSelectedFile(e.target.files[0]);
    }
  });

  function handleSelectedFile(file) {
    currentFile = file;
    document.querySelectorAll('.preset-btn').forEach(b => b.classList.remove('active'));
    currentTargetText.textContent = file.name;
    const sizeKb = (file.size / 1024).toFixed(1);
    targetSizeText.textContent = `${sizeKb} KB`;
    logTerminal(`Custom binary staged for triage: ${file.name} (${sizeKb} KB)`, 'cyan');
  }

  // ------------------------------------------------------------------------
  // Terminal Logging Helper
  // ------------------------------------------------------------------------
  function logTerminal(text, type = 'normal') {
    const line = document.createElement('div');
    line.className = 'terminal-line';

    const timestamp = new Date().toISOString().split('T')[1].slice(0, 8);
    const timeSpan = document.createElement('span');
    timeSpan.className = 'text-dim';
    timeSpan.textContent = `[${timestamp}] `;
    line.appendChild(timeSpan);

    const msgSpan = document.createElement('span');
    if (type === 'cyan') msgSpan.className = 'text-cyan';
    else if (type === 'emerald') msgSpan.className = 'text-emerald';
    else if (type === 'crimson') msgSpan.className = 'text-crimson';
    else if (type === 'amber') msgSpan.className = 'text-amber';

    msgSpan.textContent = text;
    line.appendChild(msgSpan);

    terminalOutput.appendChild(line);
    terminalOutput.scrollTop = terminalOutput.scrollHeight;
  }

  // ------------------------------------------------------------------------
  // Execute Analysis
  // ------------------------------------------------------------------------
  startAnalysisBtn.addEventListener('click', runTriage);

  async function runTriage() {
    startAnalysisBtn.disabled = true;
    analysisSpinner.classList.remove('hidden');

    logTerminal('=== STARTING MALWSENTINEL TIER-2 STATIC TRIAGE PROTOCOL ===', 'cyan');

    const formData = new FormData();
    if (currentFile) {
      formData.append('file', currentFile);
    } else {
      const preset = presetMap[currentPresetId];
      formData.append('preset_path', preset ? preset.path : './suspicious_sample.exe');
    }

    // Attach active AI Agent settings
    formData.append('provider', aiSettings.provider || 'gemini');
    if (aiSettings.model) formData.append('model', aiSettings.model);
    if (aiSettings.base_url) formData.append('base_url', aiSettings.base_url);
    if (aiSettings.api_key) formData.append('api_key', aiSettings.api_key);

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        throw new Error(`Server returned HTTP ${response.status}`);
      }

      const data = await response.json();
      lastAnalysisData = data;

      // Animate thought traces in terminal
      if (data.thoughts && Array.isArray(data.thoughts)) {
        for (const thought of data.thoughts) {
          logTerminal(`[Thought] ${thought}`, 'cyan');
          await sleep(180);
        }
      }

      // Render all metrics
      renderTriageResults(data);
      logTerminal('Static analysis and Threat Intelligence report completed successfully.', 'emerald');

    } catch (err) {
      logTerminal(`ERROR during triage: ${err.message}`, 'crimson');
      alert(`Analysis failed: ${err.message}`);
    } finally {
      startAnalysisBtn.disabled = false;
      analysisSpinner.classList.add('hidden');
    }
  }

  function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // ------------------------------------------------------------------------
  // Render Telemetry & Cards
  // ------------------------------------------------------------------------
  function renderTriageResults(data) {
    const results = data.results || {};
    const hashes = results.hashes || {};
    const entropy = results.entropy || {};
    const pe = results.pe_structure || {};
    const iocs = results.iocs || {};

    // 1. Overall Severity Score Dial
    const score = data.threat_score || 0;
    threatScoreNum.textContent = score;

    // Circumference of r=42 is ~264
    const offset = 264 - (score / 100) * 264;
    dialFill.style.strokeDashoffset = offset;

    if (score >= 70) {
      dialFill.style.stroke = 'var(--accent-crimson)';
      threatLevelBadge.className = 'threat-badge badge-critical';
      threatLevelBadge.textContent = 'CRITICAL THREAT';
    } else if (score >= 35) {
      dialFill.style.stroke = 'var(--accent-amber)';
      threatLevelBadge.className = 'threat-badge badge-suspicious';
      threatLevelBadge.textContent = 'SUSPICIOUS / ELEVATED';
    } else {
      dialFill.style.stroke = 'var(--accent-emerald)';
      threatLevelBadge.className = 'threat-badge badge-clean';
      threatLevelBadge.textContent = 'LOW RISK / BENIGN';
    }

    // Quick Stats
    statPacking.textContent = entropy.is_likely_packed ? 'PACKED (YES)' : 'UNPACKED (NO)';
    statApis.textContent = (pe.suspicious_imports || []).length;
    const totalIocs = (iocs.ipv4_indicators || []).length + (iocs.url_indicators || []).length + (iocs.registry_keys || []).length;
    statIocs.textContent = totalIocs;

    // 2. Cryptographic Hashes
    md5Val.textContent = hashes.md5 || 'N/A';
    sha256Val.textContent = hashes.sha256 || 'N/A';

    // 3. Shannon Byte Entropy
    const entVal = entropy.entropy || 0.0;
    entropyNumeric.textContent = `${entVal.toFixed(4)} / 8.0000`;
    const pct = Math.min((entVal / 8.0) * 100, 100);
    entropyFill.style.width = `${pct}%`;
    entropyAnalysisText.textContent = entropy.analysis || 'Analysis complete.';

    // 4. PE Section Map
    renderPeSections(pe.sections || []);

    // 5. Suspicious Imports
    renderSuspiciousImports(pe.suspicious_imports || []);

    // 5b. MITRE ATT&CK Matrix Mapping
    renderMitreMatrix(data.mitre_matrix || []);

    // 6. Indicators of Compromise (IoCs)
    ipCount.textContent = (iocs.ipv4_indicators || []).length;
    urlCount.textContent = (iocs.url_indicators || []).length;
    regCount.textContent = (iocs.registry_keys || []).length;
    renderIocTabContent(activeIocTab);

    // 7. Policy Audit Log
    renderPolicyAudit(data.policy_audit || []);

    // 8. Report View
    renderReport(data.report_markdown || 'No report synthesized.');
  }

  function renderPeSections(sections) {
    sectionsCount.textContent = `${sections.length} Sections`;
    peSectionsContainer.innerHTML = '';

    if (!sections || sections.length === 0) {
      peSectionsContainer.innerHTML = '<div class="sections-empty">No PE sections identified (Non-PE or packed format).</div>';
      return;
    }

    // Proportional Visual Bar
    const barWrap = document.createElement('div');
    barWrap.className = 'sections-bar-wrap';

    const totalRaw = sections.reduce((acc, s) => acc + (s.raw_size || 1), 0) || 1;
    const colors = ['#00f0ff', '#3b82f6', '#8b5cf6', '#ec4899', '#10b981', '#f59e0b', '#06b6d4'];

    sections.forEach((sec, idx) => {
      const slice = document.createElement('div');
      slice.className = 'sec-bar-slice';
      const widthPct = Math.max(((sec.raw_size || 1) / totalRaw) * 100, 8);
      slice.style.width = `${widthPct}%`;
      slice.style.background = colors[idx % colors.length];
      slice.textContent = sec.name;
      slice.title = `${sec.name}: Raw ${sec.raw_size}B, Entropy ${sec.entropy}`;
      barWrap.appendChild(slice);
    });

    peSectionsContainer.appendChild(barWrap);

    // Detailed Table
    const table = document.createElement('table');
    table.className = 'sections-table';
    table.innerHTML = `
      <thead>
        <tr>
          <th>Section</th>
          <th>Virtual Addr</th>
          <th>Virtual Size</th>
          <th>Raw Size</th>
          <th>Entropy</th>
        </tr>
      </thead>
      <tbody>
        ${sections.map(s => {
          const isSusp = s.is_suspicious_entropy;
          const pillClass = isSusp ? 'sec-entropy-pill sec-entropy-high' : 'sec-entropy-pill sec-entropy-normal';
          return `
            <tr>
              <td><strong style="color: #fff;">${s.name}</strong></td>
              <td>${s.virtual_address}</td>
              <td>${s.virtual_size} B</td>
              <td>${s.raw_size} B</td>
              <td><span class="${pillClass}">${s.entropy.toFixed(3)}</span></td>
            </tr>
          `;
        }).join('')}
      </tbody>
    `;
    peSectionsContainer.appendChild(table);
  }

  function renderSuspiciousImports(imports) {
    suspiciousCountBadge.textContent = `${imports.length} detected`;
    suspiciousImportsContainer.innerHTML = '';

    if (!imports || imports.length === 0) {
      suspiciousImportsContainer.innerHTML = '<div class="tags-empty">No suspicious Win32 API calls flagged in import table.</div>';
      return;
    }

    imports.forEach(imp => {
      const pill = document.createElement('div');
      pill.className = 'suspicious-pill';
      pill.innerHTML = `
        <span class="pill-cat">${imp.category || 'General'}</span>
        <span class="pill-api">${imp.api}</span>
        <span class="pill-dll">(${imp.dll})</span>
      `;
      suspiciousImportsContainer.appendChild(pill);
    });
  }

  function renderMitreMatrix(matrix) {
    mitreCountBadge.textContent = `${matrix.length} mapped`;
    mitreMatrixContainer.innerHTML = '';

    if (!matrix || matrix.length === 0) {
      mitreMatrixContainer.innerHTML = '<div class="tags-empty">No suspicious capabilities mapped to MITRE ATT&CK for this sample.</div>';
      return;
    }

    matrix.forEach(tech => {
      const card = document.createElement('div');
      card.className = 'mitre-card';
      card.innerHTML = `
        <div class="mitre-header">
          <div style="display: flex; align-items: center; gap: 8px;">
            <span class="mitre-tech-id">${tech.id}</span>
            <span class="mitre-tech-name">${tech.name}</span>
          </div>
          <span class="mitre-tactic-pill">${tech.tactic}</span>
        </div>
        <div class="mitre-evidence">
          <strong>Evidence:</strong> ${escapeHtml(tech.evidence)}
        </div>
      `;
      mitreMatrixContainer.appendChild(card);
    });
  }

  // ------------------------------------------------------------------------
  // IoC Explorer Tabs
  // ------------------------------------------------------------------------
  iocTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      iocTabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      activeIocTab = tab.dataset.tab;
      renderIocTabContent(activeIocTab);
    });
  });

  function renderIocTabContent(tabKey) {
    iocList.innerHTML = '';
    const iocs = (lastAnalysisData && lastAnalysisData.results && lastAnalysisData.results.iocs) || {};

    let items = [];
    if (tabKey === 'ips') items = iocs.ipv4_indicators || [];
    else if (tabKey === 'urls') items = iocs.url_indicators || [];
    else if (tabKey === 'registry') items = iocs.registry_keys || [];

    if (!items || items.length === 0) {
      iocList.innerHTML = `<div class="ioc-empty">No ${tabKey} indicators detected in this sample.</div>`;
      return;
    }

    items.forEach(val => {
      const item = document.createElement('div');
      item.className = 'ioc-item';
      item.innerHTML = `
        <span class="ioc-val">${escapeHtml(val)}</span>
        <button class="copy-btn" title="Copy to clipboard">📋</button>
      `;
      const copyBtn = item.querySelector('.copy-btn');
      copyBtn.addEventListener('click', () => copyToClipboard(val, copyBtn));
      iocList.appendChild(item);
    });
  }

  exportIocsBtn.addEventListener('click', () => {
    const iocs = (lastAnalysisData && lastAnalysisData.results && lastAnalysisData.results.iocs) || {};
    const blob = new Blob([JSON.stringify(iocs, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `iocs_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  });

  // ------------------------------------------------------------------------
  // Policy Audit Log
  // ------------------------------------------------------------------------
  function renderPolicyAudit(auditLog) {
    auditCounter.textContent = `${auditLog.length} checks`;
    auditList.innerHTML = '';

    if (!auditLog || auditLog.length === 0) {
      auditList.innerHTML = '<div class="audit-empty">No policy checks recorded.</div>';
      return;
    }

    auditLog.forEach(entry => {
      const item = document.createElement('div');
      item.className = `audit-item ${entry.allowed ? 'allowed' : 'denied'}`;
      item.innerHTML = `
        <div>
          <div class="audit-tool-name">${entry.tool_name}()</div>
          <div class="text-dim" style="font-size: 11px;">${entry.reason}</div>
        </div>
        <span class="audit-pill ${entry.allowed ? 'pill-allow' : 'pill-deny'}">
          ${entry.allowed ? 'ALLOWED' : 'BLOCKED'}
        </span>
      `;
      auditList.appendChild(item);
    });
  }

  // ------------------------------------------------------------------------
  // Report Viewer & Clipboard
  // ------------------------------------------------------------------------
  function renderReport(markdown) {
    // Simple markdown conversion for executive report
    let html = markdown
      .replace(/^### (.*$)/gim, '<h3>$1</h3>')
      .replace(/^## (.*$)/gim, '<h2>$1</h2>')
      .replace(/^# (.*$)/gim, '<h1>$1</h1>')
      .replace(/\*\*(.*?)\*\*/gim, '<strong>$1</strong>')
      .replace(/\*(.*?)\*/gim, '<em>$1</em>')
      .replace(/`([^`]+)`/gim, '<code>$1</code>')
      .replace(/^\s*\n\*/gm, '<ul>\n*')
      .replace(/^(\*.+)\s*\n([^\*])/gm, '$1\n</ul>\n\n$2')
      .replace(/^\*(.+)/gm, '<li>$1</li>')
      .replace(/\n\n/gim, '<br><br>');

    reportContentArea.innerHTML = html;
  }

  copyReportBtn.addEventListener('click', () => {
    if (lastAnalysisData && lastAnalysisData.report_markdown) {
      copyToClipboard(lastAnalysisData.report_markdown, copyReportBtn);
    }
  });

  // ------------------------------------------------------------------------
  // Generic Copy Button Event Delegation
  // ------------------------------------------------------------------------
  document.querySelectorAll('.copy-btn[data-copy-target]').forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.dataset.copyTarget;
      const el = document.getElementById(targetId);
      if (el) {
        copyToClipboard(el.textContent.trim(), btn);
      }
    });
  });

  function copyToClipboard(text, btnElement) {
    navigator.clipboard.writeText(text).then(() => {
      const orig = btnElement.textContent;
      btnElement.textContent = '✅';
      setTimeout(() => { btnElement.textContent = orig; }, 1500);
    }).catch(err => {
      console.error('Failed to copy text: ', err);
    });
  }

  function escapeHtml(str) {
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  // ------------------------------------------------------------------------
  // Security Violation Demo Modal Handler
  // ------------------------------------------------------------------------
  testViolationBtn.addEventListener('click', async () => {
    try {
      const res = await fetch('/api/test-violation', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: {
            tool_name: 'run_command',
            command: 'subprocess.Popen(["./suspicious_sample.exe"])'
          }
        })
      });

      const result = await res.json();
      violationModal.classList.remove('hidden');

      logTerminal('SECURITY EVENT: Dynamic execution attempt triggered by user test.', 'crimson');
      logTerminal(`Hook Decision: DENY - ${result.message}`, 'crimson');

    } catch (err) {
      alert(`Failed to test policy hook: ${err.message}`);
    }
  });

  closeModalBtn.addEventListener('click', () => violationModal.classList.add('hidden'));
  acknowledgeModalBtn.addEventListener('click', () => violationModal.classList.add('hidden'));
  violationModal.addEventListener('click', (e) => {
    if (e.target === violationModal) violationModal.classList.add('hidden');
  });

  // ------------------------------------------------------------------------
  // YARA Rule Modal Handlers
  // ------------------------------------------------------------------------
  openYaraBtn.addEventListener('click', () => {
    if (lastAnalysisData && lastAnalysisData.yara_rule) {
      yaraCodeBlock.textContent = lastAnalysisData.yara_rule;
    } else {
      yaraCodeBlock.textContent = '/* Please run triage first to generate a YARA rule for this binary */';
    }
    yaraModal.classList.remove('hidden');
  });

  closeYaraModalBtn.addEventListener('click', () => yaraModal.classList.add('hidden'));
  yaraModal.addEventListener('click', (e) => {
    if (e.target === yaraModal) yaraModal.classList.add('hidden');
  });

  copyYaraBtn.addEventListener('click', () => {
    if (lastAnalysisData && lastAnalysisData.yara_rule) {
      copyToClipboard(lastAnalysisData.yara_rule, copyYaraBtn);
    }
  });

  downloadYaraBtn.addEventListener('click', () => {
    if (lastAnalysisData && lastAnalysisData.yara_rule) {
      const fileName = (lastAnalysisData.file_info && lastAnalysisData.file_info.file_name) || 'sample';
      const clean = fileName.replace(/[^a-zA-Z0-9_]/g, '_');
      const blob = new Blob([lastAnalysisData.yara_rule], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${clean}_detection.yar`;
      a.click();
      URL.revokeObjectURL(url);
    }
  });

  // ------------------------------------------------------------------------
  // STIX 2.1 Threat Intel Export
  // ------------------------------------------------------------------------
  exportStixBtn.addEventListener('click', () => {
    if (lastAnalysisData && lastAnalysisData.stix_bundle) {
      const fileName = (lastAnalysisData.file_info && lastAnalysisData.file_info.file_name) || 'sample';
      const clean = fileName.replace(/[^a-zA-Z0-9_]/g, '_');
      const blob = new Blob([JSON.stringify(lastAnalysisData.stix_bundle, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `stix21_${clean}_bundle.json`;
      a.click();
      URL.revokeObjectURL(url);
    } else {
      alert('Please run static triage first to generate STIX 2.1 telemetry.');
    }
  });

  // ------------------------------------------------------------------------
  // Strings Inspector Modal Handlers
  // ------------------------------------------------------------------------
  openStringsBtn.addEventListener('click', () => {
    stringsModal.classList.remove('hidden');
    stringsSearchInput.value = '';
    renderStringsTable('');
  });

  closeStringsModalBtn.addEventListener('click', () => stringsModal.classList.add('hidden'));
  closeStringsBottomBtn.addEventListener('click', () => stringsModal.classList.add('hidden'));
  stringsModal.addEventListener('click', (e) => {
    if (e.target === stringsModal) stringsModal.classList.add('hidden');
  });

  stringsSearchInput.addEventListener('input', (e) => {
    renderStringsTable(e.target.value);
  });

  function renderStringsTable(filterTerm = '') {
    stringsTableBody.innerHTML = '';
    const allStrings = (lastAnalysisData && lastAnalysisData.sample_strings) || [];
    const term = filterTerm.toLowerCase().trim();

    const filtered = term
      ? allStrings.filter(s => s.string.toLowerCase().includes(term) || s.type.toLowerCase().includes(term))
      : allStrings;

    stringsFilteredCount.textContent = `${filtered.length} of ${allStrings.length} strings`;

    if (!filtered || filtered.length === 0) {
      stringsTableBody.innerHTML = '<tr><td colspan="3" class="tags-empty">No matching strings found.</td></tr>';
      return;
    }

    filtered.forEach(s => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><code>${s.offset}</code></td>
        <td><span class="badge-count" style="font-size: 10px;">${s.type}</span></td>
        <td><code>${escapeHtml(s.string)}</code></td>
      `;
      stringsTableBody.appendChild(tr);
    });
  }

  copyStringsBtn.addEventListener('click', () => {
    const allStrings = (lastAnalysisData && lastAnalysisData.sample_strings) || [];
    if (allStrings.length > 0) {
      const text = allStrings.map(s => `[${s.offset}] (${s.type}) ${s.string}`).join('\n');
      copyToClipboard(text, copyStringsBtn);
    }
  });

  // ------------------------------------------------------------------------
  // Print / PDF Export
  // ------------------------------------------------------------------------
  printReportBtn.addEventListener('click', () => {
    window.print();
  });

  // ------------------------------------------------------------------------
  // AI Agent & Model Provider Configuration
  // ------------------------------------------------------------------------
  async function loadProviderMetadata() {
    try {
      const res = await fetch('/api/providers');
      if (res.ok) {
        const data = await res.json();
        availableProviders = {};
        (data.providers || []).forEach(p => { availableProviders[p.id] = p; });
        updateModelStatusBadge();
      }
    } catch (e) {
      console.warn('Failed to load provider metadata:', e);
    }
  }

  function getProviderDisplayName(providerId) {
    const p = availableProviders[providerId];
    if (p) return `${p.icon} ${p.name}`;
    return (providerId || 'AI AGENT').toUpperCase();
  }

  function updateModelStatusBadge() {
    const p = availableProviders[aiSettings.provider];
    const icon = p ? p.icon : '🤖';
    const modelShort = (aiSettings.model || 'DEFAULT').toUpperCase();
    if (modelStatus) {
      modelStatus.textContent = `${icon} ${modelShort}`;
    }
  }

  openModelSettingsBtn.addEventListener('click', () => {
    providerSelect.value = aiSettings.provider || 'gemini';
    modelNameInput.value = aiSettings.model || '';
    baseUrlInput.value = aiSettings.base_url || '';
    apiKeyInput.value = aiSettings.api_key || '';
    updateModalFormFields(providerSelect.value);
    modelSettingsModal.classList.remove('hidden');
  });

  providerSelect.addEventListener('change', (e) => {
    updateModalFormFields(e.target.value);
  });

  function updateModalFormFields(selectedPid) {
    const p = availableProviders[selectedPid];
    if (p) {
      if (!modelNameInput.value || modelNameInput.dataset.autoFilled === 'true' || selectedPid !== aiSettings.provider) {
        modelNameInput.value = p.default_model;
        modelNameInput.dataset.autoFilled = 'true';
      }
      if (!baseUrlInput.value || baseUrlInput.dataset.autoFilled === 'true' || selectedPid !== aiSettings.provider) {
        baseUrlInput.value = p.base_url;
        baseUrlInput.dataset.autoFilled = 'true';
      }
      if (selectedPid === 'lmstudio') {
        envKeyStatusText.textContent = '💡 LM Studio runs locally at http://127.0.0.1:1234/v1. No API key required!';
      } else {
        envKeyStatusText.textContent = `💡 Server defaults to ${p.env_key} in .env if left blank.`;
      }
    }
  }

  modelNameInput.addEventListener('input', () => { modelNameInput.dataset.autoFilled = 'false'; });
  baseUrlInput.addEventListener('input', () => { baseUrlInput.dataset.autoFilled = 'false'; });

  toggleKeyVisibilityBtn.addEventListener('click', () => {
    if (apiKeyInput.type === 'password') {
      apiKeyInput.type = 'text';
      toggleKeyVisibilityBtn.textContent = '🔒 Hide Key';
    } else {
      apiKeyInput.type = 'password';
      toggleKeyVisibilityBtn.textContent = '👁️ Show Key';
    }
  });

  saveModelSettingsBtn.addEventListener('click', () => {
    aiSettings.provider = providerSelect.value;
    aiSettings.model = modelNameInput.value.trim();
    aiSettings.base_url = baseUrlInput.value.trim();
    aiSettings.api_key = apiKeyInput.value.trim();

    try {
      localStorage.setItem('malwsentinel_ai_settings', JSON.stringify(aiSettings));
    } catch (e) {}

    updateModelStatusBadge();
    modelSettingsModal.classList.add('hidden');
    logTerminal(`AI Agent switched to: ${getProviderDisplayName(aiSettings.provider)} (${aiSettings.model})`, 'cyan');
  });

  closeModelModalBtn.addEventListener('click', () => modelSettingsModal.classList.add('hidden'));
  cancelModelModalBtn.addEventListener('click', () => modelSettingsModal.classList.add('hidden'));
  modelSettingsModal.addEventListener('click', (e) => {
    if (e.target === modelSettingsModal) modelSettingsModal.classList.add('hidden');
  });

  // Initialize providers and launch initial triage
  loadProviderMetadata();
  updateModelStatusBadge();
  runTriage();
});
