/* jwtd Interactive Web App Engine */

// Sample Tokens for Presets
const SAMPLES = {
  hs256: {
    token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTc4NDY3OTE3OSwiZXhwIjoxNzg0NjgyNzc5LCJuYmYiOjE3ODQ2NzkxNzl9.9gGz5q7q6b-a2hB8E8_M3J3W6P5L0k1V-m4R2N7X8Y4",
    key: "raw:my-hmac-secret"
  },
  rs256: {
    token: "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleS0xMDAxIn0.eyJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20iLCJzdWIiOiJ1c2VyXzkwMjEiLCJhdWQiOiJhcGkuZXhhbXBsZS5jb20iLCJpYXQiOjE3ODQ2NzkxNzksImV4cCI6MTc4NDY4Mjc3OSwicm9sZXMiOlsidXNlciIsImFkbWluIl19.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    key: ""
  },
  jwe: {
    token: "eyJhbGciOiJSU0EtT0FFRi0yNTYiLCJlbmMiOiJBMjU2R0NNIiwia2lkIjoia2V5LTk5MSJ9.c2VjcmV0LWtleS1kYXRh.aXZkYXRh.Y2lwaGVydGV4dGRhdGE.dGFnZGF0YQ",
    key: ""
  },
  nested: {
    token: "eyJhbGciOiJSU0EtT0FFRi0yNTYiLCJlbmMiOiJBMjU2R0NNIiwjdHlwIjoiSldUIn0.S0VZX0RBVEE.SVZfREFUQQ.ZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrSVhWQ0o5LmV5SnpkV0lpT2lKeE1qTTBOVFlMT0Rrd0lpd2libUZ0WlNJNklrcHBiaUJEYjJWSllpd2laV3h3SWpveE56ZzBOamd5TnpDNUZRLmsxWTJVek4zS1hkMmgwSTBVM2FXTWFNeU16VXlNVjhuTVN4V01uUlhaZw.VEFHX0RBVEE",
    key: ""
  }
};

document.addEventListener("DOMContentLoaded", () => {
  initPlayground();
  initCommandBuilder();
  initTabs();
});

// Helper: Base64URL Decode
function base64UrlDecode(str) {
  let output = str.replace(/-/g, '+').replace(/_/g, '/');
  switch (output.length % 4) {
    case 0: break;
    case 2: output += '=='; break;
    case 3: output += '='; break;
    default: throw new Error('Illegal base64url string!');
  }
  try {
    return decodeURIComponent(atob(output).split('').map(c => 
      '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)
    ).join(''));
  } catch (e) {
    return atob(output);
  }
}

// Helper: Format Timestamps (exp, iat, nbf)
function formatTimestampValue(val) {
  if (typeof val === 'number' && val > 1000000000 && val < 2500000000) {
    try {
      const dateStr = new Date(val * 1000).toISOString();
      return `"${dateStr} (${val})"`;
    } catch (e) {}
  }
  return null;
}

// Syntax Highlighting JSON to HTML
function renderFormattedJSON(obj) {
  function formatValue(v, indent = '  ') {
    if (v === null) {
      return `<span class="json-null">null</span>`;
    }
    if (typeof v === 'boolean') {
      return `<span class="json-boolean">${v}</span>`;
    }
    if (typeof v === 'number') {
      return `<span class="json-number">${v}</span>`;
    }
    if (typeof v === 'string') {
      return `<span class="json-string">"${escapeHtml(v)}"</span>`;
    }
    if (Array.isArray(v)) {
      if (v.length === 0) return '[]';
      const items = v.map(item => indent + '  ' + formatValue(item, indent + '  ')).join(',\n');
      return `[\n${items}\n${indent}]`;
    }
    if (typeof v === 'object') {
      const keys = Object.keys(v);
      if (keys.length === 0) return '{}';
      const pairs = keys.map(k => {
        let valStr = formatValue(v[k], indent + '  ');
        // Check for timestamp fields: iat, exp, nbf
        if ((k === 'exp' || k === 'iat' || k === 'nbf') && typeof v[k] === 'number') {
          const tsFormatted = formatTimestampValue(v[k]);
          if (tsFormatted) {
            valStr = `<span class="json-string">${tsFormatted}</span>`;
          }
        }
        return `${indent}  <span class="json-key">"${escapeHtml(k)}"</span>: ${valStr}`;
      }).join(',\n');
      return `{\n${pairs}\n${indent}}`;
    }
    return escapeHtml(String(v));
  }

  return formatValue(obj);
}

function escapeHtml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// Token Parsing Engine
async function decodeToken(tokenStr, keyStr = '') {
  tokenStr = tokenStr.trim();
  if (!tokenStr) {
    return `<span class="jwt-label">Header:</span>\n<span class="json-null">Please enter a JWT or JWE token above.</span>`;
  }

  const parts = tokenStr.split('.');

  // Check if JWE (5 parts)
  if (parts.length === 5) {
    return decodeJWE(parts, keyStr);
  }

  // Check if JWT (3 parts)
  if (parts.length === 3) {
    return await decodeJWT(parts, keyStr, tokenStr);
  }

  return `<span class="sig-status invalid">Error: Invalid token format. Expected 3 parts (JWT) or 5 parts (JWE), found ${parts.length} parts.</span>`;
}

// Decode JWE (5 parts)
function decodeJWE(parts, keyStr) {
  let headerHtml = '';
  try {
    const headerObj = JSON.parse(base64UrlDecode(parts[0]));
    headerHtml = renderFormattedJSON(headerObj);
  } catch (e) {
    headerHtml = `<span class="json-null">Invalid JWE Header: ${escapeHtml(e.message)}</span>`;
  }

  let html = `<span class="jwt-label">Protected Header:</span>\n${headerHtml}\n\n`;

  if (keyStr) {
    html += `<span class="jwt-label">Encrypted Payload:</span>\n<span class="json-string">"[Decrypted JWE Payload placeholder - Key provided]"</span>\n\n`;
  } else {
    html += `<span class="jwt-label">Encrypted Parts (No key provided):</span>\n{\n  <span class="json-key">"encrypted_key"</span>: <span class="json-number">${parts[1].length} bytes</span>,\n  <span class="json-key">"initialization_vector"</span>: <span class="json-number">${parts[2].length} bytes</span>,\n  <span class="json-key">"ciphertext"</span>: <span class="json-number">${parts[3].length} bytes</span>,\n  <span class="json-key">"tag"</span>: <span class="json-number">${parts[4].length} bytes</span>\n}\n\n`;
  }

  html += `<span class="sig-status unverified">JWE Protected Header inspected (${keyStr ? 'Decryption key provided' : 'Use --key/JWTD_KEY to decrypt payload'}).</span>`;
  return html;
}

// Decode JWT (3 parts)
async function decodeJWT(parts, keyStr, fullToken) {
  let headerObj = {}, payloadObj = {};
  let headerHtml = '', payloadHtml = '';

  try {
    headerObj = JSON.parse(base64UrlDecode(parts[0]));
    headerHtml = renderFormattedJSON(headerObj);
  } catch (e) {
    headerHtml = `<span class="json-null">Invalid JWT Header: ${escapeHtml(e.message)}</span>`;
  }

  try {
    const rawPayload = base64UrlDecode(parts[1]);
    try {
      payloadObj = JSON.parse(rawPayload);
      payloadHtml = renderFormattedJSON(payloadObj);
    } catch (e) {
      payloadHtml = `<span class="json-string">"${escapeHtml(rawPayload)}"</span>`;
    }
  } catch (e) {
    payloadHtml = `<span class="json-null">Invalid JWT Payload: ${escapeHtml(e.message)}</span>`;
  }

  let html = `<span class="jwt-label">Header:</span>\n${headerHtml}\n\n<span class="jwt-label">Claims:</span>\n${payloadHtml}\n\n`;

  // Signature verification logic
  let sigStatusHtml = '';
  if (!keyStr) {
    sigStatusHtml = `<span class="sig-status unverified">Signature: UNVERIFIED (No verification key specified)</span>`;
  } else {
    const isValid = await verifyHMAC(parts[0], parts[1], parts[2], keyStr);
    if (isValid === true) {
      sigStatusHtml = `<span class="sig-status valid">Signature: VALID</span>`;
    } else if (isValid === false) {
      sigStatusHtml = `<span class="sig-status invalid">Signature: INVALID</span>`;
    } else {
      sigStatusHtml = `<span class="sig-status unverified">Signature: Key provided (${escapeHtml(keyStr)})</span>`;
    }
  }

  html += sigStatusHtml;
  return html;
}

// HMAC Signature verification helper
async function verifyHMAC(headerB64, payloadB64, signatureB64, keyStr) {
  let secret = keyStr;
  if (secret.startsWith('raw:')) {
    secret = secret.substring(4);
  }

  try {
    const enc = new TextEncoder();
    const keyData = enc.encode(secret);
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      keyData,
      { name: "HMAC", hash: { name: "SHA-256" } },
      false,
      ["verify", "sign"]
    );

    const messageData = enc.encode(`${headerB64}.${payloadB64}`);
    const sigBuffer = base64UrlToArrayBuffer(signatureB64);

    return await crypto.subtle.verify("HMAC", cryptoKey, sigBuffer, messageData);
  } catch (e) {
    return null; // Return null if algorithm mismatch or non-HMAC key
  }
}

function base64UrlToArrayBuffer(base64Url) {
  let base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  const binaryStr = atob(base64);
  const bytes = new Uint8Array(binaryStr.length);
  for (let i = 0; i < binaryStr.length; i++) {
    bytes[i] = binaryStr.charCodeAt(i);
  }
  return bytes.buffer;
}

// Playground Initialization
function initPlayground() {
  const tokenInput = document.getElementById("input-token");
  const keyInput = document.getElementById("input-key");
  const terminalOutput = document.getElementById("terminal-output");
  const btnDecode = document.getElementById("btn-decode");
  const btnClear = document.getElementById("btn-clear");
  const btnCopyJson = document.getElementById("btn-copy-json");

  async function updateOutput() {
    if (!tokenInput || !terminalOutput) return;
    const token = tokenInput.value;
    const key = keyInput ? keyInput.value : '';
    const resultHtml = await decodeToken(token, key);
    terminalOutput.innerHTML = resultHtml;
  }

  if (btnDecode) {
    btnDecode.addEventListener("click", updateOutput);
  }

  if (tokenInput) {
    tokenInput.addEventListener("input", updateOutput);
  }
  if (keyInput) {
    keyInput.addEventListener("input", updateOutput);
  }

  if (btnClear) {
    btnClear.addEventListener("click", () => {
      tokenInput.value = '';
      if (keyInput) keyInput.value = '';
      updateOutput();
    });
  }

  if (btnCopyJson) {
    btnCopyJson.addEventListener("click", () => {
      if (terminalOutput) {
        navigator.clipboard.writeText(terminalOutput.innerText);
        showToast("Output copied to clipboard!");
      }
    });
  }

  // Preset Buttons
  document.querySelectorAll(".preset-btn").forEach(btn => {
    btn.addEventListener("click", (e) => {
      const presetKey = e.target.getAttribute("data-preset");
      if (SAMPLES[presetKey]) {
        tokenInput.value = SAMPLES[presetKey].token;
        if (keyInput) keyInput.value = SAMPLES[presetKey].key;
        updateOutput();
        showToast(`Loaded ${presetKey.toUpperCase()} sample preset`);
      }
    });
  });

  // Initial Decode
  updateOutput();
}

// Command Builder Initialization
function initCommandBuilder() {
  const sourceRadios = document.getElementsByName("builder-source");
  const keyRadios = document.getElementsByName("builder-key");
  const commandText = document.getElementById("builder-command-text");
  const btnCopyCmd = document.getElementById("btn-copy-builder-cmd");

  function generateCommand() {
    let source = "arg";
    let keyOpt = "none";

    sourceRadios.forEach(r => { if (r.checked) source = r.value; });
    keyRadios.forEach(r => { if (r.checked) keyOpt = r.value; });

    let cmd = "";

    if (source === "pipe") {
      cmd += `echo "<token>" | `;
    }

    if (keyOpt === "env") {
      cmd += `JWTD_KEY=/path/to/key.pem `;
    }

    cmd += `jwtd`;

    if (keyOpt === "flag") {
      cmd += ` --key /path/to/key.pem`;
    } else if (keyOpt === "raw") {
      cmd += ` --key raw:my-secret`;
    }

    if (source === "arg") {
      cmd += ` <token>`;
    }

    if (commandText) {
      commandText.textContent = cmd;
    }
  }

  sourceRadios.forEach(r => r.addEventListener("change", generateCommand));
  keyRadios.forEach(r => r.addEventListener("change", generateCommand));

  if (btnCopyCmd && commandText) {
    btnCopyCmd.addEventListener("click", () => {
      navigator.clipboard.writeText(commandText.textContent);
      showToast("CLI command copied to clipboard!");
    });
  }

  generateCommand();
}

// Tabs Controller
function initTabs() {
  const tabBtns = document.querySelectorAll(".tab-btn");
  tabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      const targetId = btn.getAttribute("data-tab");
      document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));

      btn.classList.add("active");
      const targetPane = document.getElementById(targetId);
      if (targetPane) targetPane.classList.add("active");
    });
  });
}

// Global Copy Helper
function copySnippet(elementId) {
  const el = document.getElementById(elementId);
  if (el) {
    navigator.clipboard.writeText(el.textContent.trim());
    showToast("Command copied to clipboard!");
  }
}

// Toast Helper
function showToast(message) {
  let container = document.querySelector(".toast-container");
  if (!container) {
    container = document.createElement("div");
    container.className = "toast-container";
    document.body.appendChild(container);
  }

  const toast = document.createElement("div");
  toast.className = "toast";
  toast.innerHTML = `<span>✓</span> <span>${escapeHtml(message)}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(100%)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 2500);
}
