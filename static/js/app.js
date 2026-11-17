/**
 * Digital Signature & Document Verification System
 * Client-Side Application Logic
 */

let state = {
  currentPrivateKey: "",
  currentPublicKey: "",
  currentFingerprint: "",
  currentAlgorithm: "",
  activeKeyView: "public", // 'public' | 'private'
  signResult: null,
  auditLogs: JSON.parse(localStorage.getItem("auditLogs") || "[]"),
};

// Initialize on DOM load
document.addEventListener("DOMContentLoaded", () => {
  if (window.lucide) {
    lucide.createIcons();
  }
  setupDragAndDrop();
  renderAuditLogs();
});

// Toast notification helper
function showToast(message, type = "info") {
  const container = document.getElementById("toast-container");
  if (!container) return;

  const bgClasses = {
    success: "bg-emerald-950/80 border-emerald-500/50 text-emerald-200",
    error: "bg-rose-950/80 border-rose-500/50 text-rose-200",
    info: "bg-indigo-950/80 border-indigo-500/50 text-indigo-200",
    warning: "bg-amber-950/80 border-amber-500/50 text-amber-200",
  };

  container.className = `rounded-xl p-4 border text-xs flex items-center justify-between shadow-xl transition-all ${bgClasses[type] || bgClasses.info}`;
  container.innerHTML = `
    <div class="flex items-center gap-2">
      <span>${escapeHtml(message)}</span>
    </div>
    <button onclick="this.parentElement.classList.add('hidden')" class="text-slate-400 hover:text-white text-xs ml-4">✕</button>
  `;
  container.classList.remove("hidden");

  setTimeout(() => {
    container.classList.add("hidden");
  }, 5000);
}

// Tab navigation
function switchTab(tabId) {
  document.querySelectorAll(".tab-panel").forEach((panel) => {
    panel.classList.add("hidden");
  });
  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.classList.remove("active");
  });

  const targetPanel = document.getElementById(tabId);
  if (targetPanel) {
    targetPanel.classList.remove("hidden");
  }

  const activeBtn = document.getElementById(`btn-${tabId}`);
  if (activeBtn) {
    activeBtn.classList.add("active");
  }

  if (window.lucide) {
    lucide.createIcons();
  }
}

// ==========================================
// TAB 1: KEY MANAGEMENT
// ==========================================
async function generateKeys() {
  const btn = document.getElementById("btn-generate-keys");
  const algo = document.getElementById("keygen-algo").value;
  const passphrase = document.getElementById("keygen-passphrase").value;

  btn.disabled = true;
  btn.innerHTML = `<i data-lucide="loader-2" class="w-4 h-4 animate-spin"></i> Generating...`;
  if (window.lucide) lucide.createIcons();

  try {
    const res = await fetch("/api/keygen", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ algorithm: algo, passphrase: passphrase || null }),
    });

    const data = await res.json();
    if (!data.success) {
      throw new Error(data.error || "Failed to generate keys");
    }

    state.currentPrivateKey = data.private_key;
    state.currentPublicKey = data.public_key;
    state.currentFingerprint = data.fingerprint;
    state.currentAlgorithm = data.algorithm;

    document.getElementById("active-algo-badge").innerText = `${data.algorithm} Active`;
    document.getElementById("active-algo-badge").className = "text-xs px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 font-medium";

    document.getElementById("key-fingerprint-box").classList.remove("hidden");
    document.getElementById("display-fingerprint").innerText = data.fingerprint;

    toggleKeyView("public");

    addAuditLog("Key Generation", `${data.algorithm} Key Pair`, data.fingerprint.slice(0, 16) + "...", "Keys Generated");
    showToast(`Successfully generated new ${data.algorithm} key pair!`, "success");
  } catch (err) {
    showToast(`Keygen Error: ${err.message}`, "error");
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<i data-lucide="sparkles" class="w-4 h-4"></i> Generate New Keys`;
    if (window.lucide) lucide.createIcons();
  }
}

function toggleKeyView(view) {
  state.activeKeyView = view;
  const btnPub = document.getElementById("btn-view-pub");
  const btnPriv = document.getElementById("btn-view-priv");
  const display = document.getElementById("display-key-pem");

  if (view === "public") {
    btnPub.className = "text-xs px-3 py-1.5 rounded-lg bg-indigo-600 text-white font-medium";
    btnPriv.className = "text-xs px-3 py-1.5 rounded-lg bg-slate-800 text-slate-300 font-medium";
    display.value = state.currentPublicKey || "No public key generated yet.";
  } else {
    btnPriv.className = "text-xs px-3 py-1.5 rounded-lg bg-indigo-600 text-white font-medium";
    btnPub.className = "text-xs px-3 py-1.5 rounded-lg bg-slate-800 text-slate-300 font-medium";
    display.value = state.currentPrivateKey || "No private key generated yet.";
  }
}

function copyCurrentKey() {
  const content = state.activeKeyView === "public" ? state.currentPublicKey : state.currentPrivateKey;
  if (!content) {
    showToast("No key to copy", "warning");
    return;
  }
  navigator.clipboard.writeText(content).then(() => {
    showToast(`Copied ${state.activeKeyView} key to clipboard!`, "info");
  });
}

function copyFingerprint() {
  if (!state.currentFingerprint) return;
  navigator.clipboard.writeText(state.currentFingerprint).then(() => {
    showToast("Copied public key fingerprint to clipboard!", "info");
  });
}

function downloadCurrentKey() {
  const isPub = state.activeKeyView === "public";
  const content = isPub ? state.currentPublicKey : state.currentPrivateKey;
  if (!content) {
    showToast("No key to download", "warning");
    return;
  }
  const filename = isPub ? "public_key.pem" : "private_key.pem";
  downloadBlob(content, filename, "application/x-pem-file");
}

function loadGeneratedKeyIntoSigner() {
  if (!state.currentPrivateKey) {
    showToast("Please generate a key pair first", "warning");
    return;
  }
  document.getElementById("sign-private-key").value = state.currentPrivateKey;
  switchTab("tab-sign");
  showToast("Loaded private key into Document Signer", "info");
}

function loadGeneratedKeyIntoVerifier() {
  if (!state.currentPublicKey) {
    showToast("Please generate a key pair first", "warning");
    return;
  }
  document.getElementById("verify-public-key").value = state.currentPublicKey;
  switchTab("tab-verify");
  showToast("Loaded public key into Signature Verifier", "info");
}

// ==========================================
// TAB 2: SIGN DOCUMENT
// ==========================================
let signDocFile = null;

function handleSignDocSelect(e) {
  const file = e.target.files && e.target.files[0];
  if (!file) return;
  signDocFile = file;
  document.getElementById("sign-doc-label").innerText = `Selected: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
}

function handleSignKeyFile(e) {
  const file = e.target.files && e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = (event) => {
    document.getElementById("sign-private-key").value = event.target.result;
    showToast(`Loaded key from file: ${file.name}`, "info");
  };
  reader.readAsText(file);
}

async function signDocument() {
  if (!signDocFile) {
    showToast("Please select a document file to sign", "warning");
    return;
  }
  const privKey = document.getElementById("sign-private-key").value.trim();
  if (!privKey) {
    showToast("Please provide the signer private key (PEM)", "warning");
    return;
  }

  const btn = document.getElementById("btn-execute-sign");
  btn.disabled = true;
  btn.innerHTML = `<i data-lucide="loader-2" class="w-4 h-4 animate-spin"></i> Signing...`;
  if (window.lucide) lucide.createIcons();

  const formData = new FormData();
  formData.append("document", signDocFile);
  formData.append("private_key_text", privKey);
  formData.append("passphrase", document.getElementById("sign-key-passphrase").value);
  formData.append("signer_name", document.getElementById("signer-identity").value);
  formData.append("hash_algo", document.getElementById("sign-hash-algo").value);

  try {
    const res = await fetch("/api/sign", {
      method: "POST",
      body: formData,
    });
    const data = await res.json();
    if (!data.success) {
      throw new Error(data.error || "Failed to sign document");
    }

    state.signResult = data;

    // Update outputs
    document.getElementById("sign-output-hash").innerText = data.document_hash;
    document.getElementById("sign-output-sig").value = data.signature_base64;
    document.getElementById("sign-output-manifest").value = JSON.stringify(data.manifest, null, 2);

    document.getElementById("sign-status-badge").innerText = `Signed (${data.key_algorithm})`;
    document.getElementById("sign-status-badge").className = "text-xs px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 font-medium";

    document.getElementById("btn-download-sig").disabled = false;
    document.getElementById("btn-download-manifest").disabled = false;
    document.getElementById("btn-send-to-verifier").disabled = false;

    addAuditLog("Document Signed", data.document_name, data.document_hash, "Success");
    showToast("Document signed successfully!", "success");
  } catch (err) {
    showToast(err.message, "error");
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<i data-lucide="lock" class="w-4 h-4"></i> Sign Document`;
    if (window.lucide) lucide.createIcons();
  }
}

function downloadSignature() {
  if (!state.signResult) return;
  // Convert base64 to binary byte array for raw .sig
  const binaryString = atob(state.signResult.signature_base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  const blob = new Blob([bytes], { type: "application/octet-stream" });
  const filename = `${state.signResult.document_name || "document"}.sig`;
  triggerDownload(blob, filename);
}

function downloadManifest() {
  if (!state.signResult) return;
  const jsonStr = JSON.stringify(state.signResult.manifest, null, 2);
  downloadBlob(jsonStr, `${state.signResult.document_name || "document"}.manifest.json`, "application/json");
}

function sendSignOutputToVerifier() {
  if (!state.signResult) return;

  // Transfer signature
  document.getElementById("verify-signature-input").value = state.signResult.signature_base64;

  // Transfer public key if available
  if (state.currentPublicKey) {
    document.getElementById("verify-public-key").value = state.currentPublicKey;
  }

  // Pre-set document input label
  if (signDocFile) {
    verifyDocFile = signDocFile;
    document.getElementById("verify-doc-label").innerText = `Selected: ${signDocFile.name} (${(signDocFile.size / 1024).toFixed(1)} KB)`;
  }

  switchTab("tab-verify");
  showToast("Transferred signed document details to Verifier!", "info");
}

// ==========================================
// TAB 3: VERIFY SIGNATURE
// ==========================================
let verifyDocFile = null;

function handleVerifyDocSelect(e) {
  const file = e.target.files && e.target.files[0];
  if (!file) return;
  verifyDocFile = file;
  document.getElementById("verify-doc-label").innerText = `Selected: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
}

function handleVerifyKeyFile(e) {
  const file = e.target.files && e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = (event) => {
    document.getElementById("verify-public-key").value = event.target.result;
    showToast(`Loaded public key: ${file.name}`, "info");
  };
  reader.readAsText(file);
}

function handleVerifySigFile(e) {
  const file = e.target.files && e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = (event) => {
    document.getElementById("verify-signature-input").value = event.target.result;
    showToast(`Loaded signature/manifest: ${file.name}`, "info");
  };
  if (file.name.endsWith(".json")) {
    reader.readAsText(file);
  } else {
    // Binary .sig or base64
    const binaryReader = new FileReader();
    binaryReader.onload = (event) => {
      const bytes = new Uint8Array(event.target.result);
      let binary = "";
      for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
      }
      const b64 = btoa(binary);
      document.getElementById("verify-signature-input").value = b64;
      showToast(`Loaded binary signature as Base64`, "info");
    };
    binaryReader.readAsArrayBuffer(file);
  }
}

async function verifyDocument() {
  if (!verifyDocFile) {
    showToast("Please select the received document file", "warning");
    return;
  }
  const pubKey = document.getElementById("verify-public-key").value.trim();
  if (!pubKey) {
    showToast("Please provide the signer public key (PEM)", "warning");
    return;
  }
  const sigText = document.getElementById("verify-signature-input").value.trim();
  if (!sigText) {
    showToast("Please provide the signature or manifest JSON", "warning");
    return;
  }

  const btn = document.getElementById("btn-execute-verify");
  btn.disabled = true;
  btn.innerHTML = `<i data-lucide="loader-2" class="w-4 h-4 animate-spin"></i> Verifying...`;
  if (window.lucide) lucide.createIcons();

  const formData = new FormData();
  formData.append("document", verifyDocFile);
  formData.append("public_key_text", pubKey);
  formData.append("signature_text", sigText);

  try {
    const res = await fetch("/api/verify", {
      method: "POST",
      body: formData,
    });
    const data = await res.json();
    if (!data.success) {
      throw new Error(data.error || "Verification request failed");
    }

    const v = data.verification;
    updateVerificationUI(v);

    addAuditLog(
      "Document Verification",
      verifyDocFile.name,
      v.document_hash,
      v.is_valid ? "VALID" : "INVALID / TAMPERED"
    );

    if (v.is_valid) {
      showToast("Verification successful: Document is intact & authentic!", "success");
    } else {
      showToast("Verification FAILED: Document tampered or key mismatch!", "error");
    }
  } catch (err) {
    showToast(err.message, "error");
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<i data-lucide="badge-check" class="w-4 h-4"></i> Verify Cryptographic Signature`;
    if (window.lucide) lucide.createIcons();
  }
}

function updateVerificationUI(v) {
  const badge = document.getElementById("verify-result-badge");
  const hero = document.getElementById("verify-hero");
  const heroIcon = document.getElementById("verify-hero-icon");
  const heroTitle = document.getElementById("verify-hero-title");
  const heroDesc = document.getElementById("verify-hero-desc");
  const tamperBox = document.getElementById("tamper-alert-box");

  document.getElementById("verify-digest").innerText = v.document_hash || "N/A";
  document.getElementById("verify-algo").innerText = `${v.key_algorithm} with ${v.hash_algorithm}`;
  document.getElementById("verify-fingerprint").innerText = v.key_fingerprint || "N/A";
  document.getElementById("verify-time").innerText = v.verified_at;

  if (v.is_valid) {
    badge.innerText = "AUTHENTIC & VERIFIED";
    badge.className = "text-xs px-2.5 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 font-semibold";

    hero.className = "rounded-xl border p-5 transition-all bg-emerald-950/40 border-emerald-500/50";
    heroIcon.className = "p-2.5 rounded-xl bg-emerald-500/20 text-emerald-400";
    heroIcon.innerHTML = `<i data-lucide="check-check" class="w-6 h-6"></i>`;
    heroTitle.innerText = "VALID DIGITAL SIGNATURE";
    heroTitle.className = "text-sm font-bold text-emerald-300";
    heroDesc.innerText = "Cryptographic integrity and origin authenticity are mathematically confirmed. No modifications have occurred.";

    tamperBox.classList.add("hidden");
  } else {
    badge.innerText = "VERIFICATION FAILED";
    badge.className = "text-xs px-2.5 py-0.5 rounded-full bg-rose-500/20 text-rose-300 font-semibold";

    hero.className = "rounded-xl border p-5 transition-all bg-rose-950/40 border-rose-500/50";
    heroIcon.className = "p-2.5 rounded-xl bg-rose-500/20 text-rose-400";
    heroIcon.innerHTML = `<i data-lucide="shield-x" class="w-6 h-6"></i>`;
    heroTitle.innerText = "SIGNATURE VERIFICATION FAILED";
    heroTitle.className = "text-sm font-bold text-rose-300";
    heroDesc.innerText = v.status_message;

    tamperBox.classList.remove("hidden");
  }

  if (window.lucide) lucide.createIcons();
}

// ==========================================
// TAB 4: TAMPER LAB
// ==========================================
async function runTamperExperiment() {
  const privKey = document.getElementById("tamper-private-key").value.trim() || state.currentPrivateKey;
  if (!privKey) {
    showToast("Please generate or paste a private key first", "warning");
    return;
  }

  const docInput = document.getElementById("tamper-doc-input");
  const tamperPos = document.getElementById("tamper-pos").value || "0";

  const formData = new FormData();
  if (docInput.files && docInput.files[0]) {
    formData.append("document", docInput.files[0]);
  } else {
    // Default text document
    const blob = new Blob(["Official Contract: Party A agrees to pay Party B $100,000 for deliverables."], { type: "text/plain" });
    formData.append("document", blob, "contract.txt");
  }
  formData.append("private_key_text", privKey);
  formData.append("tamper_position", tamperPos);

  try {
    const res = await fetch("/api/tamper-lab", {
      method: "POST",
      body: formData,
    });
    const data = await res.json();
    if (!data.success) {
      throw new Error(data.error || "Tamper experiment failed");
    }

    const tr = data.tamper_result;

    document.getElementById("tamper-orig-hash").innerText = tr.original_hash;
    document.getElementById("tamper-orig-status").innerText = "VALID (Authentic: True)";
    document.getElementById("tamper-orig-status").className = "text-xs font-semibold text-emerald-400";

    document.getElementById("tamper-mod-hash").innerText = tr.tampered_hash;
    document.getElementById("tamper-mod-status").innerText = "FAILED (Tamper Detected)";
    document.getElementById("tamper-mod-status").className = "text-xs font-semibold text-rose-400";

    addAuditLog("Tamper Simulation", `Altered Byte [${tr.tampered_byte_index}]`, tr.tampered_hash, "Tamper Rejected");
    showToast("Tamper experiment completed: Modifying 1 byte broke verification!", "warning");
  } catch (err) {
    showToast(err.message, "error");
  }
}

// ==========================================
// TAB 5: AUDIT LOGS
// ==========================================
function addAuditLog(action, subject, digest, status) {
  const entry = {
    time: new Date().toISOString().replace("T", " ").substring(0, 19),
    action,
    subject,
    digest: digest ? digest.slice(0, 24) + "..." : "-",
    status,
  };
  state.auditLogs.unshift(entry);
  if (state.auditLogs.length > 50) state.auditLogs.pop();
  localStorage.setItem("auditLogs", JSON.stringify(state.auditLogs));
  renderAuditLogs();
}

function renderAuditLogs() {
  const tbody = document.getElementById("audit-table-body");
  if (!tbody) return;

  if (state.auditLogs.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="5" class="p-4 text-center text-slate-500 font-sans text-xs">No audit events recorded yet. Perform key generation, signing, or verification to view logs.</td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = state.auditLogs
    .map(
      (log) => `
    <tr class="hover:bg-slate-800/40 transition">
      <td class="p-3 text-slate-400">${escapeHtml(log.time)}</td>
      <td class="p-3 font-semibold text-indigo-300 font-sans">${escapeHtml(log.action)}</td>
      <td class="p-3 text-slate-300">${escapeHtml(log.subject)}</td>
      <td class="p-3 text-slate-400 select-all">${escapeHtml(log.digest)}</td>
      <td class="p-3 font-sans">
        <span class="px-2 py-0.5 rounded-full text-[10px] font-medium ${
          log.status.includes("VALID") || log.status.includes("Success") || log.status.includes("Generated")
            ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
            : "bg-rose-500/10 text-rose-400 border border-rose-500/20"
        }">${escapeHtml(log.status)}</span>
      </td>
    </tr>
  `
    )
    .join("");
}

function clearAuditLogs() {
  state.auditLogs = [];
  localStorage.removeItem("auditLogs");
  renderAuditLogs();
  showToast("Audit logs cleared", "info");
}

// Drag & drop helper
function setupDragAndDrop() {
  const signZone = document.getElementById("drop-zone-sign-doc");
  const signInput = document.getElementById("sign-doc-input");

  if (signZone && signInput) {
    signZone.addEventListener("click", () => signInput.click());
    ["dragenter", "dragover"].forEach((event) => {
      signZone.addEventListener(event, (e) => {
        e.preventDefault();
        signZone.classList.add("border-indigo-500", "bg-slate-900/60");
      });
    });
    ["dragleave", "drop"].forEach((event) => {
      signZone.addEventListener(event, (e) => {
        e.preventDefault();
        signZone.classList.remove("border-indigo-500", "bg-slate-900/60");
      });
    });
    signZone.addEventListener("drop", (e) => {
      if (e.dataTransfer.files && e.dataTransfer.files.length) {
        signDocFile = e.dataTransfer.files[0];
        document.getElementById("sign-doc-label").innerText = `Selected: ${signDocFile.name} (${(signDocFile.size / 1024).toFixed(1)} KB)`;
      }
    });
  }

  const verifyZone = document.getElementById("drop-zone-verify-doc");
  const verifyInput = document.getElementById("verify-doc-input");

  if (verifyZone && verifyInput) {
    verifyZone.addEventListener("click", () => verifyInput.click());
    ["dragenter", "dragover"].forEach((event) => {
      verifyZone.addEventListener(event, (e) => {
        e.preventDefault();
        verifyZone.classList.add("border-emerald-500", "bg-slate-900/60");
      });
    });
    ["dragleave", "drop"].forEach((event) => {
      verifyZone.addEventListener(event, (e) => {
        e.preventDefault();
        verifyZone.classList.remove("border-emerald-500", "bg-slate-900/60");
      });
    });
    verifyZone.addEventListener("drop", (e) => {
      if (e.dataTransfer.files && e.dataTransfer.files.length) {
        verifyDocFile = e.dataTransfer.files[0];
        document.getElementById("verify-doc-label").innerText = `Selected: ${verifyDocFile.name} (${(verifyDocFile.size / 1024).toFixed(1)} KB)`;
      }
    });
  }
}

// Utility download functions
function downloadBlob(content, filename, contentType) {
  const blob = new Blob([content], { type: contentType });
  triggerDownload(blob, filename);
}

function triggerDownload(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function copyToClipboard(elementId) {
  const el = document.getElementById(elementId);
  if (!el || !el.value) return;
  navigator.clipboard.writeText(el.value).then(() => {
    showToast("Copied to clipboard!", "info");
  });
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
