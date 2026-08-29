/**
 * AP Payment Fraud Sentinel — Unified Frontend Application v2.5
 * =============================================================
 * Powered by RocketRide Multi-Agent Forensic AI, Supabase Registry,
 * IMAP Email Ingestion Worker, and Stripe / RazorpayX Payouts.
 */

// ─── State Management ────────────────────────────────────────────────────────
const state = {
  supabase: null,
  user: null,
  supabaseConfig: { url: '', anon_key: '', is_configured: false },
  vendors: [],
  auditHistory: [],
  hitlHolds: [],
  emailLogs: [],
  activeTab: 'dashboard',
  currentSingleInvoiceId: null,
  selectedPayoutInvoice: null,
  stats: { total: 0, clean: 0, elevated: 0, hold: 0, fraud_held: 0 },
  authMode: 'signin',
};

// ─── DOM Ready Initialization ────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  try {
    setupNavigation();
    setupModals();
    setupAuth();
    setupVendorRegistry();
    setupSingleAudit();
    setupUniversalIngestion();
    setupBatchUpload();
    setupEmailPolling();
    setupPayoutGateway();
    setupSettings();
    setupAuditTable();
    setupAdminTelemetry();
  } catch (err) {
    console.error('Error in setup:', err);
  }

  // Initial Data Load
  await loadSystemHealth();
  await initSupabaseAuth();
  await loadVendors();
  await loadAuditHistory();
  await loadEmailLogs();
});


// ─── System Health & Status ──────────────────────────────────────────────────
async function loadSystemHealth() {
  try {
    const res = await fetch('/api/health');
    if (!res.ok) return;
    const data = await res.json();

    const engineDot = document.getElementById('engineDot');
    const engineLabel = document.getElementById('engineLabel');
    if (engineDot && engineLabel) {
      if (data.rocketride_online) {
        engineDot.style.background = '#10b981';
        engineLabel.textContent = 'RocketRide Online';
      } else {
        engineDot.style.background = '#818cf8';
        engineLabel.textContent = data.engine || 'Direct AI Active';
      }
    }

    updateSupabaseBadge(data.supabase_configured);
  } catch (err) {
    console.warn('Health check note:', err);
  }
}

function updateSupabaseBadge(isConfigured) {
  const badge = document.getElementById('supabaseBadge');
  const dot = document.getElementById('supabaseDot');
  const label = document.getElementById('supabaseLabel');
  if (!badge || !dot || !label) return;

  if (isConfigured) {
    badge.style.background = 'rgba(16, 185, 129, 0.12)';
    badge.style.borderColor = 'rgba(16, 185, 129, 0.3)';
    badge.style.color = '#34d399';
    dot.style.background = '#10b981';
    label.textContent = 'Supabase: Connected';
  } else {
    badge.style.background = 'rgba(99, 102, 241, 0.12)';
    badge.style.borderColor = 'rgba(99, 102, 241, 0.3)';
    badge.style.color = '#a5b4fc';
    dot.style.background = '#818cf8';
    label.textContent = 'Supabase: Local Sync';
  }
}


// ─── Supabase Authentication ──────────────────────────────────────────────────
async function initSupabaseAuth() {
  try {
    const res = await fetch('/api/auth/config');
    if (!res.ok) return;
    const cfg = await res.json();
    state.supabaseConfig = cfg;

    if (cfg.is_configured && window.supabase && cfg.supabase_url && cfg.supabase_anon_key) {
      state.supabase = window.supabase.createClient(cfg.supabase_url, cfg.supabase_anon_key);
      try {
        const { data: { session } } = await state.supabase.auth.getSession();
        if (session && session.user) {
          setUserSession(session.user);
        }
      } catch (e) {}

      state.supabase.auth.onAuthStateChange((event, session) => {
        if (session && session.user) {
          setUserSession(session.user);
        } else {
          clearUserSession();
        }
      });
    } else {
      const localUser = localStorage.getItem('sentinel_local_user');
      if (localUser) {
        try { setUserSession(JSON.parse(localUser)); } catch (e) {}
      }
    }
  } catch (err) {
    console.warn('Supabase Auth init:', err);
  }
}

function setUserSession(user) {
  state.user = user;
  const wrap = document.getElementById('userAuthWrap');
  if (!wrap) return;
  const email = user.email || 'analyst@sentinel.finance';
  const initial = email.charAt(0).toUpperCase();
  const isAdmin = !email || email.toLowerCase().includes('admin') || user.user_metadata?.role === 'admin' || user.role === 'admin';

  wrap.innerHTML = `
    <div class="user-profile-chip" title="${email} (${isAdmin ? 'Admin' : 'Analyst'})">
      <div class="user-avatar">${initial}</div>
      <span class="user-email-text">${email}</span>
      ${isAdmin ? '<span class="badge" style="background:rgba(99,102,241,0.25); color:#a5b4fc; font-size:0.65rem; padding:0.15rem 0.4rem; margin-left:0.25rem;">ADMIN</span>' : ''}
      <button class="signout-btn" id="signOutBtn" title="Sign Out">✕</button>
    </div>
  `;

  // Show/hide admin telemetry navigation tab
  const navAdmin = document.getElementById('navAdminTelemetry');
  if (navAdmin) navAdmin.style.display = isAdmin ? 'inline-flex' : 'none';

  document.getElementById('signOutBtn')?.addEventListener('click', async () => {
    if (state.supabase) {
      try { await state.supabase.auth.signOut(); } catch(e) {}
    }
    localStorage.removeItem('sentinel_local_user');
    clearUserSession();
    showToast('Signed out successfully.', 'info');
  });

  const authModal = document.getElementById('authModal');
  if (authModal) authModal.style.display = 'none';
}

function clearUserSession() {
  state.user = null;
  const wrap = document.getElementById('userAuthWrap');
  if (!wrap) return;
  wrap.innerHTML = `<button class="btn btn-primary btn-sm" id="authModalBtn">🔐 Sign In</button>`;
  document.getElementById('authModalBtn')?.addEventListener('click', () => {
    const modal = document.getElementById('authModal');
    if (modal) modal.style.display = 'flex';
  });

  // Default to showing admin telemetry in local demo mode
  const navAdmin = document.getElementById('navAdminTelemetry');
  if (navAdmin) navAdmin.style.display = 'inline-flex';
}


function setupAuth() {
  const authModal = document.getElementById('authModal');
  const authModalBtn = document.getElementById('authModalBtn');
  const authModalClose = document.getElementById('authModalClose');
  const authTabSignIn = document.getElementById('authTabSignIn');
  const authTabSignUp = document.getElementById('authTabSignUp');
  const authForm = document.getElementById('authForm');
  const authSubmitBtn = document.getElementById('authSubmitBtn');
  const authErrorMsg = document.getElementById('authErrorMsg');

  authModalBtn?.addEventListener('click', () => {
    if (authModal) authModal.style.display = 'flex';
  });

  authModalClose?.addEventListener('click', () => {
    if (authModal) authModal.style.display = 'none';
  });

  authTabSignIn?.addEventListener('click', () => {
    state.authMode = 'signin';
    authTabSignIn.classList.add('active');
    authTabSignUp.classList.remove('active');
    authSubmitBtn.textContent = 'Sign In with Supabase';
    if (authErrorMsg) authErrorMsg.style.display = 'none';
  });

  authTabSignUp?.addEventListener('click', () => {
    state.authMode = 'signup';
    authTabSignUp.classList.add('active');
    authTabSignIn.classList.remove('active');
    authSubmitBtn.textContent = 'Create Account with Supabase';
    if (authErrorMsg) authErrorMsg.style.display = 'none';
  });

  authForm?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('authEmail').value.trim();
    const password = document.getElementById('authPassword').value;

    if (authErrorMsg) authErrorMsg.style.display = 'none';
    authSubmitBtn.disabled = true;
    authSubmitBtn.textContent = 'Authenticating...';

    try {
      if (state.supabase) {
        if (state.authMode === 'signin') {
          const { data, error } = await state.supabase.auth.signInWithPassword({ email, password });
          if (error) throw error;
          setUserSession(data.user);
          showToast(`Welcome back, ${data.user.email}!`, 'success');
        } else {
          const { data, error } = await state.supabase.auth.signUp({ email, password });
          if (error) throw error;
          setUserSession(data.user || { email, id: 'user_' + Date.now() });
          showToast('Account created successfully!', 'success');
        }
      } else {
        const mockUser = { email, id: 'local_' + Date.now(), role: 'AP Security Analyst' };
        localStorage.setItem('sentinel_local_user', JSON.stringify(mockUser));
        setUserSession(mockUser);
        showToast(`Signed in as ${email} (Local Registry Mode)`, 'success');
      }
      if (authModal) authModal.style.display = 'none';
    } catch (err) {
      if (authErrorMsg) {
        authErrorMsg.textContent = err.message || 'Authentication failed.';
        authErrorMsg.style.display = 'block';
      }
    } finally {
      authSubmitBtn.disabled = false;
      authSubmitBtn.textContent = state.authMode === 'signin' ? 'Sign In with Supabase' : 'Create Account with Supabase';
    }
  });

  document.getElementById('authDemoAdminBtn')?.addEventListener('click', () => {
    const adminUser = { email: 'admin@sentinel.finance', id: 'usr_admin_001', role: 'admin' };
    localStorage.setItem('sentinel_local_user', JSON.stringify(adminUser));
    setUserSession(adminUser);
    if (authModal) authModal.style.display = 'none';
    showToast('Authenticated as Administrator (Full Privileges Granted)', 'success');
  });

  document.getElementById('authDemoAnalystBtn')?.addEventListener('click', () => {
    const analystUser = { email: 'analyst@sentinel.finance', id: 'usr_analyst_001', role: 'analyst' };
    localStorage.setItem('sentinel_local_user', JSON.stringify(analystUser));
    setUserSession(analystUser);
    if (authModal) authModal.style.display = 'none';
    showToast('Authenticated as Security Analyst (Standard Dashboard Mode)', 'info');
  });
}



// ─── Navigation Tabs ─────────────────────────────────────────────────────────
function setupNavigation() {
  const navTabsContainer = document.getElementById('navTabs');
  navTabsContainer?.addEventListener('click', (e) => {
    const btn = e.target.closest('.nav-tab');
    if (btn) {
      const target = btn.getAttribute('data-tab');
      if (target) switchTab(target);
    }
  });

  document.getElementById('quickAuditBtn')?.addEventListener('click', () => switchTab('audit-single'));
  document.getElementById('openAddVendorTopBtn')?.addEventListener('click', () => {
    switchTab('vendors');
    openVendorModal();
  });
}

window.switchTab = function(tabName) {
  state.activeTab = tabName;
  document.querySelectorAll('.nav-tab').forEach(t => {
    if (t.getAttribute('data-tab') === tabName) t.classList.add('active');
    else t.classList.remove('active');
  });

  document.querySelectorAll('.tab-pane').forEach(p => {
    if (p.id === `tab-${tabName}`) {
      p.classList.add('active');
      p.style.display = 'block';
    } else {
      p.classList.remove('active');
      p.style.display = 'none';
    }
  });

  if (tabName === 'admin-telemetry') {
    loadAdminTelemetry();
  }

  window.scrollTo({ top: 0, behavior: 'smooth' });
};



// ─── Vendor Master Registry ──────────────────────────────────────────────────
function setupVendorRegistry() {
  document.getElementById('addVendorBtn')?.addEventListener('click', () => openVendorModal());
  document.getElementById('vendorModalClose')?.addEventListener('click', closeVendorModal);
  document.getElementById('vendorModalCancel')?.addEventListener('click', closeVendorModal);

  document.getElementById('vendorSearchInput')?.addEventListener('input', (e) => {
    renderVendorsTable(e.target.value.toLowerCase());
  });

  document.getElementById('vendorForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    await saveVendorForm();
  });
}

async function loadVendors() {
  try {
    const res = await fetch('/api/vendors');
    if (!res.ok) return;
    const vendors = await res.json();
    state.vendors = vendors;
    renderVendorsTable();
    updateVendorCounts();
  } catch (err) {
    console.error('Failed to load vendors:', err);
  }
}

function renderVendorsTable(filter = '') {
  const tbody = document.getElementById('vendorsBody');
  if (!tbody) return;

  const filtered = state.vendors.filter(v => {
    if (!filter) return true;
    const s = filter.toLowerCase();
    const name = (v.vendor_name || v.name || '').toLowerCase();
    const domain = (v.verified_domain || v.domain || '').toLowerCase();
    const bank = (v.bank_account_number || '').toLowerCase();
    const cat = (v.category || '').toLowerCase();
    return name.includes(s) || domain.includes(s) || bank.includes(s) || cat.includes(s);
  });

  if (filtered.length === 0) {
    tbody.innerHTML = `
      <tr class="empty-row">
        <td colspan="8">${filter ? 'No vendors match your search.' : 'No vendors registered yet. Click "+ Add New Vendor" to register one.'}</td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = filtered.map(v => {
    const status = v.status || 'ACTIVE';
    const statusClass = status === 'ACTIVE' ? 'badge-clean' : (status === 'BLACKLISTED' ? 'badge-hold' : 'badge-elevated');
    const name = v.vendor_name || v.name || 'Unknown';
    const domain = v.verified_domain || v.domain || '';
    const routing = v.bank_routing_code || v.routing_number || '';
    const avgSpend = v.avg_invoice_amount ? `$${Number(v.avg_invoice_amount).toLocaleString(undefined, {minimumFractionDigits:2})}` : '—';

    return `
      <tr>
        <td><code style="color:#818cf8; font-size:0.78rem;">${escapeHtml(v.vendor_id || v.id || '—')}</code></td>
        <td>
          <div style="font-weight:600; color:var(--text-primary);">${escapeHtml(name)}</div>
          <div style="font-size:0.75rem; color:var(--text-muted);">${escapeHtml(v.category || 'General')}</div>
        </td>
        <td>
          <div style="font-family:var(--font-mono); color:#93c5fd;">${escapeHtml(domain)}</div>
          <div style="font-size:0.72rem; color:var(--text-muted);">${escapeHtml(v.primary_email || '')}</div>
        </td>
        <td>
          <div class="bank-info-cell">
            <div><span class="bank-label">Acct:</span> ${escapeHtml(v.bank_account_number || '—')}</div>
            <div><span class="bank-label">Routing:</span> ${escapeHtml(routing || '—')}</div>
          </div>
        </td>
        <td>
          <div style="font-family:var(--font-mono); font-weight:600; color:#34d399;">
            ${escapeHtml(v.contact_phone || 'Not configured')}
          </div>
        </td>
        <td><span style="font-family:var(--font-mono); font-weight:600;">${avgSpend}</span></td>
        <td><span class="badge ${statusClass}">${status}</span></td>
        <td>
          <div style="display:flex; gap:6px;">
            <button class="btn btn-ghost btn-sm" onclick="editVendor('${v.vendor_id || v.id}')" title="Edit Vendor">✏️</button>
            <button class="btn btn-ghost btn-sm" onclick="quickAuditVendorDomain('${domain}', '${escapeHtml(name)}')" title="Audit Invoice for this Vendor">⚡ Audit</button>
            <button class="btn btn-ghost btn-sm text-red" onclick="deleteVendor('${v.vendor_id || v.id}')" title="Delete Vendor">🗑️</button>
          </div>
        </td>
      </tr>
    `;
  }).join('');
}

function updateVendorCounts() {
  const total = state.vendors.length;
  const active = state.vendors.filter(v => (v.status || 'ACTIVE') === 'ACTIVE').length;
  const review = state.vendors.filter(v => v.status === 'UNDER_REVIEW').length;
  const blacklisted = state.vendors.filter(v => v.status === 'BLACKLISTED').length;

  const setTxt = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
  setTxt('navVendorCount', total);
  setTxt('tVendors', total);
  setTxt('statVendorTotal', total);
  setTxt('statVendorActive', active);
  setTxt('statVendorReview', review);
  setTxt('statVendorBlacklisted', blacklisted);
}

function openVendorModal(vendorId = null) {
  const modal = document.getElementById('vendorModal');
  const title = document.getElementById('vendorModalTitle');
  const form = document.getElementById('vendorForm');
  if (!modal || !form) return;
  form.reset();

  if (vendorId) {
    const v = state.vendors.find(item => item.vendor_id === vendorId || item.id === vendorId);
    if (v) {
      if (title) title.textContent = '✏️ Edit Vendor Details';
      document.getElementById('vm_vendor_id').value = v.vendor_id || v.id;
      document.getElementById('vm_name').value = v.vendor_name || v.name || '';
      document.getElementById('vm_domain').value = v.verified_domain || v.domain || '';
      document.getElementById('vm_bank').value = v.bank_account_number || '';
      document.getElementById('vm_routing').value = v.bank_routing_code || v.routing_number || '';
      document.getElementById('vm_phone').value = v.contact_phone || '';
      document.getElementById('vm_email').value = v.primary_email || v.contact_email || '';
      document.getElementById('vm_avg_amount').value = v.avg_invoice_amount || '';
      document.getElementById('vm_category').value = v.category || 'General';
      document.getElementById('vm_status').value = v.status || 'ACTIVE';
      document.getElementById('vm_notes').value = v.notes || '';
    }
  } else {
    if (title) title.textContent = '🏢 Register New Vendor (Supabase)';
    document.getElementById('vm_vendor_id').value = '';
  }

  modal.style.display = 'flex';
}

function closeVendorModal() {
  const modal = document.getElementById('vendorModal');
  if (modal) modal.style.display = 'none';
}

window.editVendor = function(vendorId) {
  openVendorModal(vendorId);
};

window.quickAuditVendorDomain = function(domain, name) {
  switchTab('audit-single');
  document.getElementById('sinv_vendor_name').value = name;
  document.getElementById('sinv_domain').value = domain;
  document.getElementById('sinv_id').value = 'INV-' + Math.floor(1000 + Math.random() * 9000);
  document.getElementById('sinv_amount').value = '4500.00';
  document.getElementById('sinv_bank').value = '123456789';
  document.getElementById('sinv_routing').value = '021000021';
  showToast(`Loaded ${name} for invoice auditing`, 'info');
};

window.deleteVendor = async function(vendorId) {
  if (!confirm(`Are you sure you want to delete this vendor record?`)) return;
  try {
    const res = await fetch(`/api/vendors/${vendorId}`, { method: 'DELETE' });
    if (!res.ok) throw new Error('Delete failed');
    showToast('Vendor removed successfully.', 'success');
    await loadVendors();
  } catch (err) {
    showToast('Failed to delete vendor: ' + err.message, 'error');
  }
};

async function saveVendorForm() {
  const vendorId = document.getElementById('vm_vendor_id').value.trim();
  const name = document.getElementById('vm_name').value.trim();
  const domain = document.getElementById('vm_domain').value.trim().toLowerCase();
  const bank = document.getElementById('vm_bank').value.trim();
  const routing = document.getElementById('vm_routing').value.trim();
  const phone = document.getElementById('vm_phone').value.trim();
  const email = document.getElementById('vm_email').value.trim();
  const avgAmount = parseFloat(document.getElementById('vm_avg_amount').value) || 0.0;
  const category = document.getElementById('vm_category').value;
  const status = document.getElementById('vm_status').value;
  const notes = document.getElementById('vm_notes').value.trim();

  const payload = {
    vendor_id: vendorId || undefined,
    vendor_name: name,
    verified_domain: domain,
    primary_email: email,
    bank_account_number: bank,
    bank_routing_code: routing,
    contact_phone: phone,
    avg_invoice_amount: avgAmount,
    category,
    status,
    notes
  };

  const saveBtn = document.getElementById('vendorModalSave');
  if (saveBtn) {
    saveBtn.disabled = true;
    saveBtn.textContent = 'Saving to Supabase...';
  }

  try {
    const url = vendorId ? `/api/vendors/${vendorId}` : '/api/vendors';
    const method = vendorId ? 'PUT' : 'POST';
    const res = await fetch(url, {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || 'Save failed');
    }

    showToast(`Vendor ${name} saved successfully to Supabase!`, 'success');
    closeVendorModal();
    await loadVendors();
  } catch (err) {
    showToast('Failed to save vendor: ' + err.message, 'error');
  } finally {
    if (saveBtn) {
      saveBtn.disabled = false;
      saveBtn.textContent = '💾 Save to Supabase Registry';
    }
  }
}


// ─── Universal Document Ingestion & Smart Pre-Check ──────────────────────────
function setupUniversalIngestion() {
  const dropzone = document.getElementById('universalDropzone');
  const fileInput = document.getElementById('universalFileInput');
  const browseBtn = document.getElementById('universalBrowseBtn');
  const statusBox = document.getElementById('universalUploadStatus');

  browseBtn?.addEventListener('click', (e) => {
    e.stopPropagation();
    fileInput?.click();
  });

  dropzone?.addEventListener('click', () => fileInput?.click());

  dropzone?.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropzone.classList.add('dragover');
  });

  dropzone?.addEventListener('dragleave', () => {
    dropzone.classList.remove('dragover');
  });

  dropzone?.addEventListener('drop', (e) => {
    e.preventDefault();
    dropzone.classList.remove('dragover');
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleUniversalDocument(e.dataTransfer.files[0]);
    }
  });

  fileInput?.addEventListener('change', (e) => {
    if (e.target.files && e.target.files[0]) {
      handleUniversalDocument(e.target.files[0]);
    }
  });
}

async function handleUniversalDocument(file) {
  const statusBox = document.getElementById('universalUploadStatus');
  const placeholder = document.getElementById('singleResultPlaceholder');
  const resultContent = document.getElementById('singleResultContent');

  if (statusBox) {
    statusBox.style.display = 'block';
    statusBox.className = 'precheck-alert precheck-success';
    statusBox.innerHTML = `<span>⏳ Extracting & Pre-Checking ${file.name}...</span>`;
  }

  const formData = new FormData();
  formData.append('file', file);

  try {
    const res = await fetch('/api/audit/upload', {
      method: 'POST',
      body: formData
    });

    if (!res.ok) {
      const err = await res.json();
      if (statusBox) {
        statusBox.className = 'precheck-alert precheck-error';
        statusBox.innerHTML = `<span>🚫 ${escapeHtml(err.detail || '400 Bad Request: Non-Invoice Document Rejected')}</span>`;
      }
      showToast('Document Rejected: Not a commercial invoice', 'error');
      return;
    }

    const verdict = await res.json();
    if (statusBox) {
      statusBox.className = 'precheck-alert precheck-success';
      statusBox.innerHTML = `<span>✅ <strong>Smart Pre-Check Passed:</strong> Valid commercial invoice markers verified. Analyzed via ${verdict._provider || 'RocketRide'}</span>`;
    }

    if (placeholder) placeholder.style.display = 'none';
    if (resultContent) resultContent.style.display = 'block';
    renderSingleVerdict(verdict, { invoice_amount: verdict._invoice_amount, vendor_name: verdict._vendor_name });

    addAuditVerdictToState(verdict);
    showToast(`Ingested ${file.name}: ${verdict.risk_tier}`, verdict.risk_tier === 'HOLD' ? 'error' : 'success');

  } catch (err) {
    if (statusBox) {
      statusBox.className = 'precheck-alert precheck-error';
      statusBox.innerHTML = `<span>🚫 Error processing document: ${escapeHtml(err.message)}</span>`;
    }
    showToast('Document upload error: ' + err.message, 'error');
  }
}


// ─── Single Invoice Audit ────────────────────────────────────────────────────
function setupSingleAudit() {
  const form = document.getElementById('singleInvoiceForm');
  const fillSampleBtn = document.getElementById('fillSampleFraudBtn');

  fillSampleBtn?.addEventListener('click', () => {
    document.getElementById('sinv_vendor_name').value = 'Acme Corp';
    document.getElementById('sinv_domain').value = 'acnne-corp.com'; // Typosquat!
    document.getElementById('sinv_id').value = 'INV-2026-BEC-9901';
    document.getElementById('sinv_amount').value = '48500.00';
    document.getElementById('sinv_bank').value = '999888777666'; // Changed account!
    document.getElementById('sinv_routing').value = '021000021';
    document.getElementById('sinv_urgency').checked = true;
    document.getElementById('sinv_bank_change').checked = true;
    document.getElementById('sinv_exec_override').checked = true;
    document.getElementById('sinv_notes').value = 'URGENT: Executive memo from Finance Director requesting immediate wire to new beneficiary account. Confidential transaction.';
    showToast('Pre-filled BEC Spoofing attack sample', 'info');
  });

  form?.addEventListener('submit', async (e) => {
    e.preventDefault();
    await runSingleInvoiceAudit();
  });
}

async function runSingleInvoiceAudit() {
  const btn = document.getElementById('runSingleAuditBtn');
  const placeholder = document.getElementById('singleResultPlaceholder');
  const resultContent = document.getElementById('singleResultContent');
  const statusBadge = document.getElementById('singleResultStatusBadge');

  const payload = {
    vendor_name: document.getElementById('sinv_vendor_name').value.trim(),
    sender_domain: document.getElementById('sinv_domain').value.trim().toLowerCase(),
    invoice_number: document.getElementById('sinv_id').value.trim(),
    invoice_amount: parseFloat(document.getElementById('sinv_amount').value) || 0.0,
    bank_account_number: document.getElementById('sinv_bank').value.trim(),
    routing_number: document.getElementById('sinv_routing').value.trim(),
    urgency_language_detected: document.getElementById('sinv_urgency').checked,
    bank_change_request: document.getElementById('sinv_bank_change').checked,
    executive_override_claimed: document.getElementById('sinv_exec_override').checked,
    notes_or_text: document.getElementById('sinv_notes').value.trim()
  };

  if (btn) {
    btn.disabled = true;
    btn.textContent = '🔄 Multi-Agent Pipeline Analyzing...';
  }
  if (statusBadge) {
    statusBadge.textContent = 'Analyzing...';
    statusBadge.className = 'badge badge-purple';
  }

  try {
    const res = await fetch('/api/audit/single', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!res.ok) throw new Error(`Audit failed (${res.status})`);
    const verdict = await res.json();

    if (placeholder) placeholder.style.display = 'none';
    if (resultContent) resultContent.style.display = 'block';
    renderSingleVerdict(verdict, payload);

    addAuditVerdictToState(verdict);
    showToast(`Audit Complete: ${verdict.risk_tier} (Risk: ${verdict.risk_score})`, verdict.risk_tier === 'HOLD' ? 'error' : (verdict.risk_tier === 'ELEVATED' ? 'info' : 'success'));
  } catch (err) {
    showToast('Audit error: ' + err.message, 'error');
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = '🔍 Run Forensic Fraud Audit';
    }
  }
}

function renderSingleVerdict(verdict, invoice) {
  const tier = (verdict.risk_tier || 'ELEVATED').toUpperCase();
  const score = typeof verdict.risk_score === 'number' ? verdict.risk_score.toFixed(2) : '0.50';

  const tierBadge = document.getElementById('verdictTierBadge');
  if (tierBadge) {
    tierBadge.textContent = tier;
    tierBadge.className = 'verdict-tier-badge ' + (tier === 'HOLD' ? 'tier-hold' : (tier === 'CLEAN' ? 'tier-clean' : 'tier-elevated'));
  }

  const setTxt = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
  setTxt('verdictScoreNum', score);
  setTxt('verdictFraudType', verdict.threat_type || verdict.fraud_type || 'None Detected');
  setTxt('verdictConfidence', `${Math.round((verdict.confidence || 0.95) * 100)}%`);
  setTxt('verdictRecommendation', verdict.recommendation || 'AUTO_APPROVE');
  setTxt('verdictLatency', `${verdict._latency_ms || 420}ms`);
  setTxt('verdictSummaryText', verdict.audit_summary || 'No summary available.');

  const rfList = document.getElementById('verdictRiskFactorsList');
  if (rfList) {
    const factors = verdict.key_risk_factors || [];
    if (factors.length > 0) {
      rfList.innerHTML = factors.map(f => `<li class="risk-factor-item">⚠️ ${escapeHtml(f)}</li>`).join('');
    } else {
      rfList.innerHTML = `<li style="font-size:0.8rem; color:#34d399;">✅ No risk factors detected. Master registry cross-check verified.</li>`;
    }
  }

  const oobWrap = document.getElementById('verdictOobWrap');
  if (oobWrap) {
    if (tier === 'HOLD' || verdict.out_of_band_action) {
      oobWrap.style.display = 'block';
      setTxt('verdictOobText', verdict.out_of_band_action || 'Call vendor on verified phone from master registry.');
      setTxt('verdictPhoneBox', `📞 Verified Call-Back Phone: ${verdict.verified_vendor_phone || 'See Supabase Vendor Master'}`);
    } else {
      oobWrap.style.display = 'none';
    }
  }

  state.currentSingleInvoiceId = verdict._invoice_id;
  const actionsWrap = document.getElementById('verdictActions');
  const payBtn = document.getElementById('verdictPayBtn');

  if (actionsWrap) {
    if (tier === 'HOLD') {
      actionsWrap.innerHTML = `
        <button class="btn btn-danger" id="verdictRejectBtn">🚫 Reject & Blacklist</button>
        <button class="btn btn-success" id="verdictReleaseBtn">✅ Approve & Route to ERP</button>
      `;
      document.getElementById('verdictReleaseBtn')?.addEventListener('click', async () => {
        await resolveHitlPayment(verdict._invoice_id, 'APPROVE');
      });
      document.getElementById('verdictRejectBtn')?.addEventListener('click', async () => {
        await resolveHitlPayment(verdict._invoice_id, 'REJECT');
      });
    } else if (tier === 'CLEAN') {
      actionsWrap.innerHTML = `
        <button class="btn btn-pay" id="verdictPayBtn">💳 One-Click Payout (Stripe / RazorpayX)</button>
      `;
      document.getElementById('verdictPayBtn')?.addEventListener('click', () => {
        openPayoutModal(verdict);
      });
    }
  }
}


// ─── Batch Ingestion ─────────────────────────────────────────────────────────
function setupBatchUpload() {
  const dropzone = document.getElementById('dropzone');
  const fileInput = document.getElementById('fileInput');
  const browseBtn = document.getElementById('browseBtn');
  const templateBtn = document.getElementById('demoTemplateBtn');

  browseBtn?.addEventListener('click', () => fileInput?.click());
  dropzone?.addEventListener('click', (e) => {
    if (e.target !== browseBtn && e.target !== templateBtn) fileInput?.click();
  });

  dropzone?.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropzone.classList.add('dragover');
  });

  dropzone?.addEventListener('dragleave', () => {
    dropzone.classList.remove('dragover');
  });

  dropzone?.addEventListener('drop', (e) => {
    e.preventDefault();
    dropzone.classList.remove('dragover');
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleBatchFile(e.dataTransfer.files[0]);
    }
  });

  fileInput?.addEventListener('change', (e) => {
    if (e.target.files && e.target.files[0]) {
      handleBatchFile(e.target.files[0]);
    }
  });

  templateBtn?.addEventListener('click', () => {
    const template = [
      {
        invoice_id: "INV-2026-001",
        vendor_name: "Acme Corp",
        sender_domain: "acme-corp.com",
        invoice_amount: 4500.00,
        bank_account_number: "123456789",
        routing_number: "021000021",
        urgency_language_detected: false
      },
      {
        invoice_id: "INV-2026-002-BEC",
        vendor_name: "Acme Corp",
        sender_domain: "acnne-corp.com",
        invoice_amount: 48500.00,
        bank_account_number: "999888777666",
        routing_number: "021000021",
        urgency_language_detected: true,
        bank_change_request: true,
        notes_or_text: "URGENT: Updated banking info. Wire immediately per CFO."
      }
    ];
    const blob = new Blob([JSON.stringify(template, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'sentinel_batch_template.json';
    a.click();
    showToast('Batch JSON template downloaded', 'info');
  });
}

async function handleBatchFile(file) {
  if (!file.name.endsWith('.json')) {
    showToast('Please upload a valid .json invoice batch file.', 'error');
    return;
  }

  switchTab('dashboard');
  const progressWrap = document.getElementById('dashProgressWrap');
  const progressFill = document.getElementById('progressFill');
  const progressLabel = document.getElementById('progressLabel');

  if (progressWrap) progressWrap.style.display = 'block';
  if (progressFill) progressFill.style.width = '0%';
  if (progressLabel) progressLabel.textContent = 'Starting batch upload...';

  const formData = new FormData();
  formData.append('file', file);

  try {
    const response = await fetch('/api/audit/stream', {
      method: 'POST',
      body: formData
    });

    if (!response.ok) throw new Error(`Upload failed (${response.status})`);

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { value, done } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop();

      for (const line of lines) {
        if (line.startsWith('data: ')) {
          try {
            const evt = JSON.parse(line.slice(6));
            handleBatchEvent(evt);
          } catch (e) {}
        }
      }
    }
    showToast('Batch audit stream completed!', 'success');
  } catch (err) {
    showToast('Batch processing error: ' + err.message, 'error');
  } finally {
    setTimeout(() => { if (progressWrap) progressWrap.style.display = 'none'; }, 4000);
  }
}

function handleBatchEvent(evt) {
  if (evt.type === 'batch_start') {
    state.stats = { total: 0, clean: 0, elevated: 0, hold: 0, fraud_held: 0 };
  } else if (evt.type === 'invoice_result') {
    const { idx, total, verdict, stats } = evt;
    const pct = Math.round((idx / total) * 100);
    const fill = document.getElementById('progressFill');
    const lbl = document.getElementById('progressLabel');
    if (fill) fill.style.width = `${pct}%`;
    if (lbl) lbl.textContent = `${idx} / ${total} (${pct}%)`;

    const setTxt = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    setTxt('tTotal', idx);
    setTxt('tClean', stats.clean);
    setTxt('tElevated', stats.elevated);
    setTxt('tHold', stats.hold);
    setTxt('tFraud', `$${Math.round(stats.fraud_held_usd).toLocaleString()}`);
    setTxt('tProgress', `${stats.wall_time_s}s elapsed`);

    addAuditVerdictToState(verdict);
  }
}


// ─── Audit Log Table & Telemetry ─────────────────────────────────────────────
async function loadAuditHistory() {
  try {
    const res = await fetch('/api/invoices');
    if (!res.ok) return;
    const invoices = await res.json();
    state.auditHistory = [];
    state.hitlHolds = [];

    invoices.forEach(inv => {
      let verdict = inv.raw_payload || {};
      verdict._invoice_id = inv.invoice_number || inv.id;
      verdict._vendor_name = inv.vendor_name || 'Vendor';
      verdict._vendor_domain = inv.verified_domain || '';
      verdict._invoice_amount = inv.extracted_amount || 0.0;
      verdict.risk_tier = inv.status || 'CLEAN';
      verdict.risk_score = inv.risk_score || 0.0;
      verdict.threat_type = inv.threat_type;
      verdict.hitl_action = inv.hitl_actor ? inv.status : null;
      verdict.payout_tx_id = inv.payout_tx_id;
      verdict.paid_at = inv.paid_at;

      state.auditHistory.push(verdict);
      if (inv.status === 'HOLD' && !inv.hitl_actor) {
        state.hitlHolds.push(verdict);
      }
    });

    renderAuditTable();
    renderHitlDesk();
    updateTelemetryFromHistory();
  } catch (err) {
    console.warn('Could not load audit history:', err);
  }
}

function addAuditVerdictToState(verdict) {
  state.auditHistory.unshift(verdict);
  renderAuditTable();
  updateTelemetryFromHistory();

  if (verdict.risk_tier === 'HOLD' && !verdict.hitl_action) {
    state.hitlHolds.unshift(verdict);
    renderHitlDesk();
  }
}

function updateTelemetryFromHistory() {
  const total = state.auditHistory.length;
  const clean = state.auditHistory.filter(v => v.risk_tier === 'CLEAN' || v.risk_tier === 'PAID').length;
  const elevated = state.auditHistory.filter(v => v.risk_tier === 'ELEVATED').length;
  const hold = state.auditHistory.filter(v => v.risk_tier === 'HOLD').length;
  const fraudHeld = state.auditHistory
    .filter(v => v.risk_tier === 'HOLD')
    .reduce((sum, v) => sum + (parseFloat(v._invoice_amount) || 0), 0);

  const setTxt = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
  setTxt('tTotal', total);
  setTxt('tClean', clean);
  setTxt('tElevated', elevated);
  setTxt('tHold', hold);
  setTxt('tFraud', `$${Math.round(fraudHeld).toLocaleString()}`);
}

function setupAuditTable() {
  document.getElementById('auditSearchInput')?.addEventListener('input', () => renderAuditTable());
  document.getElementById('riskFilterSelect')?.addEventListener('change', () => renderAuditTable());
  document.getElementById('exportAuditBtn')?.addEventListener('click', () => {
    const blob = new Blob([JSON.stringify(state.auditHistory, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sentinel_audit_log_${new Date().toISOString().slice(0,10)}.json`;
    a.click();
    showToast('Exported audit log as JSON', 'info');
  });
}

function renderAuditTable() {
  const tbody = document.getElementById('resultsBody');
  if (!tbody) return;

  const search = (document.getElementById('auditSearchInput')?.value || '').toLowerCase();
  const tierFilter = document.getElementById('riskFilterSelect')?.value || 'ALL';

  const filtered = state.auditHistory.filter(v => {
    if (tierFilter !== 'ALL' && v.risk_tier !== tierFilter) return false;
    if (!search) return true;
    const inv = (v._invoice_id || '').toLowerCase();
    const vendor = (v._vendor_name || '').toLowerCase();
    const domain = (v._vendor_domain || '').toLowerCase();
    const ftype = (v.threat_type || v.fraud_type || '').toLowerCase();
    const summ = (v.audit_summary || '').toLowerCase();
    return inv.includes(search) || vendor.includes(search) || domain.includes(search) || ftype.includes(search) || summ.includes(search);
  });

  if (filtered.length === 0) {
    tbody.innerHTML = `
      <tr class="empty-row">
        <td colspan="9">No audit records match the current filters.</td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = filtered.map(v => {
    const tier = (v.risk_tier || 'ELEVATED').toUpperCase();
    let tierBadgeHtml = '';

    if (tier === 'PAID') {
      tierBadgeHtml = `<span class="badge badge-paid">✅ PAID</span>`;
    } else if (tier === 'HOLD') {
      tierBadgeHtml = `<span class="badge badge-hold">🔴 HOLD</span>`;
    } else if (tier === 'ELEVATED') {
      tierBadgeHtml = `<span class="badge badge-elevated">⚠️ ELEVATED</span>`;
    } else {
      tierBadgeHtml = `<span class="badge badge-clean">✅ CLEAN</span>`;
    }

    const score = typeof v.risk_score === 'number' ? v.risk_score.toFixed(2) : '0.50';
    const scoreColorClass = v.risk_score >= 0.61 ? 'score-high' : (v.risk_score >= 0.26 ? 'score-medium' : 'score-low');
    const amount = v._invoice_amount ? `$${Number(v._invoice_amount).toLocaleString(undefined, {minimumFractionDigits:2})}` : '$0.00';

    let actionBtn = '';
    if (tier === 'PAID') {
      actionBtn = `<span style="font-family:var(--font-mono); font-size:0.72rem; color:#34d399;">${escapeHtml(v.payout_tx_id || 'Settled')}</span>`;
    } else if (tier === 'HOLD') {
      if (v.hitl_action) {
        actionBtn = `<span class="badge ${v.hitl_action === 'APPROVED' || v.hitl_action === 'RELEASED' ? 'badge-clean' : 'badge-hold'}">${v.hitl_action}</span>`;
      } else {
        actionBtn = `<button class="btn btn-danger btn-sm" onclick="openHitlActionModal('${v._invoice_id}')">Resolve Hold</button>`;
      }
    } else if (tier === 'CLEAN' || v.hitl_action === 'APPROVED') {
      actionBtn = `<button class="btn btn-pay btn-sm" onclick="openPayoutModal('${v._invoice_id}')">💳 Pay Now</button>`;
    } else {
      actionBtn = `<span style="font-size:0.75rem; color:var(--text-muted);">In Review</span>`;
    }

    return `
      <tr>
        <td><code style="color:#93c5fd; font-weight:600;">${escapeHtml(v._invoice_id || '—')}</code></td>
        <td>
          <div style="font-weight:600; color:var(--text-primary);">${escapeHtml(v._vendor_name || 'Unknown')}</div>
          <div style="font-size:0.75rem; font-family:var(--font-mono); color:var(--text-muted);">${escapeHtml(v._vendor_domain || '')}</div>
        </td>
        <td><span style="font-family:var(--font-mono); font-weight:700;">${amount}</span></td>
        <td><span class="score-badge ${scoreColorClass}">${score}</span></td>
        <td>${tierBadgeHtml}</td>
        <td><code style="color:#f87171; font-size:0.78rem;">${v.threat_type || v.fraud_type || '—'}</code></td>
        <td><span style="font-family:var(--font-mono); font-size:0.75rem;">${v._latency_ms || 400}ms</span></td>
        <td><div style="max-width:320px; font-size:0.78rem; line-height:1.3; color:var(--text-secondary);">${escapeHtml(v.audit_summary || '')}</div></td>
        <td>${actionBtn}</td>
      </tr>
    `;
  }).join('');
}


// ─── HITL Desk ───────────────────────────────────────────────────────────────
function renderHitlDesk() {
  const container = document.getElementById('hitlCards');
  const navBadge = document.getElementById('navHitlCount');
  const deskCount = document.getElementById('hitlDeskCount');
  if (!container) return;

  const pending = state.hitlHolds.filter(h => !h.hitl_action);
  if (deskCount) deskCount.textContent = `${pending.length} Pending Holds`;

  if (navBadge) {
    if (pending.length > 0) {
      navBadge.style.display = 'inline-block';
      navBadge.textContent = pending.length;
    } else {
      navBadge.style.display = 'none';
    }
  }

  if (pending.length === 0) {
    container.innerHTML = `
      <div class="empty-hitl-box">
        <div class="empty-icon">✅</div>
        <h3>No Pending Payment Holds</h3>
        <p>All audited invoices are clear or have already been resolved by an analyst.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = pending.map(v => {
    const amount = v._invoice_amount ? `$${Number(v._invoice_amount).toLocaleString(undefined, {minimumFractionDigits:2})}` : '$0.00';
    return `
      <div class="hitl-card">
        <div class="hitl-card-header">
          <div class="hitl-card-vendor">${escapeHtml(v._vendor_name || 'Unknown')}</div>
          <div class="hitl-card-amount">${amount}</div>
        </div>
        <div style="font-size:0.8rem; font-family:var(--font-mono); color:#93c5fd; margin-bottom:0.5rem;">
          Invoice: ${escapeHtml(v._invoice_id)} · Domain: ${escapeHtml(v._vendor_domain || '')}
        </div>
        <div style="font-size:0.82rem; color:#fca5a5; margin-bottom:0.75rem; background:rgba(239,68,68,0.1); padding:0.4rem 0.6rem; border-radius:4px;">
          🚩 <strong>${v.threat_type || v.fraud_type || 'Suspicious'}</strong>: ${escapeHtml(v.audit_summary || '')}
        </div>
        <div style="font-size:0.78rem; color:#fecaca; margin-bottom:0.75rem;">
          📞 <strong>Required Action:</strong> ${escapeHtml(v.out_of_band_action || 'Call vendor master phone before release.')}
        </div>
        <div class="hitl-card-actions">
          <button class="btn btn-danger btn-sm" onclick="resolveHitlPayment('${v._invoice_id}', 'REJECT')">🚫 Reject & Blacklist</button>
          <button class="btn btn-success btn-sm" onclick="resolveHitlPayment('${v._invoice_id}', 'APPROVE')">✅ Approve & Route to ERP</button>
        </div>
      </div>
    `;
  }).join('');
}

window.openHitlActionModal = function(invoiceId) {
  const item = state.auditHistory.find(v => v._invoice_id === invoiceId);
  if (!item) return;

  const modal = document.getElementById('hitlActionModal');
  const body = document.getElementById('hitlModalBody');
  const releaseBtn = document.getElementById('modalRelease');
  const rejectBtn = document.getElementById('modalReject');
  if (!modal || !body || !releaseBtn || !rejectBtn) return;

  const amount = item._invoice_amount ? `$${Number(item._invoice_amount).toLocaleString(undefined, {minimumFractionDigits:2})}` : '$0.00';
  body.innerHTML = `
    <div style="margin-bottom:1rem;">
      <h3 style="font-size:1.1rem; color:var(--text-primary);">${escapeHtml(item._vendor_name)} — <span style="color:#f87171;">${amount}</span></h3>
      <p style="font-family:var(--font-mono); font-size:0.8rem; color:#93c5fd;">Invoice ID: ${item._invoice_id}</p>
    </div>
    <div style="background:rgba(239,68,68,0.1); border:1px solid rgba(239,68,68,0.3); padding:0.75rem; border-radius:6px; margin-bottom:1rem;">
      <div style="font-weight:700; color:#f87171; font-size:0.85rem;">🚨 Trigger: ${item.threat_type || item.fraud_type || 'BEC Alert'}</div>
      <div style="font-size:0.82rem; color:var(--text-secondary); margin-top:0.25rem;">${escapeHtml(item.audit_summary || '')}</div>
    </div>
    <div style="background:rgba(255,255,255,0.03); padding:0.75rem; border-radius:6px; font-size:0.82rem;">
      <strong>Out-of-Band Call Action:</strong>
      <p style="color:#fecaca; margin-top:0.25rem;">${escapeHtml(item.out_of_band_action || 'Call verified master contact before releasing payment.')}</p>
    </div>
  `;

  releaseBtn.onclick = async () => {
    await resolveHitlPayment(invoiceId, 'APPROVE');
    modal.style.display = 'none';
  };
  rejectBtn.onclick = async () => {
    await resolveHitlPayment(invoiceId, 'REJECT');
    modal.style.display = 'none';
  };

  modal.style.display = 'flex';
};

window.resolveHitlPayment = async function(invoiceId, action) {
  try {
    const res = await fetch(`/api/invoices/${invoiceId}/hitl`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action, actor: state.user?.email || 'AP Security Analyst' })
    });
    if (!res.ok) throw new Error('HITL update failed');

    const item = state.auditHistory.find(v => v._invoice_id === invoiceId);
    if (item) item.hitl_action = action === 'APPROVE' ? 'APPROVED' : 'REJECTED';

    const holdItem = state.hitlHolds.find(v => v._invoice_id === invoiceId);
    if (holdItem) holdItem.hitl_action = action === 'APPROVE' ? 'APPROVED' : 'REJECTED';

    renderAuditTable();
    renderHitlDesk();
    showToast(`Invoice ${invoiceId}: Marked as ${action === 'APPROVE' ? 'Approved & Ready for Payout' : 'Rejected'}`, 'success');
  } catch (err) {
    showToast('Failed to resolve hold: ' + err.message, 'error');
  }
};


// ─── One-Click Payout Gateway (Stripe Connect / RazorpayX) ────────────────────
function setupPayoutGateway() {
  const modal = document.getElementById('payoutModal');
  const closeBtn = document.getElementById('payoutModalClose');
  const cancelBtn = document.getElementById('payoutModalCancel');
  const confirmBtn = document.getElementById('payoutConfirmBtn');

  closeBtn?.addEventListener('click', () => { if (modal) modal.style.display = 'none'; });
  cancelBtn?.addEventListener('click', () => { if (modal) modal.style.display = 'none'; });

  confirmBtn?.addEventListener('click', async () => {
    if (!state.selectedPayoutInvoice) return;
    const invId = state.selectedPayoutInvoice._invoice_id;
    const method = document.getElementById('payoutGatewaySelect').value;
    const actor = document.getElementById('payoutActor').value.trim();

    confirmBtn.disabled = true;
    confirmBtn.textContent = '🚀 Processing Payout via Gateway...';

    try {
      const res = await fetch(`/api/invoices/${invId}/pay`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payment_method: method, actor })
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || 'Payout failed');
      }

      const result = await res.json();
      showToast(`Payment of $${state.selectedPayoutInvoice._invoice_amount} settled via ${method}! Ref: ${result.payout_tx_id}`, 'success');

      // Update in local state
      const item = state.auditHistory.find(v => v._invoice_id === invId);
      if (item) {
        item.risk_tier = 'PAID';
        item.payout_tx_id = result.payout_tx_id;
      }

      modal.style.display = 'none';
      renderAuditTable();
      updateTelemetryFromHistory();
    } catch (err) {
      showToast('Payment failed: ' + err.message, 'error');
    } finally {
      confirmBtn.disabled = false;
      confirmBtn.textContent = '🚀 Confirm & Release Payment';
    }
  });
}

window.openPayoutModal = function(invoiceInput) {
  let item = null;
  if (typeof invoiceInput === 'string') {
    item = state.auditHistory.find(v => v._invoice_id === invoiceInput);
  } else {
    item = invoiceInput;
  }
  if (!item) return;

  state.selectedPayoutInvoice = item;
  const modal = document.getElementById('payoutModal');
  if (!modal) return;

  const setTxt = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
  setTxt('payModalInvoiceId', item._invoice_id);
  setTxt('payModalVendor', item._vendor_name);
  setTxt('payModalBank', 'Verified Master Account (Checked)');
  setTxt('payModalAmount', `$${Number(item._invoice_amount || 0).toLocaleString(undefined, {minimumFractionDigits:2})}`);

  modal.style.display = 'flex';
};


// ─── IMAP Email Polling & Logs ────────────────────────────────────────────────
function setupEmailPolling() {
  const headerBtn = document.getElementById('syncMailsHeaderBtn');
  const tabBtn = document.getElementById('syncMailsTabBtn');

  const handleSync = async () => {
    const icon = document.getElementById('syncMailsIcon');
    if (icon) icon.className = 'spin-icon';

    showToast('Polling IMAP inbox for vendor invoice attachments...', 'info');
    try {
      const res = await fetch('/api/email/sync', { method: 'POST' });
      const data = await res.json();
      showToast(data.message || 'Email sync complete', 'success');
      await loadEmailLogs();
      await loadAuditHistory();
    } catch (err) {
      showToast('Email sync failed: ' + err.message, 'error');
    } finally {
      if (icon) icon.className = '';
    }
  };

  headerBtn?.addEventListener('click', handleSync);
  tabBtn?.addEventListener('click', handleSync);
}

async function loadEmailLogs() {
  try {
    const res = await fetch('/api/email/logs');
    if (!res.ok) return;
    state.emailLogs = await res.json();
    renderEmailLogsTable();
  } catch (err) {
    console.warn('Could not load email logs:', err);
  }
}

function renderEmailLogsTable() {
  const tbody = document.getElementById('emailLogsBody');
  if (!tbody) return;

  if (state.emailLogs.length === 0) {
    tbody.innerHTML = `
      <tr class="empty-row">
        <td colspan="5">No IMAP email logs found yet. Click "Analyze Unread Mails" to check inbox.</td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = state.emailLogs.map(l => {
    const dateStr = l.created_at ? new Date(l.created_at).toLocaleTimeString() : '—';
    const status = l.status || 'PROCESSED';
    const badgeClass = status === 'CLEAN' ? 'badge-clean' : (status === 'HOLD' ? 'badge-hold' : 'badge-elevated');

    return `
      <tr>
        <td><span style="font-family:var(--font-mono); font-size:0.78rem;">${dateStr}</span></td>
        <td><code>${escapeHtml(l.sender_email)}</code></td>
        <td><div style="font-weight:500;">${escapeHtml(l.subject || 'No Subject')}</div></td>
        <td>${l.attachment_processed ? '✅ Yes (Invoice Parsed)' : '❌ None / Skipped'}</td>
        <td><span class="badge ${badgeClass}">${status}</span></td>
      </tr>
    `;
  }).join('');
}


// ─── Settings & Reconnect ─────────────────────────────────────────────────────
async function loadRocketRideConfig() {
  try {
    const res = await fetch('/api/rocketride/config');
    if (!res.ok) return;
    const cfg = await res.json();
    
    const uriInput = document.getElementById('cfg_rocketride_uri');
    const keyInput = document.getElementById('cfg_rocketride_key');
    const badge = document.getElementById('cfgRocketRideBadge');

    if (uriInput) uriInput.value = cfg.rocketride_uri || 'ws://localhost:5565';
    if (keyInput) keyInput.value = cfg.rocketride_apikey || 'local';

    if (badge) {
      if (cfg.is_connected) {
        badge.className = 'badge badge-clean';
        badge.textContent = '🟢 Online: RocketRide Engine';
      } else {
        badge.className = 'badge badge-purple';
        badge.textContent = '🟣 Direct AI Active (Fallback)';
      }
    }
  } catch (e) {
    console.warn('Could not load RocketRide config:', e);
  }
}

function setupSettings() {
  const modal = document.getElementById('settingsModal');
  const btn = document.getElementById('settingsBtn');
  const closeBtn = document.getElementById('settingsModalClose');
  const form = document.getElementById('supabaseConfigForm');
  const copySqlBtn = document.getElementById('copySqlBtn');
  const rrForm = document.getElementById('rocketrideConfigForm');
  const rrBtn = document.getElementById('rocketrideReconnectBtn');

  btn?.addEventListener('click', async () => {
    if (modal) {
      document.getElementById('cfg_supabase_url').value = state.supabaseConfig.url || '';
      document.getElementById('cfg_supabase_anon_key').value = state.supabaseConfig.anon_key || '';
      modal.style.display = 'flex';
      await loadRocketRideConfig();
    }
  });

  closeBtn?.addEventListener('click', () => {
    if (modal) modal.style.display = 'none';
  });

  rrForm?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const uri = document.getElementById('cfg_rocketride_uri').value.trim();
    const apikey = document.getElementById('cfg_rocketride_key').value.trim();

    if (rrBtn) {
      rrBtn.disabled = true;
      rrBtn.textContent = '🔄 Testing Connection...';
    }

    try {
      const res = await fetch('/api/rocketride/reconnect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rocketride_uri: uri, rocketride_apikey: apikey })
      });
      const data = await res.json();
      showToast(data.message, data.is_connected ? 'success' : 'info');
      await loadSystemHealth();
      await loadRocketRideConfig();
    } catch (err) {
      showToast('Connection error: ' + err.message, 'error');
    } finally {
      if (rrBtn) {
        rrBtn.disabled = false;
        rrBtn.textContent = '🔄 Test & Reconnect RocketRide';
      }
    }
  });

  form?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = document.getElementById('cfg_supabase_url').value.trim();
    const key = document.getElementById('cfg_supabase_anon_key').value.trim();

    try {
      const res = await fetch('/api/auth/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ supabase_url: url, supabase_anon_key: key })
      });
      if (!res.ok) throw new Error('Failed to update config');
      showToast('Supabase configuration updated successfully!', 'success');
      if (modal) modal.style.display = 'none';
      await loadSystemHealth();
      await initSupabaseAuth();
      await loadVendors();
    } catch (err) {
      showToast('Error: ' + err.message, 'error');
    }
  });

  copySqlBtn?.addEventListener('click', async () => {
    try {
      const res = await fetch('/api/schema/sql');
      const data = await res.json();
      await navigator.clipboard.writeText(data.sql);
      showToast('Supabase SQL Schema copied to clipboard!', 'success');
    } catch (err) {
      showToast('Failed to copy SQL: ' + err.message, 'error');
    }
  });
}

// ─── Admin Telemetry Panel ───────────────────────────────────────────────────
function setupAdminTelemetry() {
  document.getElementById('refreshTelemetryBtn')?.addEventListener('click', loadAdminTelemetry);
}

async function loadAdminTelemetry() {
  try {
    const res = await fetch('/api/admin/telemetry', {
      headers: {
        'Authorization': state.user?.access_token ? `Bearer ${state.user.access_token}` : 'Bearer admin_secret_token',
        'X-Sentinel-Role': 'admin',
        'X-Sentinel-User': state.user?.email || 'admin@sentinel.finance'
      }
    });
    if (!res.ok) return;
    const data = await res.json();

    const admEngineState = document.getElementById('admEngineState');
    const admEngineUri = document.getElementById('admEngineUri');
    const admAvgLatency = document.getElementById('admAvgLatency');
    const admActiveSessions = document.getElementById('admActiveSessions');
    const admSupabaseStatus = document.getElementById('admSupabaseStatus');
    const admProjectRef = document.getElementById('admProjectRef');
    const admGroqToken = document.getElementById('admGroqToken');
    const admGeminiToken = document.getElementById('admGeminiToken');

    if (admEngineState) admEngineState.textContent = data.is_connected ? 'Active (Port 5565)' : 'Direct Failover';
    if (admEngineUri) admEngineUri.textContent = data.rocketride_uri || 'ws://localhost:5565';
    if (admAvgLatency) admAvgLatency.textContent = (data.metrics?.avg_latency_ms || 120) + ' ms';
    if (admActiveSessions) admActiveSessions.textContent = (data.groq_session_token ? 1 : 0) + (data.gemini_session_token ? 1 : 0) + ' Sessions';
    if (admSupabaseStatus) admSupabaseStatus.textContent = 'Connected (17.6)';
    if (admProjectRef) admProjectRef.textContent = data.database?.project_ref || 'zoixzkvakuiqoebpwodv';
    if (admGroqToken) admGroqToken.textContent = data.groq_session_token ? `Session: ${data.groq_session_token}` : 'Ready / Active';
    if (admGeminiToken) admGeminiToken.textContent = data.gemini_session_token ? `Session: ${data.gemini_session_token}` : 'Failover Ready';
  } catch (err) {
    console.warn('Telemetry fetch note:', err);
  }
}

function setupModals() {

  document.getElementById('hitlModalClose')?.addEventListener('click', () => {
    const modal = document.getElementById('hitlActionModal');
    if (modal) modal.style.display = 'none';
  });

  document.querySelectorAll('.modal-overlay').forEach(overlay => {
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) {
        overlay.style.display = 'none';
      }
    });
  });
}


// ─── Utilities ────────────────────────────────────────────────────────────────
function showToast(message, type = 'info') {
  const container = document.getElementById('toastContainer');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  const icon = type === 'success' ? '✅' : (type === 'error' ? '🚫' : 'ℹ️');
  toast.innerHTML = `<span>${icon}</span> <span>${escapeHtml(message)}</span>`;

  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

function escapeHtml(str) {
  if (typeof str !== 'string') return str || '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
}
