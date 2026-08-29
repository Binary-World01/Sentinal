/**
 * AP Payment Fraud Sentinel — Frontend Application
 * =================================================
 * Powered by Supabase Authentication, Supabase Vendor Registry,
 * and RocketRide Multi-Agent Forensic AI.
 */

// ─── State Management ────────────────────────────────────────────────────────
const state = {
  supabase: null,
  user: null,
  supabaseConfig: { url: '', anon_key: '', is_configured: false },
  vendors: [],
  auditHistory: [],
  hitlHolds: [],
  activeTab: 'dashboard',
  currentSingleInvoiceId: null,
  stats: { total: 0, clean: 0, elevated: 0, hold: 0, fraud_held: 0 },
  authMode: 'signin', // 'signin' or 'signup'
};

// ─── DOM Ready Initialization ────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  try {
    setupNavigation();
    setupModals();
    setupAuth();
    setupVendorRegistry();
    setupSingleAudit();
    setupBatchUpload();
    setupSettings();
    setupAuditTable();
  } catch (err) {
    console.error('Error in initial setup:', err);
  }

  // Load backend health and Supabase config asynchronously
  await loadSystemHealth();
  await initSupabaseAuth();
  await loadVendors();
  await loadAuditHistory();
});


// ─── System Health & Supabase Status ─────────────────────────────────────────
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
    console.warn('Health check warning:', err);
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
      
      // Check active session
      try {
        const { data: { session } } = await state.supabase.auth.getSession();
        if (session && session.user) {
          setUserSession(session.user);
        }
      } catch (e) {}

      // Listen for auth state changes
      state.supabase.auth.onAuthStateChange((event, session) => {
        if (session && session.user) {
          setUserSession(session.user);
        } else {
          clearUserSession();
        }
      });
    } else {
      // Local storage fallback for session
      const localUser = localStorage.getItem('sentinel_local_user');
      if (localUser) {
        try { setUserSession(JSON.parse(localUser)); } catch (e) {}
      }
    }
  } catch (err) {
    console.warn('Supabase Auth init note:', err);
  }
}

function setUserSession(user) {
  state.user = user;
  const wrap = document.getElementById('userAuthWrap');
  if (!wrap) return;
  const email = user.email || 'analyst@sentinel.io';
  const initial = email.charAt(0).toUpperCase();

  wrap.innerHTML = `
    <div class="user-profile-chip" title="${email}">
      <div class="user-avatar">${initial}</div>
      <span class="user-email-text">${email}</span>
      <button class="signout-btn" id="signOutBtn" title="Sign Out">✕</button>
    </div>
  `;

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
        // Local mode authentication fallback
        const mockUser = { email, id: 'local_' + Date.now(), role: 'AP Security Analyst' };
        localStorage.setItem('sentinel_local_user', JSON.stringify(mockUser));
        setUserSession(mockUser);
        showToast(`Signed in as ${email} (Local Registry Mode)`, 'success');
      }
      if (authModal) authModal.style.display = 'none';
    } catch (err) {
      if (authErrorMsg) {
        authErrorMsg.textContent = err.message || 'Authentication failed. Please check credentials.';
        authErrorMsg.style.display = 'block';
      }
    } finally {
      authSubmitBtn.disabled = false;
      authSubmitBtn.textContent = state.authMode === 'signin' ? 'Sign In with Supabase' : 'Create Account with Supabase';
    }
  });
}


// ─── Navigation Tabs ─────────────────────────────────────────────────────────
function setupNavigation() {
  const navTabsContainer = document.getElementById('navTabs');
  
  // Delegated tab click
  navTabsContainer?.addEventListener('click', (e) => {
    const btn = e.target.closest('.nav-tab');
    if (btn) {
      const target = btn.getAttribute('data-tab');
      if (target) switchTab(target);
    }
  });

  // Top action bar buttons
  document.getElementById('quickAuditBtn')?.addEventListener('click', () => switchTab('audit-single'));
  document.getElementById('openAddVendorTopBtn')?.addEventListener('click', () => {
    switchTab('vendors');
    openVendorModal();
  });

  // Badge click to open Settings
  document.getElementById('supabaseBadge')?.addEventListener('click', () => {
    const modal = document.getElementById('settingsModal');
    if (modal) {
      document.getElementById('cfg_supabase_url').value = state.supabaseConfig.url || '';
      document.getElementById('cfg_supabase_anon_key').value = state.supabaseConfig.anon_key || '';
      modal.style.display = 'flex';
    }
  });
}

window.switchTab = function(tabName) {
  state.activeTab = tabName;

  // Update tabs UI
  document.querySelectorAll('.nav-tab').forEach(t => {
    if (t.getAttribute('data-tab') === tabName) t.classList.add('active');
    else t.classList.remove('active');
  });

  // Update panes
  document.querySelectorAll('.tab-pane').forEach(p => {
    if (p.id === `tab-${tabName}`) {
      p.classList.add('active');
      p.style.display = 'block';
    } else {
      p.classList.remove('active');
      p.style.display = 'none';
    }
  });

  // Scroll to top
  window.scrollTo({ top: 0, behavior: 'smooth' });
};


// ─── Vendor Registry (Supabase CRUD) ──────────────────────────────────────────
function setupVendorRegistry() {
  document.getElementById('addVendorBtn')?.addEventListener('click', () => openVendorModal());
  document.getElementById('vendorModalClose')?.addEventListener('click', closeVendorModal);
  document.getElementById('vendorModalCancel')?.addEventListener('click', closeVendorModal);

  // Search filter
  document.getElementById('vendorSearchInput')?.addEventListener('input', (e) => {
    renderVendorsTable(e.target.value.toLowerCase());
  });

  // Vendor form submit
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
    const name = (v.name || '').toLowerCase();
    const domain = (v.domain || '').toLowerCase();
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
    const aliases = Array.isArray(v.known_domains) ? v.known_domains.filter(d => d !== v.domain) : [];
    const aliasHtml = aliases.length > 0 ? `<div style="font-size:0.72rem; color:var(--text-muted);">Aliases: ${aliases.join(', ')}</div>` : '';
    const avgSpend = v.avg_invoice_amount ? `$${Number(v.avg_invoice_amount).toLocaleString(undefined, {minimumFractionDigits:2})}` : '—';

    return `
      <tr>
        <td><code style="color:#818cf8; font-size:0.78rem;">${escapeHtml(v.vendor_id || '—')}</code></td>
        <td>
          <div style="font-weight:600; color:var(--text-primary);">${escapeHtml(v.name)}</div>
          <div style="font-size:0.75rem; color:var(--text-muted);">${escapeHtml(v.category || 'General')}</div>
        </td>
        <td>
          <div style="font-family:var(--font-mono); color:#93c5fd;">${escapeHtml(v.domain)}</div>
          ${aliasHtml}
        </td>
        <td>
          <div class="bank-info-cell">
            <div><span class="bank-label">Acct:</span> ${escapeHtml(v.bank_account_number || '—')}</div>
            <div><span class="bank-label">Routing:</span> ${escapeHtml(v.routing_number || '—')}</div>
          </div>
        </td>
        <td>
          <div style="font-family:var(--font-mono); font-weight:600; color:#34d399;">
            ${escapeHtml(v.contact_phone || 'Not configured')}
          </div>
          <div style="font-size:0.72rem; color:var(--text-muted);">${escapeHtml(v.contact_email || '')}</div>
        </td>
        <td><span style="font-family:var(--font-mono); font-weight:600;">${avgSpend}</span></td>
        <td><span class="badge ${statusClass}">${status}</span></td>
        <td>
          <div style="display:flex; gap:6px;">
            <button class="btn btn-ghost btn-sm" onclick="editVendor('${v.vendor_id}')" title="Edit Vendor">✏️</button>
            <button class="btn btn-ghost btn-sm" onclick="quickAuditVendorDomain('${v.domain}', '${escapeHtml(v.name)}')" title="Audit Invoice for this Vendor">⚡ Audit</button>
            <button class="btn btn-ghost btn-sm text-red" onclick="deleteVendor('${v.vendor_id}')" title="Delete Vendor">🗑️</button>
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
    const v = state.vendors.find(item => item.vendor_id === vendorId);
    if (v) {
      if (title) title.textContent = '✏️ Edit Vendor Details';
      document.getElementById('vm_vendor_id').value = v.vendor_id;
      document.getElementById('vm_name').value = v.name || '';
      document.getElementById('vm_domain').value = v.domain || '';
      document.getElementById('vm_aliases').value = Array.isArray(v.known_domains) ? v.known_domains.join(', ') : '';
      document.getElementById('vm_bank').value = v.bank_account_number || '';
      document.getElementById('vm_routing').value = v.routing_number || '';
      document.getElementById('vm_phone').value = v.contact_phone || '';
      document.getElementById('vm_email').value = v.contact_email || '';
      document.getElementById('vm_avg_amount').value = v.avg_invoice_amount || '';
      document.getElementById('vm_category').value = v.category || 'General Vendor';
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
  document.getElementById('sinv_amount').value = '15000.00';
  document.getElementById('sinv_bank').value = '';
  document.getElementById('sinv_routing').value = '';
  showToast(`Loaded ${name} for invoice auditing`, 'info');
};

window.deleteVendor = async function(vendorId) {
  if (!confirm(`Are you sure you want to delete vendor ${vendorId}?`)) return;
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
  const aliasesRaw = document.getElementById('vm_aliases').value.trim();
  const bank = document.getElementById('vm_bank').value.trim();
  const routing = document.getElementById('vm_routing').value.trim();
  const phone = document.getElementById('vm_phone').value.trim();
  const email = document.getElementById('vm_email').value.trim();
  const avgAmount = parseFloat(document.getElementById('vm_avg_amount').value) || 0.0;
  const category = document.getElementById('vm_category').value;
  const status = document.getElementById('vm_status').value;
  const notes = document.getElementById('vm_notes').value.trim();

  const known_domains = aliasesRaw ? aliasesRaw.split(',').map(s => s.trim().toLowerCase()).filter(Boolean) : [];
  if (domain && !known_domains.includes(domain)) known_domains.push(domain);

  const payload = {
    vendor_id: vendorId || undefined,
    name,
    domain,
    known_domains,
    bank_account_number: bank,
    routing_number: routing,
    contact_phone: phone,
    contact_email: email,
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


// ─── Single Real Invoice Audit ────────────────────────────────────────────────
function setupSingleAudit() {
  const form = document.getElementById('singleInvoiceForm');
  const fillSampleBtn = document.getElementById('fillSampleFraudBtn');

  fillSampleBtn?.addEventListener('click', () => {
    // Fill a realistic BEC attack spoofing Stripe
    document.getElementById('sinv_vendor_name').value = 'Stripe Inc.';
    document.getElementById('sinv_domain').value = 'str1pe.com'; // Typosquat!
    document.getElementById('sinv_id').value = 'INV-2026-BEC-9901';
    document.getElementById('sinv_amount').value = '84500.00';
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
    btn.textContent = '🔄 Agents Analyzing Signals...';
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

    // Render result
    if (placeholder) placeholder.style.display = 'none';
    if (resultContent) resultContent.style.display = 'block';
    renderSingleVerdict(verdict, payload);

    // Add to audit table
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
  setTxt('verdictFraudType', verdict.fraud_type || 'None Detected');
  setTxt('verdictConfidence', `${Math.round((verdict.confidence || 0.95) * 100)}%`);
  setTxt('verdictRecommendation', verdict.recommendation || 'AUTO_APPROVE');
  setTxt('verdictLatency', `${verdict._latency_ms || 420}ms`);
  setTxt('verdictSummaryText', verdict.audit_summary || 'No summary available.');

  // Risk Factors
  const rfList = document.getElementById('verdictRiskFactorsList');
  if (rfList) {
    const factors = verdict.key_risk_factors || [];
    if (factors.length > 0) {
      rfList.innerHTML = factors.map(f => `<li class="risk-factor-item">⚠️ ${escapeHtml(f)}</li>`).join('');
    } else {
      rfList.innerHTML = `<li style="font-size:0.8rem; color:#34d399;">✅ No risk factors detected. Cross-check against master registry verified.</li>`;
    }
  }

  // Out of band action
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

  // Action buttons
  state.currentSingleInvoiceId = verdict._invoice_id;
  const actionsWrap = document.getElementById('verdictActions');
  if (actionsWrap) {
    actionsWrap.innerHTML = `
      <button class="btn btn-danger" id="verdictRejectBtn">🚫 Reject & Blacklist</button>
      <button class="btn btn-success" id="verdictReleaseBtn">✅ Approve & Route to ERP</button>
    `;
    document.getElementById('verdictReleaseBtn')?.addEventListener('click', async () => {
      await resolveHitlPayment(verdict._invoice_id, 'RELEASED');
    });
    document.getElementById('verdictRejectBtn')?.addEventListener('click', async () => {
      await resolveHitlPayment(verdict._invoice_id, 'REJECTED');
    });
  }
}


// ─── Batch File Upload & Stream ───────────────────────────────────────────────
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
        vendor_name: "Cloudflare Global Services",
        sender_domain: "cloudflare.com",
        invoice_amount: 12500.00,
        bank_account_number: "987654321098",
        routing_number: "021000021",
        urgency_language_detected: false
      },
      {
        invoice_id: "INV-2026-002-BEC",
        vendor_name: "Cloudflare Global Services",
        sender_domain: "cloudf1are.com",
        invoice_amount: 75000.00,
        bank_account_number: "111222333444",
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
    showToast('Please upload a valid .json invoice file.', 'error');
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

    if (!response.ok) {
      throw new Error(`Upload failed (${response.status})`);
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { value, done } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop(); // keep last incomplete line

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
    state.stats.total = 0;
    state.stats.clean = 0;
    state.stats.elevated = 0;
    state.stats.hold = 0;
    state.stats.fraud_held = 0;
    const prog = document.getElementById('tProgress');
    if (prog) prog.textContent = `Processing ${evt.total} invoices...`;
  } else if (evt.type === 'invoice_result') {
    const { idx, total, verdict, telemetry } = evt;
    const pct = Math.round((idx / total) * 100);
    const fill = document.getElementById('progressFill');
    const lbl = document.getElementById('progressLabel');
    if (fill) fill.style.width = `${pct}%`;
    if (lbl) lbl.textContent = `${idx} / ${total} (${pct}%)`;

    // Update telemetry
    const setTxt = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    setTxt('tTotal', idx);
    setTxt('tClean', telemetry.clean);
    setTxt('tElevated', telemetry.elevated);
    setTxt('tHold', telemetry.hold);
    setTxt('tFraud', `$${Math.round(telemetry.fraud_held_usd).toLocaleString()}`);
    setTxt('tProgress', `${telemetry.wall_time_s}s elapsed`);

    addAuditVerdictToState(verdict);
  } else if (evt.type === 'batch_complete') {
    const prog = document.getElementById('tProgress');
    if (prog) prog.textContent = `Completed in ${evt.wall_time_s}s`;
    const fill = document.getElementById('progressFill');
    const lbl = document.getElementById('progressLabel');
    if (fill) fill.style.width = '100%';
    if (lbl) lbl.textContent = `${evt.total} / ${evt.total} (Done)`;
  }
}


// ─── Audit Log Table & HITL Queue ────────────────────────────────────────────
async function loadAuditHistory() {
  try {
    const res = await fetch('/api/audit/history');
    if (!res.ok) return;
    const logs = await res.json();
    state.auditHistory = [];
    state.hitlHolds = [];
    logs.forEach(log => {
      let verdict = {};
      try { verdict = JSON.parse(log.raw_verdict || '{}'); } catch(e) {}
      if (!verdict._invoice_id) {
        verdict = {
          _invoice_id: log.invoice_id,
          _vendor_name: log.vendor_name,
          _vendor_domain: log.vendor_domain,
          _invoice_amount: log.invoice_amount,
          risk_tier: log.risk_tier,
          risk_score: log.risk_score,
          fraud_type: log.fraud_type,
          _latency_ms: log.latency_ms,
          audit_summary: log.audit_summary,
          hitl_action: log.hitl_action,
        };
      }
      state.auditHistory.push(verdict);
      if (verdict.risk_tier === 'HOLD' && !verdict.hitl_action) {
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

  // If HOLD, add to HITL Queue
  if (verdict.risk_tier === 'HOLD' && !verdict.hitl_action) {
    state.hitlHolds.unshift(verdict);
    renderHitlDesk();
  }
}

function updateTelemetryFromHistory() {
  const total = state.auditHistory.length;
  const clean = state.auditHistory.filter(v => v.risk_tier === 'CLEAN').length;
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
    const ftype = (v.fraud_type || '').toLowerCase();
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
    const tierClass = tier === 'HOLD' ? 'badge-hold' : (tier === 'CLEAN' ? 'badge-clean' : 'badge-elevated');
    const score = typeof v.risk_score === 'number' ? v.risk_score.toFixed(2) : '0.50';
    const scoreColorClass = v.risk_score >= 0.61 ? 'score-high' : (v.risk_score >= 0.26 ? 'score-medium' : 'score-low');
    const amount = v._invoice_amount ? `$${Number(v._invoice_amount).toLocaleString(undefined, {minimumFractionDigits:2})}` : '$0.00';

    let actionBtn = '';
    if (tier === 'HOLD') {
      if (v.hitl_action) {
        actionBtn = `<span class="badge ${v.hitl_action === 'RELEASED' ? 'badge-clean' : 'badge-hold'}">${v.hitl_action}</span>`;
      } else {
        actionBtn = `<button class="btn btn-danger btn-sm" onclick="openHitlActionModal('${v._invoice_id}')">Resolve Hold</button>`;
      }
    } else {
      actionBtn = `<span style="font-size:0.75rem; color:var(--text-muted);">Auto-Routed</span>`;
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
        <td><span class="badge ${tierClass}">${tier}</span></td>
        <td><code style="color:#f87171; font-size:0.78rem;">${v.fraud_type || '—'}</code></td>
        <td><span style="font-family:var(--font-mono); font-size:0.75rem;">${v._latency_ms || 400}ms</span></td>
        <td><div style="max-width:320px; font-size:0.78rem; line-height:1.3; color:var(--text-secondary);">${escapeHtml(v.audit_summary || '')}</div></td>
        <td>${actionBtn}</td>
      </tr>
    `;
  }).join('');
}


// ─── HITL Resolution Desk & Actions ──────────────────────────────────────────
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
          🚩 <strong>${v.fraud_type || 'Suspicious Activity'}</strong>: ${escapeHtml(v.audit_summary || '')}
        </div>
        <div style="font-size:0.78rem; color:#fecaca; margin-bottom:0.75rem;">
          📞 <strong>Required Action:</strong> ${escapeHtml(v.out_of_band_action || 'Call vendor master phone before release.')}
        </div>
        <div class="hitl-card-actions">
          <button class="btn btn-danger btn-sm" onclick="resolveHitlPayment('${v._invoice_id}', 'REJECTED')">🚫 Reject & Blacklist</button>
          <button class="btn btn-success btn-sm" onclick="resolveHitlPayment('${v._invoice_id}', 'RELEASED')">✅ Release to ERP</button>
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
      <div style="font-weight:700; color:#f87171; font-size:0.85rem;">🚨 Fraud Trigger: ${item.fraud_type || 'BEC Alert'}</div>
      <div style="font-size:0.82rem; color:var(--text-secondary); margin-top:0.25rem;">${escapeHtml(item.audit_summary || '')}</div>
    </div>
    <div style="background:rgba(255,255,255,0.03); padding:0.75rem; border-radius:6px; font-size:0.82rem;">
      <strong>Out-of-Band Call Required:</strong>
      <p style="color:#fecaca; margin-top:0.25rem;">${escapeHtml(item.out_of_band_action || 'Call verified master contact before releasing payment.')}</p>
    </div>
  `;

  releaseBtn.onclick = async () => {
    await resolveHitlPayment(invoiceId, 'RELEASED');
    modal.style.display = 'none';
  };
  rejectBtn.onclick = async () => {
    await resolveHitlPayment(invoiceId, 'REJECTED');
    modal.style.display = 'none';
  };

  modal.style.display = 'flex';
};

window.resolveHitlPayment = async function(invoiceId, action) {
  try {
    const endpoint = action === 'RELEASED' ? `/api/hitl/release/${invoiceId}` : `/api/hitl/reject/${invoiceId}`;
    const res = await fetch(endpoint, { method: 'POST' });
    if (!res.ok) throw new Error('Action failed');

    // Update in local state
    const item = state.auditHistory.find(v => v._invoice_id === invoiceId);
    if (item) item.hitl_action = action;

    const holdItem = state.hitlHolds.find(v => v._invoice_id === invoiceId);
    if (holdItem) holdItem.hitl_action = action;

    // Update single audit result card if currently displaying this invoice
    if (state.currentSingleInvoiceId === invoiceId) {
      const actionsWrap = document.getElementById('verdictActions');
      if (actionsWrap) {
        if (action === 'REJECTED') {
          actionsWrap.innerHTML = `<div class="badge badge-hold" style="padding:0.6rem 1.2rem; font-size:0.85rem; width:100%; justify-content:center;">🚫 Payment REJECTED & Vendor Blacklisted</div>`;
        } else {
          actionsWrap.innerHTML = `<div class="badge badge-clean" style="padding:0.6rem 1.2rem; font-size:0.85rem; width:100%; justify-content:center;">✅ Payment APPROVED & Released to ERP</div>`;
        }
      }
    }

    // Close modal if open
    const modal = document.getElementById('hitlActionModal');
    if (modal) modal.style.display = 'none';

    // Reload vendors to reflect any auto-blacklisting
    await loadVendors();
    renderAuditTable();
    renderHitlDesk();

    showToast(`Invoice ${invoiceId}: Payment ${action === 'RELEASED' ? 'Approved & Released' : 'Rejected & Vendor Flagged'}`, action === 'RELEASED' ? 'success' : 'error');
  } catch (err) {
    showToast('Failed to resolve hold: ' + err.message, 'error');
  }
};


// ─── Settings & Engine / Supabase Configuration ──────────────────────────────
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

  // RocketRide Reconnect Form
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
      if (data.is_connected) {
        showToast(data.message, 'success');
      } else {
        showToast(data.message, 'info');
      }

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

function setupModals() {
  document.getElementById('hitlModalClose')?.addEventListener('click', () => {
    const modal = document.getElementById('hitlActionModal');
    if (modal) modal.style.display = 'none';
  });

  // Close modals when clicking on background backdrop
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
