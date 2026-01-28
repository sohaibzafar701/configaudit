/**
 * Baseline Configuration Management JavaScript
 */

let baselines = [];
let allRules = [];
let currentBaselineId = null;

// API helper
async function apiRequest(url, method = 'GET', data = null) {
    const options = {
        method,
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include'
    };
    if (data && method !== 'GET') {
        options.body = JSON.stringify(data);
    }
    try {
        const response = await fetch(url, options);
        const result = await response.json();
        return { ok: response.ok, data: result, status: response.status };
    } catch (error) {
        console.error('API request failed:', error);
        return { ok: false, error: error.message };
    }
}

// Load baselines
async function loadBaselines() {
    const container = document.getElementById('baselinesList');
    if (!container) {
        console.error('baselinesList container not found');
        return;
    }
    
    // Show loading state
    container.innerHTML = '<p class="text-gray-500">Loading baselines...</p>';
    
    const vendor = document.getElementById('filterVendor')?.value || '';
    const deviceType = document.getElementById('filterDeviceType')?.value || '';
    const framework = document.getElementById('filterFramework')?.value || '';
    const search = document.getElementById('searchBaseline')?.value || '';
    
    let url = '/api/baselines?';
    if (vendor) url += `vendor=${vendor}&`;
    if (deviceType) url += `device_type=${deviceType}&`;
    if (framework) url += `framework=${framework}&`;
    
    try {
        const result = await apiRequest(url);
        
        if (!result.ok) {
            const errorMsg = result.data?.error || result.error || 'Unknown error';
            console.error('Failed to load baselines:', errorMsg);
            // eslint-disable-next-line security/detect-dangerous-html-method
            container.innerHTML = `<p class="text-red-500">Error loading baselines: ${escapeHtml(errorMsg)}</p>`;
            return;
        }
        
        if (!result.data || !Array.isArray(result.data.baselines)) {
            console.error('Invalid response format:', result.data);
            container.innerHTML = '<p class="text-red-500">Error: Invalid response format from server</p>';
            return;
        }
        
        baselines = result.data.baselines;
        
        // Apply search filter
        if (search) {
            baselines = baselines.filter(b => 
                b.name.toLowerCase().includes(search.toLowerCase()) ||
                (b.description && b.description.toLowerCase().includes(search.toLowerCase()))
            );
        }
        
        const countEl = document.getElementById('baselineCount');
        if (countEl) {
            countEl.textContent = baselines.length;
        }
        
        renderBaselines();
    } catch (error) {
        console.error('Exception loading baselines:', error);
        // eslint-disable-next-line security/detect-dangerous-html-method
        container.innerHTML = `<p class="text-red-500">Error loading baselines: ${escapeHtml(error.message)}</p>`;
    }
}

// Render baselines list
function renderBaselines() {
    const container = document.getElementById('baselinesList');
    if (!container) {
        console.error('baselinesList container not found');
        return;
    }
    
    if (baselines.length === 0) {
        container.innerHTML = '<p class="text-gray-500">No baselines found. Create your first baseline configuration or copy a platform baseline.</p>';
        return;
    }
    
    // eslint-disable-next-line security/detect-dangerous-html-method
    container.innerHTML = baselines.map(baseline => {
        const isPlatform = baseline.is_platform === true;
        const orgName = baseline.organization_name || '';
        
        return `
        <div class="bg-white border border-gray-200 rounded-lg p-4 hover:shadow-md transition-shadow">
            <div class="flex justify-between items-start">
                <div class="flex-1">
                    <div class="flex items-center gap-2 mb-2">
                        <h4 class="text-lg font-semibold text-gray-900">${escapeHtml(baseline.name)}</h4>
                        ${isPlatform ? '<span class="px-2 py-1 bg-indigo-100 text-indigo-800 rounded text-xs font-semibold">Platform Baseline</span>' : ''}
                        ${orgName && !isPlatform ? `<span class="px-2 py-1 bg-gray-100 text-gray-600 rounded text-xs">${escapeHtml(orgName)}</span>` : ''}
                    </div>
                    <p class="text-sm text-gray-600 mb-3">${escapeHtml(baseline.description || 'No description')}</p>
                    <div class="flex flex-wrap gap-2 mb-3">
                        ${baseline.vendor ? `<span class="px-2 py-1 bg-blue-100 text-blue-800 rounded text-xs">${escapeHtml(baseline.vendor)}</span>` : ''}
                        ${baseline.device_type ? `<span class="px-2 py-1 bg-green-100 text-green-800 rounded text-xs">${escapeHtml(baseline.device_type)}</span>` : ''}
                        ${baseline.frameworks_list && baseline.frameworks_list.length > 0 ? 
                            baseline.frameworks_list.map(f => `<span class="px-2 py-1 bg-purple-100 text-purple-800 rounded text-xs">${escapeHtml(f)}</span>`).join('') 
                            : ''}
                        <span class="px-2 py-1 bg-gray-100 text-gray-800 rounded text-xs">${baseline.rule_count || 0} rules</span>
                    </div>
                </div>
                <div class="flex gap-2 ml-4">
                    ${isPlatform ? `
                    <button onclick="copyBaseline(${baseline.id})" class="px-3 py-1 bg-indigo-600 text-white rounded hover:bg-indigo-700 text-sm" title="Copy Baseline">
                        <i class="fas fa-copy"></i>
                    </button>
                    ` : ''}
                    <button onclick="generateBaselineDocument(${baseline.id})" class="px-3 py-1 bg-green-600 text-white rounded hover:bg-green-700 text-sm" title="Generate Document">
                        <i class="fas fa-file-pdf"></i>
                    </button>
                    <button onclick="viewBaselineTemplate(${baseline.id})" class="px-3 py-1 bg-blue-600 text-white rounded hover:bg-blue-700 text-sm" title="View Template">
                        <i class="fas fa-code"></i>
                    </button>
                    <button onclick="compareAuditToBaseline(${baseline.id})" class="px-3 py-1 bg-purple-600 text-white rounded hover:bg-purple-700 text-sm" title="Compare Audit">
                        <i class="fas fa-balance-scale"></i>
                    </button>
                    ${!isPlatform ? `
                    <button onclick="editBaseline(${baseline.id})" class="px-3 py-1 bg-yellow-600 text-white rounded hover:bg-yellow-700 text-sm" title="Edit">
                        <i class="fas fa-edit"></i>
                    </button>
                    <button onclick="deleteBaseline(${baseline.id})" class="px-3 py-1 bg-red-600 text-white rounded hover:bg-red-700 text-sm" title="Delete">
                        <i class="fas fa-trash"></i>
                    </button>
                    ` : `
                    <button disabled class="px-3 py-1 bg-gray-300 text-gray-500 rounded text-sm cursor-not-allowed" title="Platform baselines are read-only">
                        <i class="fas fa-lock"></i>
                    </button>
                    `}
                </div>
            </div>
        </div>
        `;
    }).join('');
}

// Show create baseline modal
function showCreateBaselineModal() {
    currentBaselineId = null;
    document.getElementById('modalTitle').textContent = 'Create Baseline';
    document.getElementById('baselineForm').reset();
    document.getElementById('baselineId').value = '';
    loadRulesForSelection();
    document.getElementById('baselineModal').classList.remove('hidden');
}

// Close baseline modal
function closeBaselineModal() {
    document.getElementById('baselineModal').classList.add('hidden');
    currentBaselineId = null;
}

// Load rules for selection
async function loadRulesForSelection() {
    const result = await apiRequest('/api/rules?status=enabled');
    
    if (result.ok && result.data) {
        allRules = Array.isArray(result.data) ? result.data : result.data.rules || [];
        renderRulesCheckboxes();
    }
}

// Render rules checkboxes
function renderRulesCheckboxes() {
    const container = document.getElementById('rulesCheckboxes');
    
    if (allRules.length === 0) {
        container.innerHTML = '<p class="text-gray-500">No rules available</p>';
        return;
    }
    
    // Group by category
    const rulesByCategory = {};
    allRules.forEach(rule => {
        const category = rule.category || 'Other';
        if (!rulesByCategory[category]) {
            rulesByCategory[category] = [];
        }
        rulesByCategory[category].push(rule);
    });
    
    // eslint-disable-next-line security/detect-dangerous-html-method
    container.innerHTML = Object.keys(rulesByCategory).sort().map(category => `
        <div class="mb-4">
            <h5 class="font-semibold text-sm mb-2">${escapeHtml(category)}</h5>
            <div class="space-y-1 ml-4">
                ${rulesByCategory[category].map(rule => `
                    <label class="flex items-center space-x-2 cursor-pointer">
                        <input type="checkbox" value="${rule.id}" class="baseline-rule-checkbox" 
                               ${currentBaselineId && baselines.find(b => b.id === currentBaselineId)?.rule_ids?.includes(rule.id) ? 'checked' : ''}>
                        <span class="text-sm">${escapeHtml(rule.name)}</span>
                    </label>
                `).join('')}
            </div>
        </div>
    `).join('');
}

// Edit baseline
async function editBaseline(baselineId) {
    const baseline = baselines.find(b => b.id === baselineId);
    if (!baseline) {
        showToast('Baseline not found', 'error');
        return;
    }
    
    if (baseline.is_platform) {
        showToast('Platform baselines cannot be edited. Please copy the baseline first.', 'error');
        return;
    }
    
    currentBaselineId = baselineId;
    document.getElementById('modalTitle').textContent = 'Edit Baseline';
    document.getElementById('baselineId').value = baselineId;
    document.getElementById('baselineName').value = baseline.name;
    document.getElementById('baselineDescription').value = baseline.description || '';
    document.getElementById('baselineVendor').value = baseline.vendor || '';
    document.getElementById('baselineDeviceType').value = baseline.device_type || '';
    document.getElementById('baselineFrameworks').value = baseline.frameworks_list ? baseline.frameworks_list.join(',') : '';
    document.getElementById('baselineTemplate').value = baseline.template_config || '';
    
    await loadRulesForSelection();
    document.getElementById('baselineModal').classList.remove('hidden');
}

// Copy baseline
async function copyBaseline(baselineId) {
    const baseline = baselines.find(b => b.id === baselineId);
    if (!baseline) {
        showToast('Baseline not found', 'error');
        return;
    }
    
    if (!baseline.is_platform) {
        showToast('Only platform baselines can be copied', 'error');
        return;
    }
    
    const customName = prompt(`Enter a name for the copied baseline (or leave blank to use "${baseline.name} (Copy)"):`, `${baseline.name} (Copy)`);
    if (customName === null) return; // User cancelled
    
    const result = await apiRequest(`/api/baselines/${baselineId}/copy`, 'POST', { name: customName || '' });
    
    if (result.ok && result.data) {
        showToast('Baseline copied successfully', 'success');
        loadBaselines();
    } else {
        const errorMsg = result.data?.error || result.error || 'Unknown error';
        showToast('Error copying baseline: ' + errorMsg, 'error');
    }
}

// Delete baseline
async function deleteBaseline(baselineId) {
    const baseline = baselines.find(b => b.id === baselineId);
    if (!baseline) {
        showToast('Baseline not found', 'error');
        return;
    }
    
    if (baseline.is_platform) {
        showToast('Platform baselines cannot be deleted', 'error');
        return;
    }
    
    if (!confirm('Are you sure you want to delete this baseline?')) return;
    
    const result = await apiRequest(`/api/baselines/${baselineId}`, 'POST', { action: 'delete' });
    
    if (result.ok) {
        showToast('Baseline deleted successfully', 'success');
        loadBaselines();
    } else {
        const errorMsg = result.data?.error || result.error || 'Unknown error';
        showToast('Error deleting baseline: ' + errorMsg, 'error');
    }
}

// Generate baseline document
async function generateBaselineDocument(baselineId) {
    window.open(`/api/baselines/${baselineId}/document?format=html`, '_blank');
}

// View baseline template
async function viewBaselineTemplate(baselineId) {
    const result = await apiRequest(`/api/baselines/${baselineId}/template`);
    
    if (result.ok && result.data.template) {
        const modal = document.createElement('div');
        modal.className = 'fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center';
        // eslint-disable-next-line security/detect-dangerous-html-method
        modal.innerHTML = `
            <div class="bg-white rounded-lg shadow-xl max-w-4xl w-full mx-4 max-h-[90vh] overflow-y-auto">
                <div class="p-6">
                    <div class="flex justify-between items-center mb-4">
                        <h3 class="text-xl font-bold">Baseline Template: ${escapeHtml(result.data.baseline_name)}</h3>
                        <button onclick="this.closest('.fixed').remove()" class="text-gray-500 hover:text-gray-700">
                            <i class="fas fa-times"></i>
                        </button>
                    </div>
                    <pre class="bg-gray-100 p-4 rounded-lg overflow-x-auto"><code>${escapeHtml(result.data.template)}</code></pre>
                    <div class="mt-4 flex justify-end">
                        <button onclick="this.closest('.fixed').remove()" class="px-4 py-2 bg-gray-300 rounded-lg hover:bg-gray-400">Close</button>
                    </div>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
    } else {
        showToast('Error loading template: ' + (result.data?.error || result.error), 'error');
    }
}

// Compare audit to baseline
async function compareAuditToBaseline(baselineId) {
    // Prompt for audit ID
    const auditId = prompt('Enter Audit ID to compare:');
    if (!auditId) return;
    
    const result = await apiRequest(`/api/baselines/${baselineId}/compare?audit_id=${auditId}`);
    
    if (result.ok && result.data) {
        const comparison = result.data;
        const modal = document.createElement('div');
        modal.className = 'fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center';
        // eslint-disable-next-line security/detect-dangerous-html-method
        modal.innerHTML = `
            <div class="bg-white rounded-lg shadow-xl max-w-4xl w-full mx-4 max-h-[90vh] overflow-y-auto">
                <div class="p-6">
                    <div class="flex justify-between items-center mb-4">
                        <h3 class="text-xl font-bold">Baseline Compliance Report</h3>
                        <button onclick="this.closest('.fixed').remove()" class="text-gray-500 hover:text-gray-700">
                            <i class="fas fa-times"></i>
                        </button>
                    </div>
                    <div class="mb-4 p-4 bg-gray-50 rounded-lg">
                        <p><strong>Baseline:</strong> ${escapeHtml(comparison.baseline_name)}</p>
                        <p><strong>Device:</strong> ${escapeHtml(comparison.audit_device)}</p>
                        <p><strong>Compliance Score:</strong> <span class="text-2xl font-bold">${comparison.compliance_score}%</span></p>
                        <p><strong>Compliance Level:</strong> ${comparison.compliance_level}</p>
                        <p><strong>Passed:</strong> ${comparison.passed_rules} | <strong>Failed:</strong> ${comparison.failed_rules} | <strong>Total:</strong> ${comparison.total_rules}</p>
                    </div>
                    <div class="mb-4">
                        <h4 class="font-semibold mb-2">Failed Requirements (${comparison.failed_rules})</h4>
                        ${comparison.failed_rules_detail.map(rule => `
                            <div class="border-l-4 border-red-500 p-3 mb-2 bg-red-50">
                                <strong>${escapeHtml(rule.rule_name)}</strong> [${rule.rule_category}]<br>
                                <span class="text-sm">${rule.findings_count} issue(s) found</span>
                            </div>
                        `).join('')}
                    </div>
                    <div class="flex justify-end gap-2">
                        <button onclick="window.open('/api/baselines/${baselineId}/compare?audit_id=${auditId}&format=html', '_blank')" class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">
                            <i class="fas fa-file-pdf mr-2"></i>Export Report
                        </button>
                        <button onclick="this.closest('.fixed').remove()" class="px-4 py-2 bg-gray-300 rounded-lg hover:bg-gray-400">Close</button>
                    </div>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
    } else {
        showToast('Error comparing audit: ' + (result.data?.error || result.error), 'error');
    }
}

// Handle form submission
document.getElementById('baselineForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const selectedRules = Array.from(document.querySelectorAll('.baseline-rule-checkbox:checked')).map(cb => parseInt(cb.value));
    
    const data = {
        action: currentBaselineId ? 'update' : 'create',
        name: document.getElementById('baselineName').value,
        description: document.getElementById('baselineDescription').value,
        vendor: document.getElementById('baselineVendor').value,
        device_type: document.getElementById('baselineDeviceType').value,
        compliance_frameworks: document.getElementById('baselineFrameworks').value,
        rule_ids: selectedRules,
        template_config: document.getElementById('baselineTemplate').value
    };
    
    if (currentBaselineId) {
        data.action = 'update';
    }
    
    const url = currentBaselineId ? `/api/baselines/${currentBaselineId}` : '/api/baselines';
    const result = await apiRequest(url, 'POST', data);
    
    if (result.ok) {
        showToast(currentBaselineId ? 'Baseline updated successfully' : 'Baseline created successfully', 'success');
        closeBaselineModal();
        loadBaselines();
    } else {
        showToast('Error saving baseline: ' + (result.data?.error || result.error), 'error');
    }
});

// Filter event listeners
document.getElementById('filterVendor')?.addEventListener('change', loadBaselines);
document.getElementById('filterDeviceType')?.addEventListener('change', loadBaselines);
document.getElementById('filterFramework')?.addEventListener('change', loadBaselines);
document.getElementById('searchBaseline')?.addEventListener('input', loadBaselines);

// Toast notification
function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `fixed top-4 right-4 px-6 py-3 rounded-lg shadow-lg z-50 toast ${
        type === 'success' ? 'bg-green-500 text-white' : 
        type === 'error' ? 'bg-red-500 text-white' : 
        'bg-blue-500 text-white'
    }`;
    toast.textContent = message;
    document.body.appendChild(toast);
    
    setTimeout(() => {
        toast.classList.add('toast-exiting');
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// Escape HTML
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    loadBaselines();
});
