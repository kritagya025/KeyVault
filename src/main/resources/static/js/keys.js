/** API key table, creation dialog, and lifecycle actions. */

import { api, ApiError } from './api.js';
import { $, el, showError, clearError, formatDateTime, formatRelative, toLocalDateTime } from './dom.js';

const BADGE_CLASS = {
    ACTIVE: 'badge badge--active',
    REVOKED: 'badge badge--revoked',
    EXPIRED: 'badge badge--expired',
};

/** Milliseconds a destructive button stays armed before reverting. */
const ARM_TIMEOUT_MS = 4000;

/**
 * Turns a destructive button into a two-step confirm. A native `confirm()` would block
 * the page, so the confirmation lives in the button itself.
 */
function armable(button, confirmLabel, action) {
    const original = button.textContent;
    let armed = false;
    let timer;

    button.addEventListener('click', async () => {
        if (!armed) {
            armed = true;
            button.textContent = confirmLabel;
            button.classList.add('btn--danger');
            timer = setTimeout(() => {
                armed = false;
                button.textContent = original;
                button.classList.remove('btn--danger');
            }, ARM_TIMEOUT_MS);
            return;
        }

        clearTimeout(timer);
        armed = false;
        button.disabled = true;
        button.textContent = 'Working…';
        try {
            await action();
        } finally {
            button.disabled = false;
            button.textContent = original;
            button.classList.remove('btn--danger');
        }
    });

    return button;
}

/**
 * @param {{onSelect: (key: object) => void, onError: (message: string) => void}} handlers
 */
export function initKeys({ onSelect, onError }) {
    const body = $('#keys-body');
    const empty = $('#keys-empty');
    const createDialog = $('#create-dialog');
    const createForm = $('#create-form');
    const createError = $('#create-error');
    const revealDialog = $('#reveal-dialog');
    const auditDialog = $('#audit-dialog');
    const auditList = $('#audit-list');
    const auditEmpty = $('#audit-empty');
    const auditSubtitle = $('#audit-subtitle');
    const auditExportBtn = $('#audit-export-btn');

    const selectAllCheckbox = $('#keys-select-all');
    const bulkBar = $('#bulk-bar');
    const bulkCount = $('#bulk-count');
    const bulkRevokeBtn = $('#bulk-revoke-btn');
    const bulkDeleteBtn = $('#bulk-delete-btn');

    let selectedId = null;
    let selectedKeyIds = new Set();
    let currentKeys = [];
    let currentAuditKeyId = null;

    function updateBulkBar() {
        if (selectedKeyIds.size > 0) {
            bulkBar.hidden = false;
            bulkCount.textContent = `${selectedKeyIds.size} key${selectedKeyIds.size > 1 ? 's' : ''} selected`;
        } else {
            bulkBar.hidden = true;
        }
        if (selectAllCheckbox) {
            selectAllCheckbox.checked = currentKeys.length > 0 && selectedKeyIds.size === currentKeys.length;
        }
    }

    if (selectAllCheckbox) {
        selectAllCheckbox.addEventListener('change', () => {
            if (selectAllCheckbox.checked) {
                currentKeys.forEach(k => selectedKeyIds.add(k.id));
            } else {
                selectedKeyIds.clear();
            }
            render(currentKeys);
        });
    }

    if (bulkRevokeBtn) {
        bulkRevokeBtn.addEventListener('click', async () => {
            if (selectedKeyIds.size === 0) return;
            try {
                await api.bulkRevokeKeys(Array.from(selectedKeyIds));
                selectedKeyIds.clear();
                await refresh();
            } catch (err) {
                onError(err.message);
            }
        });
    }

    if (bulkDeleteBtn) {
        bulkDeleteBtn.addEventListener('click', async () => {
            if (selectedKeyIds.size === 0) return;
            try {
                await api.bulkDeleteKeys(Array.from(selectedKeyIds));
                selectedKeyIds.clear();
                await refresh();
            } catch (err) {
                onError(err.message);
            }
        });
    }

    function reveal(title, rawKey) {
        $('#reveal-title').textContent = title;
        $('#reveal-key').textContent = rawKey;

        const copyButton = $('#copy-key');
        copyButton.textContent = 'Copy';
        copyButton.onclick = async () => {
            try {
                await navigator.clipboard.writeText(rawKey);
                copyButton.textContent = 'Copied';
            } catch {
                copyButton.textContent = 'Select it manually';
            }
        };

        revealDialog.showModal();
    }

    async function showAuditLogs(key) {
        currentAuditKeyId = key.id;
        auditSubtitle.textContent = `Audit trail for "${key.name}" (ID #${key.id})`;
        auditList.replaceChildren();
        auditEmpty.hidden = true;
        auditDialog.showModal();

        try {
            const logs = await api.auditLogsForKey(key.id);
            if (!logs || logs.length === 0) {
                auditEmpty.hidden = false;
                return;
            }

            auditList.replaceChildren(...logs.map(log => {
                const li = el('li', { className: 'audit-item' });
                const top = el('div', { className: 'audit-item__top' });
                top.append(el('span', { className: 'audit-action', text: log.action }));
                top.append(el('span', { className: 'audit-time', text: formatDateTime(log.timestamp) }));
                li.append(top);
                if (log.details) {
                    li.append(el('div', { className: 'audit-details', text: log.details }));
                }
                return li;
            }));
        } catch (err) {
            auditEmpty.hidden = false;
            auditEmpty.textContent = `Error loading audit logs: ${err.message}`;
        }
    }

    function buildRow(key) {
        const row = el('tr');
        if (key.id === selectedId) row.classList.add('is-selected');

        // Checkbox column
        const checkCell = el('td');
        const cb = el('input', { type: 'checkbox' });
        cb.checked = selectedKeyIds.has(key.id);
        cb.addEventListener('change', () => {
            if (cb.checked) {
                selectedKeyIds.add(key.id);
            } else {
                selectedKeyIds.delete(key.id);
            }
            updateBulkBar();
        });
        checkCell.append(cb);
        row.append(checkCell);

        // Name, description & tags
        const nameCell = el('td', { className: 'table__name' });
        const nameWrap = el('div');
        nameWrap.append(el('strong', { text: key.name }));
        if (key.maskedKey) {
            const code = el('code', { className: 'perm', text: key.maskedKey });
            code.style.marginLeft = '8px';
            code.style.fontSize = '0.75rem';
            nameWrap.append(code);
        }
        nameCell.append(nameWrap);

        if (key.description) {
            nameCell.append(el('div', { className: 'key-desc', text: key.description }));
        }

        if (key.tags && key.tags.length > 0) {
            const tagsWrap = el('div');
            key.tags.forEach(tag => {
                tagsWrap.append(el('span', { className: 'badge--tag', text: `#${tag}` }));
            });
            nameCell.append(tagsWrap);
        }
        row.append(nameCell);

        // Status
        const status = el('td');
        if (key.environment) {
            const envClass = key.environment === 'PRODUCTION' ? 'badge--prod' :
                             key.environment === 'STAGING' ? 'badge--stage' : 'badge--dev';
            const envBadge = el('span', { className: `badge ${envClass}`, text: key.environment.slice(0, 4) });
            envBadge.style.marginRight = '6px';
            status.append(envBadge);
        }
        status.append(el('span', {
            className: BADGE_CLASS[key.status] ?? 'badge',
            text: key.status,
        }));
        if (key.expiringSoon) {
            const expBadge = el('span', { className: 'badge badge--expiring', text: '⚠️ Expiring' });
            expBadge.style.marginLeft = '6px';
            status.append(expBadge);
        }
        row.append(status);

        // Permissions & rate limit
        const perms = el('td');
        (key.permissions ?? []).forEach((p) => perms.append(el('span', { className: 'perm', text: p })));
        if (key.rateLimit) {
            const rl = el('span', { className: 'perm', text: `${key.rateLimit} req/m` });
            rl.style.borderColor = 'var(--accent)';
            perms.append(rl);
        }
        row.append(perms);

        row.append(el('td', { className: 'cell-time', text: formatDateTime(key.createdAt) }));
        row.append(el('td', { className: 'cell-time', text: key.expiresAt ? formatDateTime(key.expiresAt) : 'Never' }));

        // Actions
        const actions = el('td');
        const group = el('div', { className: 'table__actions' });

        const usageButton = el('button', { className: 'btn btn--ghost btn--sm', text: 'Usage' });
        usageButton.addEventListener('click', () => {
            selectedId = key.id;
            render(currentKeys);
            onSelect(key);
        });
        group.append(usageButton);

        const auditButton = el('button', { className: 'btn btn--ghost btn--sm', text: 'Audit' });
        auditButton.addEventListener('click', () => {
            showAuditLogs(key);
        });
        group.append(auditButton);

        if (key.status !== 'REVOKED') {
            group.append(armable(
                el('button', { className: 'btn btn--ghost btn--sm', text: 'Rotate' }),
                'Rotate key?',
                async () => {
                    try {
                        const result = await api.rotateKey(key.id, { gracePeriodHours: 24 });
                        await refresh();
                        reveal('Rotated API key (24h grace period)', result.apiKey);
                    } catch (error) {
                        onError(error.message);
                    }
                },
            ));

            group.append(armable(
                el('button', { className: 'btn btn--ghost btn--sm', text: 'Regenerate' }),
                'Replace key?',
                async () => {
                    try {
                        const result = await api.regenerateKey(key.id);
                        await refresh();
                        reveal('Regenerated API key', result.apiKey);
                    } catch (error) {
                        onError(error.message);
                    }
                },
            ));

            group.append(armable(
                el('button', { className: 'btn btn--ghost btn--sm', text: 'Revoke' }),
                'Confirm revoke',
                async () => {
                    try {
                        await api.revokeKey(key.id);
                        await refresh();
                    } catch (error) {
                        onError(error.message);
                    }
                },
            ));
        }

        group.append(armable(
            el('button', { className: 'btn btn--ghost btn--sm', text: 'Delete' }),
            'Delete key?',
            async () => {
                try {
                    await api.deleteKey(key.id);
                    if (selectedId === key.id) {
                        selectedId = null;
                    }
                    selectedKeyIds.delete(key.id);
                    await refresh();
                } catch (error) {
                    onError(error.message);
                }
            },
        ));

        actions.append(group);
        row.append(actions);
        return row;
    }

    function render(keys) {
        currentKeys = keys;
        body.replaceChildren(...keys.map(buildRow));
        empty.hidden = keys.length > 0;
        updateBulkBar();
    }

    async function refresh() {
        const keys = await api.listKeys();
        keys.sort((a, b) => (b.id ?? 0) - (a.id ?? 0));
        render(keys);
        return keys;
    }

    // ---- Create dialog -------------------------------------------------

    $('#new-key-btn').addEventListener('click', () => {
        createForm.reset();
        clearError(createError);
        createDialog.showModal();
    });

    document.querySelectorAll('[data-close-dialog]').forEach((button) => {
        button.addEventListener('click', () => button.closest('dialog').close());
    });

    createForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        clearError(createError);

        const data = new FormData(createForm);
        const permissions = data.getAll('permissions');
        const payload = {
            name: (data.get('name') ?? '').trim(),
            permissions: permissions.length ? permissions : ['READ'],
        };

        const description = (data.get('description') ?? '').trim();
        if (description) payload.description = description;

        const tagsVal = (data.get('tags') ?? '').trim();
        if (tagsVal) {
            payload.tags = tagsVal.split(',').map(s => s.trim().replace(/^#/, '')).filter(Boolean);
        }

        const environment = data.get('environment');
        if (environment) payload.environment = environment;

        const rateLimitVal = data.get('rateLimit');
        if (rateLimitVal && !isNaN(parseInt(rateLimitVal, 10))) {
            payload.rateLimit = parseInt(rateLimitVal, 10);
        }

        const ipVal = (data.get('ipRestrictions') ?? '').trim();
        if (ipVal) {
            payload.ipRestrictions = ipVal.split(',').map(s => s.trim()).filter(Boolean);
        }

        const expiresAt = toLocalDateTime(data.get('expiresAt'));
        if (expiresAt) payload.expiresAt = expiresAt;

        const button = createForm.querySelector('button[type="submit"]');
        button.disabled = true;

        try {
            const created = await api.createKey(payload);
            createDialog.close();
            await refresh();
            reveal('Your new API key', created.apiKey);
        } catch (error) {
            const detail = error instanceof ApiError && error.details
                ? `: ${Object.values(error.details).join(' · ')}`
                : '';
            showError(createError, `${error.message}${detail}`);
        } finally {
            button.disabled = false;
        }
    });

    auditExportBtn?.addEventListener('click', async () => {
        if (!currentAuditKeyId) return;
        try {
            await api.downloadAuditLogsCsv(currentAuditKeyId);
        } catch (err) {
            alert(`Failed to export audit logs: ${err.message}`);
        }
    });

    return { refresh, getSelectedId: () => selectedId };
}
