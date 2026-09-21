/** API key table, creation dialog, and lifecycle actions. */

import { api, ApiError } from './api.js';
import { $, el, showError, clearError, formatDateTime, toLocalDateTime } from './dom.js';

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

    let selectedId = null;

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
                // Clipboard access needs a secure context; the key stays selectable either way.
                copyButton.textContent = 'Select it manually';
            }
        };

        revealDialog.showModal();
    }

    function buildRow(key) {
        const row = el('tr');
        if (key.id === selectedId) row.classList.add('is-selected');

        row.append(el('td', { className: 'table__name', text: key.name }));

        const status = el('td');
        status.append(el('span', {
            className: BADGE_CLASS[key.status] ?? 'badge',
            text: key.status,
        }));
        row.append(status);

        const perms = el('td');
        (key.permissions ?? []).forEach((p) => perms.append(el('span', { className: 'perm', text: p })));
        row.append(perms);

        row.append(el('td', { className: 'cell-time', text: formatDateTime(key.createdAt) }));
        row.append(el('td', { className: 'cell-time', text: key.expiresAt ? formatDateTime(key.expiresAt) : 'Never' }));

        const actions = el('td');
        const group = el('div', { className: 'table__actions' });

        const usageButton = el('button', { className: 'btn btn--ghost btn--sm', text: 'Usage' });
        usageButton.addEventListener('click', () => {
            selectedId = key.id;
            render(currentKeys);
            onSelect(key);
        });
        group.append(usageButton);

        if (key.status !== 'REVOKED') {
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

        actions.append(group);
        row.append(actions);
        return row;
    }

    let currentKeys = [];

    function render(keys) {
        currentKeys = keys;
        body.replaceChildren(...keys.map(buildRow));
        empty.hidden = keys.length > 0;
    }

    async function refresh() {
        const keys = await api.listKeys();
        // Newest first reads better than the repository's insertion order.
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

    return { refresh, getSelectedId: () => selectedId };
}
