/** Usage statistics panel and the protected-endpoint tester. */

import { api, probe } from './api.js';
import { $, $$, el, formatRelative } from './dom.js';

/** @param {{onError: (message: string) => void}} handlers */
export function initUsage({ onError }) {
    const subject = $('#usage-subject');
    const panel = $('#usage-body');
    const log = $('#usage-log');
    const empty = $('#usage-empty');
    const refreshButton = $('#usage-refresh');

    let activeKey = null;

    function renderLog(records) {
        log.replaceChildren(...records.map((record) => {
            const row = el('tr');
            row.append(el('td', { className: 'method', text: record.method }));
            row.append(el('td', { className: 'cell-endpoint', text: record.endpoint }));
            row.append(el('td', {
                className: record.successful ? 'status-ok' : 'status-bad',
                text: String(record.statusCode),
            }));
            row.append(el('td', { className: 'cell-time', text: formatRelative(record.timestamp) }));
            return row;
        }));
        empty.hidden = records.length > 0;
    }

    async function load(key) {
        activeKey = key;
        subject.textContent = `Key: ${key.name}`;
        panel.hidden = false;
        refreshButton.hidden = false;

        try {
            const [stats, recent] = await Promise.all([
                api.usageStats(key.id),
                api.recentUsage(key.id),
            ]);

            $('#stat-total').textContent = stats.totalRequests;
            $('#stat-success').textContent = stats.successfulRequests;
            $('#stat-failed').textContent = stats.failedRequests;
            renderLog(recent);
        } catch (error) {
            onError(error.message);
        }
    }

    refreshButton.addEventListener('click', () => {
        if (activeKey) load(activeKey);
    });

    // ---- Endpoint tester -----------------------------------------------

    const output = $('#test-output');

    $$('[data-test]').forEach((button) => {
        button.addEventListener('click', async () => {
            const rawKey = $('#test-key').value.trim();
            const method = button.dataset.test;
            const path = button.dataset.path;

            if (!rawKey) {
                output.hidden = false;
                output.textContent = 'Paste a raw API key first.';
                return;
            }

            output.hidden = false;
            output.textContent = `${method} ${path}\n…`;

            try {
                const { status, body } = await probe(method, path, rawKey);
                const rendered = body ? JSON.stringify(body, null, 2) : '(no JSON body)';
                output.textContent = `${method} ${path}\n${status} ${explain(status)}\n\n${rendered}`;
            } catch (error) {
                output.textContent = `${method} ${path}\nRequest failed: ${error.message}`;
            }

            // A tracked call may have just been recorded against the selected key.
            if (activeKey) load(activeKey);
        });
    });

    function explain(status) {
        if (status === 200) return 'OK';
        if (status === 401) return 'Unauthorized — key missing, revoked, expired, or unknown';
        if (status === 403) return 'Forbidden — key lacks the required permission';
        return '';
    }

    function reset() {
        activeKey = null;
        panel.hidden = true;
        refreshButton.hidden = true;
        subject.textContent = 'Select a key to view its request history.';
        output.hidden = true;
        $('#test-key').value = '';
    }

    return { load, reset };
}
