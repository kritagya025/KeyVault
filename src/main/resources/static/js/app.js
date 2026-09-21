/** Dashboard entry point: view switching, session bootstrap, wiring. */

import { api, token, ApiError } from './api.js';
import { $, showError, clearError } from './dom.js';
import { initAuth } from './auth.js';
import { initKeys } from './keys.js';
import { initUsage } from './usage.js';

const authView = $('#auth-view');
const appView = $('#app-view');
const appError = $('#app-error');

const usage = initUsage({ onError: reportError });
const keys = initKeys({ onSelect: (key) => usage.load(key), onError: reportError });

function reportError(message) {
    showError(appError, message);
}

function showAuthView() {
    appView.hidden = true;
    authView.hidden = false;
}

async function showAppView() {
    authView.hidden = true;
    appView.hidden = false;
    clearError(appError);

    try {
        const me = await api.me();
        $('#current-user').textContent = me.email;
        await keys.refresh();
    } catch (error) {
        // A rejected token means the stored session is stale or the server restarted
        // with a different signing key; either way the fix is to sign in again.
        if (error instanceof ApiError && error.status === 401) {
            signOut();
            return;
        }
        reportError(error.message);
    }
}

function signOut() {
    token.clear();
    usage.reset();
    $('#current-user').textContent = '';
    showAuthView();
}

$('#logout-btn').addEventListener('click', signOut);

initAuth(() => showAppView());

// Boot into whichever view the stored session allows.
if (token.get()) {
    showAppView();
} else {
    showAuthView();
}
