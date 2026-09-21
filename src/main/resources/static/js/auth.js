/** Sign-in and registration for the auth view. */

import { api, token, ApiError } from './api.js';
import { $, $$, showError, clearError } from './dom.js';

/**
 * Wires the auth view.
 * @param {() => void} onAuthenticated called once a token has been stored
 */
export function initAuth(onAuthenticated) {
    const loginForm = $('#login-form');
    const registerForm = $('#register-form');
    const errorBox = $('#auth-error');

    $$('[data-auth-tab]').forEach((tab) => {
        tab.addEventListener('click', () => {
            const target = tab.dataset.authTab;

            $$('[data-auth-tab]').forEach((other) => {
                const active = other === tab;
                other.classList.toggle('is-active', active);
                other.setAttribute('aria-selected', String(active));
            });

            loginForm.hidden = target !== 'login';
            registerForm.hidden = target !== 'register';
            clearError(errorBox);
        });
    });

    /** Runs a submit handler with button locking and uniform error reporting. */
    async function submit(form, action) {
        const button = form.querySelector('button[type="submit"]');
        const label = button.textContent;

        clearError(errorBox);
        button.disabled = true;
        button.textContent = 'Working…';

        try {
            const { accessToken } = await action();
            token.set(accessToken);
            form.reset();
            onAuthenticated();
        } catch (error) {
            if (error instanceof ApiError && error.details) {
                const fields = Object.values(error.details).join(' · ');
                showError(errorBox, `${error.message}: ${fields}`);
            } else {
                showError(errorBox, error.message || 'Something went wrong.');
            }
        } finally {
            button.disabled = false;
            button.textContent = label;
        }
    }

    loginForm.addEventListener('submit', (event) => {
        event.preventDefault();
        const data = new FormData(loginForm);
        submit(loginForm, () => api.login(data.get('email').trim(), data.get('password')));
    });

    registerForm.addEventListener('submit', (event) => {
        event.preventDefault();
        const data = new FormData(registerForm);
        submit(registerForm, () =>
            api.register(data.get('name').trim(), data.get('email').trim(), data.get('password')));
    });
}
