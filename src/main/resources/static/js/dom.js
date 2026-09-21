/** Small DOM and formatting helpers shared by the dashboard modules. */

export const $ = (selector, root = document) => root.querySelector(selector);
export const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

/** Creates an element, assigning text via `textContent` so values are never parsed as HTML. */
export function el(tag, { className, text, attrs } = {}) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    if (attrs) for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
    return node;
}

export function show(node) { node.hidden = false; }
export function hide(node) { node.hidden = true; }

export function showError(node, message) {
    node.textContent = message;
    node.hidden = false;
}

export function clearError(node) {
    node.textContent = '';
    node.hidden = true;
}

/** Formats a backend `LocalDateTime` string for display. */
export function formatDateTime(value) {
    if (!value) return '—';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return date.toLocaleString(undefined, {
        year: 'numeric', month: 'short', day: 'numeric',
        hour: '2-digit', minute: '2-digit',
    });
}

/** Formats a timestamp as a short relative age, falling back to an absolute date. */
export function formatRelative(value) {
    if (!value) return '—';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;

    const seconds = Math.round((Date.now() - date.getTime()) / 1000);
    if (seconds < 60) return 'just now';
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    if (seconds < 604800) return `${Math.floor(seconds / 86400)}d ago`;
    return formatDateTime(value);
}

/**
 * Converts a `datetime-local` value (`YYYY-MM-DDTHH:mm`) into the seconds-precision
 * form Jackson expects for a `LocalDateTime`.
 */
export function toLocalDateTime(value) {
    if (!value) return null;
    return value.length === 16 ? `${value}:00` : value;
}
