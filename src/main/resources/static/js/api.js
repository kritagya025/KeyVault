/**
 * Thin fetch wrapper over the KeyVault REST API.
 *
 * The dashboard is served from the same origin as the API, so requests are relative
 * and no CORS configuration is involved.
 */

const TOKEN_KEY = 'keyvault.token';

/** Raised for any non-2xx response, carrying the status and the server's message. */
export class ApiError extends Error {
    constructor(status, message, details) {
        super(message);
        this.name = 'ApiError';
        this.status = status;
        this.details = details;
    }
}

export const token = {
    get: () => localStorage.getItem(TOKEN_KEY),
    set: (value) => localStorage.setItem(TOKEN_KEY, value),
    clear: () => localStorage.removeItem(TOKEN_KEY),
};

/**
 * Reads a response body as JSON when possible. Spring Security's entry point writes
 * an HTML error page for 401s rather than JSON, so parsing is always best-effort.
 */
async function readBody(response) {
    const text = await response.text();
    if (!text) return null;
    try {
        return JSON.parse(text);
    } catch {
        return null;
    }
}

function messageFrom(body, response) {
    if (body && typeof body.error === 'string') return body.error;
    if (response.status === 401) return 'Your session is not valid. Please sign in again.';
    if (response.status === 403) return 'This key does not carry the permission required for that endpoint.';
    return `Request failed with status ${response.status}.`;
}

/**
 * @param {string} method HTTP method
 * @param {string} path   path relative to the origin, e.g. `/api/keys`
 * @param {{body?: unknown, apiKey?: string, auth?: boolean}} [options]
 *        `apiKey` sends `X-API-Key` instead of the bearer token.
 */
async function request(method, path, options = {}) {
    const { body, apiKey, auth = true } = options;
    const headers = {};

    if (body !== undefined) headers['Content-Type'] = 'application/json';

    if (apiKey) {
        headers['X-API-Key'] = apiKey;
    } else if (auth) {
        const bearer = token.get();
        if (bearer) headers.Authorization = `Bearer ${bearer}`;
    }

    const response = await fetch(path, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
    });

    const payload = await readBody(response);

    if (!response.ok) {
        throw new ApiError(response.status, messageFrom(payload, response), payload?.details);
    }
    return payload;
}

/** Issues a request purely to observe its status code, without throwing. */
export async function probe(method, path, apiKey) {
    const response = await fetch(path, {
        method,
        headers: apiKey ? { 'X-API-Key': apiKey } : {},
    });
    return { status: response.status, body: await readBody(response) };
}

export const api = {
    register: (name, email, password) =>
        request('POST', '/api/auth/register', { body: { name, email, password }, auth: false }),

    login: (email, password) =>
        request('POST', '/api/auth/login', { body: { email, password }, auth: false }),

    me: () => request('GET', '/api/users/me'),

    listKeys: () => request('GET', '/api/keys'),

    createKey: (payload) => request('POST', '/api/keys', { body: payload }),

    revokeKey: (id) => request('PATCH', `/api/keys/${id}/revoke`),

    regenerateKey: (id) => request('POST', `/api/keys/${id}/regenerate`),

    usageStats: (id) => request('GET', `/api/keys/${id}/usage`),

    recentUsage: (id) => request('GET', `/api/keys/${id}/usage/recent`),
};
