// Fetch wrapper: same-origin cookies, CSRF header on every request, JSON errors.

export class ApiError extends Error {
  constructor(status, message, details) {
    super(message);
    this.status = status;
    this.details = details;
  }
}

async function call(method, url, { json, body, headers = {}, raw = false } = {}) {
  const init = {
    method,
    credentials: 'same-origin',
    headers: { 'X-SecureShare-CSRF': '1', ...headers },
  };
  if (json !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(json);
  } else if (body !== undefined) {
    init.body = body;
  }
  const res = await fetch(url, init);
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`;
    let details;
    try {
      const data = await res.json();
      msg = data.error || msg;
      details = data.details;
    } catch {
      /* not JSON */
    }
    throw new ApiError(res.status, msg, details);
  }
  if (raw) return res;
  if (res.status === 204) return null;
  return res.json();
}

export const api = {
  get: (url) => call('GET', url),
  post: (url, json) => call('POST', url, { json }),
  put: (url, json) => call('PUT', url, { json }),
  del: (url) => call('DELETE', url),
  putBinary: (url, blob) => call('PUT', url, { body: blob, headers: { 'Content-Type': 'application/octet-stream' } }),
  getBlob: async (url) => (await call('GET', url, { raw: true })).blob(),
};
