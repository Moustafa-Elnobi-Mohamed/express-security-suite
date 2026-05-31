/**
 * ================================================================
 *  REACT FRONTEND SECURITY UTILITIES
 *  File: src/security/frontendSecurity.js
 *
 *  Include these in your React app to harden the client side.
 *  These complement backend defenses — never replace them.
 *
 *  Usage:
 *    import { sanitizeInput, safeHtml, useCSRFToken } from './security/frontendSecurity';
 * ================================================================
 */

// ── 1. Input Sanitizer
//    Use on any value BEFORE displaying user-generated content.
export function sanitizeInput(value) {
  if (typeof value !== "string") return value;
  const div = document.createElement("div");
  div.appendChild(document.createTextNode(value));
  return div.innerHTML;
}

// ── 2. Safe HTML renderer
//    Use instead of dangerouslySetInnerHTML whenever possible.
//    Only use dangerouslySetInnerHTML when absolutely required,
//    and only with content sanitized by this function.
export function safeHtml(dirty) {
  if (!dirty) return "";
  return dirty
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;")
    .replace(/\//g, "&#x2F;");
}

// ── 3. CSRF Token hook
//    Attach this token to every state-changing request (POST/PUT/DELETE).
//    Backend must validate it. Store in a meta tag (not localStorage).
export function useCSRFToken() {
  const token = document
    .querySelector('meta[name="csrf-token"]')
    ?.getAttribute("content");
  return token;
}

// ── 4. Safe URL validator
//    Prevent open redirect attacks. Use before any redirect.
export function isSafeUrl(urlString) {
  try {
    const parsed = new URL(urlString, window.location.origin);
    // Only allow same-origin URLs
    return parsed.origin === window.location.origin;
  } catch {
    return false;
  }
}

// ── 5. Safe redirect — use instead of window.location = userInput
export function safeRedirect(urlString) {
  if (isSafeUrl(urlString)) {
    window.location.href = urlString;
  } else {
    console.warn("[Security] Blocked unsafe redirect:", urlString);
    window.location.href = "/";
  }
}

// ── 6. Secure API call wrapper
//    Attaches CSRF token, auth header, and request ID automatically.
export async function secureRequest(endpoint, options = {}) {
  const csrfToken  = useCSRFToken();
  const authToken  = sessionStorage.getItem("authToken"); // Use sessionStorage, not localStorage
  const requestId  = crypto.randomUUID();

  const headers = {
    "Content-Type":  "application/json",
    "X-Request-ID":  requestId,
    ...(csrfToken  ? { "X-CSRF-Token":  csrfToken } : {}),
    ...(authToken  ? { "Authorization": `Bearer ${authToken}` } : {}),
    ...(options.headers || {}),
  };

  const response = await fetch(endpoint, {
    ...options,
    headers,
    credentials: "include", // Send cookies for session-based auth
  });

  if (response.status === 401) {
    // Token expired — clear and redirect to login
    sessionStorage.removeItem("authToken");
    window.location.href = "/login";
    return;
  }

  return response;
}

// ── 7. Sensitive data cleaner
//    Call on logout or tab close to wipe any cached sensitive state.
export function clearSensitiveData() {
  sessionStorage.clear();
  // NOTE: Never store tokens in localStorage — it's XSS-accessible.
  // Only clear things you deliberately put there.
  const sensitiveKeys = ["authToken", "userEmail", "tempData"];
  sensitiveKeys.forEach((key) => localStorage.removeItem(key));
}

// ── 8. Form input validator
//    Client-side validation (backend must always re-validate too).
export const validators = {
  email: (v) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v),
  phone: (v) => /^\+?[\d\s\-().]{7,20}$/.test(v),
  // Passwords: min 8 chars, 1 uppercase, 1 lowercase, 1 number, 1 special
  password: (v) => /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/.test(v),
  noScript:  (v) => !/<script|javascript:|onerror=/i.test(v),
  safeText:  (v) => !/[<>{}|\\^`]/.test(v),
};

// ── 9. Subresource Integrity helper
//    Generates the integrity attribute for external scripts/styles.
//    Use in your index.html for any third-party script tags.
//    Example: <script src="..." integrity={integrityHash} crossorigin="anonymous" />
//    Generate hash with: https://www.srihash.org/
export const SRI_REMINDER = `
  Always add integrity + crossorigin attributes to external scripts:
  <script
    src="https://cdn.example.com/lib.js"
    integrity="sha384-HASH_HERE"
    crossorigin="anonymous"
  ></script>
`;
