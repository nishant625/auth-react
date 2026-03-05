import { createContext, useContext, useEffect, useState } from 'react';

const AuthContext = createContext(null);

// ── Crypto helpers ────────────────────────────────────────────────────────────

const base64UrlEncode = (buffer) => {
  const base64 = btoa(String.fromCharCode(...buffer));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

const generateRandomString = (length) => {
  const array = new Uint8Array(length);
  window.crypto.getRandomValues(array);
  return base64UrlEncode(array);
};

const sha256 = async (plain) => {
  const encoder = new TextEncoder();
  const data = encoder.encode(plain);
  const hash = await window.crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(hash);
};

// Decode JWT payload without verification — used only for quick expiry pre-checks
const decodeJwt = (token) => {
  try {
    return JSON.parse(atob(token.split('.')[1]));
  } catch {
    return null;
  }
};

// ── JWKS + RS256 verification ─────────────────────────────────────────────────

const jwksCache = {};

const fetchJwks = async (authServerUrl) => {
  const res = await fetch(`${authServerUrl}/.well-known/jwks.json`);
  if (!res.ok) throw new Error('Failed to fetch JWKS');
  const jwks = await res.json();
  jwksCache[authServerUrl] = jwks;
  return jwks;
};

// Verify RS256 JWT signature using the JWKS endpoint.
// Returns decoded payload or null if invalid.
const verifyJwt = async (token, authServerUrl) => {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const [headerB64, payloadB64, sigB64] = parts;
    const header = JSON.parse(atob(headerB64));

    const jwks = jwksCache[authServerUrl] ?? await fetchJwks(authServerUrl);
    const jwk = jwks.keys.find(k => k.kid === header.kid) ?? jwks.keys[0];
    if (!jwk) return null;

    const key = await window.crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify']
    );

    const input = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
    const sig = Uint8Array.from(
      atob(sigB64.replace(/-/g, '+').replace(/_/g, '/')),
      c => c.charCodeAt(0)
    );

    const valid = await window.crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, sig, input);
    if (!valid) return null;

    return JSON.parse(atob(payloadB64));
  } catch {
    // Clear cache on failure in case the server rotated keys
    delete jwksCache[authServerUrl];
    return null;
  }
};

// ── AuthProvider ──────────────────────────────────────────────────────────────

export function AuthProvider({ children, clientId, clientSecret, authServerUrl, redirectUri }) {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [user, setUser] = useState(null);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const code = params.get('code');
    const state = params.get('state');

    if (code) {
      handleCallback(code, state).finally(() => setIsLoading(false));
    } else {
      restoreSession().finally(() => setIsLoading(false));
    }
  }, []);

  const silentRefresh = async () => {
    const refreshToken = localStorage.getItem('refresh_token');
    if (!refreshToken) return null;

    try {
      const res = await fetch(`${authServerUrl}/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: refreshToken,
          client_id: clientId,
          ...(clientSecret && { client_secret: clientSecret }),
        }).toString(),
      });

      if (!res.ok) {
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        setIsAuthenticated(false);
        setUser(null);
        return null;
      }

      const data = await res.json();
      localStorage.setItem('access_token', data.access_token);
      if (data.refresh_token) localStorage.setItem('refresh_token', data.refresh_token);

      const verified = await verifyJwt(data.access_token, authServerUrl);
      if (verified) {
        setUser(verified);
        setIsAuthenticated(true);
      }

      return data.access_token;
    } catch {
      return null;
    }
  };

  const restoreSession = async () => {
    const token = localStorage.getItem('access_token');
    if (!token) return;

    const payload = decodeJwt(token);

    // Expired — try silent refresh before giving up
    if (!payload || payload.exp * 1000 <= Date.now()) {
      const refreshed = await silentRefresh();
      if (!refreshed) localStorage.removeItem('access_token');
      return;
    }

    // Verify signature
    const verified = await verifyJwt(token, authServerUrl);
    if (!verified) {
      localStorage.removeItem('access_token');
      return;
    }

    setUser(verified);
    setIsAuthenticated(true);
  };

  const handleCallback = async (code, returnedState) => {
    const storedState = sessionStorage.getItem('oauth_state');
    if (!storedState || returnedState !== storedState) {
      console.error('State mismatch — possible CSRF attack');
      return;
    }

    const codeVerifier = sessionStorage.getItem('pkce_verifier');
    if (!codeVerifier) {
      console.error('No code verifier found');
      return;
    }

    const res = await fetch(`${authServerUrl}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        client_id: clientId,
        ...(clientSecret && { client_secret: clientSecret }),
        code_verifier: codeVerifier,
      }).toString(),
    });

    if (!res.ok) return;

    const data = await res.json();
    localStorage.setItem('access_token', data.access_token);
    if (data.refresh_token) localStorage.setItem('refresh_token', data.refresh_token);

    sessionStorage.removeItem('pkce_verifier');
    sessionStorage.removeItem('oauth_state');

    const verified = await verifyJwt(data.access_token, authServerUrl);
    setUser(verified);
    setIsAuthenticated(!!verified);
    window.history.replaceState({}, '', window.location.pathname);
  };

  const login = async () => {
    const codeVerifier = generateRandomString(32);
    const hashed = await sha256(codeVerifier);
    const codeChallenge = base64UrlEncode(hashed);
    const state = generateRandomString(16);

    sessionStorage.setItem('pkce_verifier', codeVerifier);
    sessionStorage.setItem('oauth_state', state);

    const params = new URLSearchParams({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: redirectUri,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      scope: 'openid',
      state,
    });

    window.location.href = `${authServerUrl}/oauth/authorize?${params.toString()}`;
  };

  const logout = () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    setIsAuthenticated(false);
    setUser(null);
  };

  // Async — checks expiry and silently refreshes if needed before returning
  const getAccessToken = async () => {
    const token = localStorage.getItem('access_token');
    if (!token) return null;

    const payload = decodeJwt(token);
    if (!payload) return null;

    // Refresh if expired or expiring within 60 seconds
    if (payload.exp * 1000 < Date.now() + 60_000) {
      return await silentRefresh();
    }

    return token;
  };

  return (
    <AuthContext.Provider value={{ isAuthenticated, isLoading, user, login, logout, getAccessToken }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used inside <AuthProvider>');
  return context;
}
