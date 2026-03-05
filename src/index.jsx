import { createContext, useContext, useEffect, useState } from 'react';

const AuthContext = createContext(null);

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

const decodeJwt = (token) => {
  try {
    return JSON.parse(atob(token.split('.')[1]));
  } catch {
    return null;
  }
};

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
      // Restore session from localStorage on page load
      const token = localStorage.getItem('access_token');
      if (token) {
        const payload = decodeJwt(token);
        if (payload && payload.exp * 1000 > Date.now()) {
          setUser(payload);
          setIsAuthenticated(true);
        } else {
          localStorage.removeItem('access_token');
        }
      }
      setIsLoading(false);
    }
  }, []);

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

    const payload = decodeJwt(data.access_token);
    setUser(payload);
    setIsAuthenticated(true);
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

  const getAccessToken = () => localStorage.getItem('access_token');

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
