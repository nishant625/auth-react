# @nishant625/auth-react

React SDK for OAuth 2.0 + PKCE authentication. Works with Sentinel or any OIDC-compatible auth server.

## Install

```bash
npm install @nishant625/auth-react
```

## Setup

Wrap your app in `<AuthProvider>`:

```jsx
// main.jsx
import { AuthProvider } from '@nishant625/auth-react'

<AuthProvider
  clientId="clt_your_client_id"
  authServerUrl="http://localhost:4000"
  redirectUri="http://localhost:5173/callback"
>
  <App />
</AuthProvider>
```

| Prop | Required | Description |
|---|---|---|
| `clientId` | ✓ | Your registered client ID |
| `authServerUrl` | ✓ | Base URL of the auth server |
| `redirectUri` | ✓ | Must match a registered redirect URI |
| `clientSecret` | — | Only for confidential server-side clients — never put this in a SPA |

## Usage

```jsx
import { useAuth } from '@nishant625/auth-react'

function App() {
  const { isAuthenticated, isLoading, user, login, logout, getAccessToken } = useAuth()

  if (isLoading) return null

  if (!isAuthenticated) {
    return <button onClick={login}>Sign in</button>
  }

  return (
    <div>
      <p>Hello {user.email}</p>
      <button onClick={logout}>Sign out</button>
    </div>
  )
}
```

## `useAuth()` reference

| Value | Type | Description |
|---|---|---|
| `isAuthenticated` | `boolean` | Whether the user is logged in |
| `isLoading` | `boolean` | True during initial session check and callback processing |
| `user` | `object \| null` | Decoded JWT payload — `{ sub, email, scope, exp, ... }` |
| `login()` | `() => void` | Redirects to the auth server login page |
| `logout()` | `() => void` | Clears tokens from storage, resets state |
| `getAccessToken()` | `() => Promise<string \| null>` | Returns a valid JWT, silently refreshing if expired |

## Making authenticated API calls

`getAccessToken()` is async — it checks expiry and silently refreshes if needed.

```js
const { getAccessToken } = useAuth()

const res = await fetch('/api/me', {
  headers: {
    Authorization: `Bearer ${await getAccessToken()}`
  }
})
```

## How it works

1. `login()` generates a PKCE `code_verifier` + `code_challenge` (SHA-256), stores the verifier in `sessionStorage`, and redirects to the auth server
2. After login the auth server redirects back with `?code=...&state=...`
3. `AuthProvider` detects the code on mount, verifies `state` (CSRF protection), exchanges the code for tokens via `POST /oauth/token`
4. Tokens are stored, JWT is decoded to populate `user`, URL is cleaned up
5. On page reload, the access token is restored from storage and decoded back into `user`

## Token storage note

Access token and refresh token are stored in `localStorage`. This is simple but means XSS can read them. For higher security, keep the access token in memory and the refresh token in an `HttpOnly` cookie set by a backend proxy.
