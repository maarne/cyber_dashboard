# Feature 5 — Optional SSO, MFA, and identity governance

**Status:** proposed; implement only after approval.  
**Goal:** support safer human sign-in without weakening the existing local administrator recovery path or machine-token controls.  
**Prerequisites:** current revocable JWT sessions and admin/analyst/viewer roles. No other planned feature is required.

## 1. Current state and gap

`auth_service.py` handles bcrypt passwords, JWTs tied to account IDs/session versions, and logout revocation. `main.py` also accepts hashed machine API tokens. There is no external identity binding, second-factor challenge, recent-reauthentication state, account-disable control, or MFA recovery workflow.

Adding a provider login button alone is insufficient: the critical work is secure identity linking, incomplete-login isolation, authorization, recovery, and tests for replay/lockout.

## 2. First-release scope

### Include

- Optional local TOTP MFA using a free authenticator application, with encrypted secrets and one-time recovery codes.
- One optional, explicitly configured OIDC provider using Authorization Code + PKCE; standard protocol support rather than a provider-specific password flow.
- Admin-provisioned users and explicit external-identity linking. No automatic admin/group-role elevation.
- Local account disable/re-enable, recent reauthentication for sensitive security changes, session invalidation, and a safe recovery procedure.
- A local primary administrator recovery path, protected by the same MFA policy rather than an undocumented bypass.

### Exclude initially

- SAML, LDAP, SCIM, multi-provider discovery, passkeys/WebAuthn, SMS/email OTP, self-service public signup, paid conditional-access policies, and automatic directory-group role mapping.
- Provisioning a cloud identity tenant, hosted authentication service, secret-store subscription, or any paid resource.

## 3. Cost and development strategy

- Local TOTP and isolated/mock OIDC tests have no service cost. Prefer these for routine development.
- An existing provider's free capabilities may be used only after the user selects it and confirms its allowances. Do not assume Entra Conditional Access or a provider's enterprise MFA policy is free.
- An optional developer-run local OIDC server is acceptable, but it is not required and is not deployed to Azure by this feature.
- Keep F1-only guards. The callback requires a stable configured external HTTPS origin; if F1 is unavailable for the workload, fail configuration/deployment rather than select a paid tier.
- SQLite account/MFA data is ephemeral on the current Azure setup. State this prominently; retaining the encryption key alone cannot restore lost enrollment rows.

## 4. Recommended implementation sequence

Implement this as **one feature delivered in security-reviewed slices**:

1. Canonical principal/account state and rate-limited login challenges.
2. Local TOTP enrollment, login verification, recovery, and sensitive-action reauthentication.
3. Optional OIDC callback/token verification and explicit identity linking.
4. Provider/MFA policies, recovery drills, UI, and full end-to-end regression review.

Do not enable mandatory MFA or disable any local login path until enrollment/recovery is tested.

## 5. Proposed data model and settings

| Table/change | Essential fields and constraints |
| --- | --- |
| `users` additions | `is_active` default true, `local_login_enabled` default true, MFA-policy/enforcement metadata; existing `session_version` remains authoritative |
| `user_external_identities` | Internal user ID, exact provider issuer, subject, display metadata, linked/last-login times; unique `(issuer, subject)` |
| `oidc_login_transactions` | Hashed state, nonce, encrypted PKCE verifier, purpose `login/link`, optional target user ID/session binding, allowlisted return path, expiry, single-use completion state |
| `mfa_enrollments` | User ID, encrypted TOTP secret and key version, algorithm/digits/period, pending/active state, confirmed time, last accepted time step |
| `mfa_recovery_codes` | User ID, one-way hashed high-entropy code, created/used times; single-use atomic consumption |
| `auth_challenges` | Random challenge ID hash, user ID, purpose, completed primary-factor context, issued/expiry times, attempt count, consumed time; no full session privilege |
| `auth_rate_windows` | Privacy-preserving identity/IP bucket, purpose, window, attempts/lockout expiry; shared across workers |
| Authentication policy | Versioned admin settings for optional/required MFA and SSO behavior; configuration secrets stay outside policy rows/responses |

Proposed configuration: `FEATURE_ENTERPRISE_AUTH`, `AUTH_SECRETS_ENCRYPTION_KEY`, `PUBLIC_BASE_URL`, `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, and an explicit OIDC enable flag. Use a separate stable encryption key, not the JWT signing key; redact all secrets from APIs, logs, errors, and exports.

Existing users keep local login enabled on migration. For explicitly provisioned SSO-only accounts, preserve the current NOT NULL password schema with an unusable random password hash plus `local_login_enabled=false`; never introduce a known default password. Primary-admin local login cannot be accidentally disabled through provider configuration.

## 6. Local MFA flow

### Enrollment

1. Require a current human session and recent primary-factor/MFA reauthentication; a stolen existing cookie alone must not enroll the attacker's authenticator. For an explicitly linked SSO-only user, fresh verified OIDC authentication can provide the primary factor instead of an unavailable local password.
2. Generate a TOTP secret with cryptographic randomness, encrypt it using a maintained library from the existing `cryptography` dependency, and keep the enrollment pending with a short TTL.
3. Reveal an `otpauth` URI/QR only to that user over the authenticated flow. Generate QR locally with a pinned open-source dependency or provide a copyable URI; never send the secret to a remote QR service.
4. Verify a valid TOTP before activation; then invalidate older sessions and reveal recovery codes once.
5. Show a confirmation step requiring the user to save codes. Store only one-way hashes of high-entropy recovery codes.

### Login

- Valid password → short-lived pending challenge, **not** a normal access token.
- If MFA is mandatory but the account has no active enrollment, a successfully verified primary factor produces an **enrollment-only challenge**. It authorizes only enrollment/confirmation and recovery-code setup, never the dashboard or protected APIs. This prevents the lockout loop where MFA is required to sign in but sign-in is required to enroll. The same restricted flow handles forced re-enrollment after an approved admin reset.
- Valid TOTP/recovery code → consume challenge atomically, record authentication methods/time, then issue the ordinary revocable application JWT.
- Suggested defaults: five-minute challenge lifetime, five attempts per challenge, standard 30-second TOTP periods with at most one adjacent-step tolerance. Persist the last accepted step to block replay across workers.
- Recovery codes are one-time credentials. Two concurrent uses may succeed only once; recovery should force review/re-enrollment, not silently disable MFA.
- Enforce shared per-account and source-IP attempt budgets with generic responses that do not reveal whether a username exists. Trust proxy-derived client identity only through explicitly trusted proxy configuration, not arbitrary forwarded headers.
- User disable, role/password changes, MFA enrollment/reset, provider unlink, and policy changes invalidate affected sessions/challenges. Current-role/account checks remain server-side.

## 7. OIDC flow and account linking

1. Begin login with high-entropy state/nonce and PKCE S256. Bind state to a browser-specific short-lived HttpOnly correlation cookie and a database transaction; use an allowlisted relative return path.
2. Redirect only to the configured provider authorization endpoint. Callback uses a fixed URI derived from `PUBLIC_BASE_URL`, not untrusted Host/forwarded headers.
3. Atomically claim the one-use callback transaction before exchanging the code; a concurrent/replayed callback cannot reuse it.
4. Verify ID-token signature and algorithm against the configured issuer's JWKS, exact issuer, audience/authorized party where applicable, expiry/not-before, and nonce. Refresh JWKS once on a new key ID with bounded caching; no unverified-token fallback.
5. Resolve the internal user by **exact issuer + subject**, never by email/display-name matching. Local roles remain authoritative; claims/groups cannot grant admin permissions.
6. If the identity is not linked to an approved account, deny with a safe enrollment instruction. Optional future just-in-time provisioning would require a separate explicit approval/default-viewer policy.
7. Linking an identity to an existing account requires that account's fresh local/MFA reauthentication and an OIDC transaction marked specifically for linking. A matching or “verified” email is not sufficient proof.
8. Reuse the normal revocable application session. Do not store provider access/refresh tokens unless a separately approved feature actually requires them; never expose them to JavaScript.

### Outbound/provider safety

Use a maintained, pinned OIDC/OAuth library with explicit state/nonce/PKCE handling; review its protocol behavior rather than implementing token verification from scratch. Existing `outbound_service.py` does not yet support the form bodies/headers needed for token exchange: extend it narrowly for a provider-scoped client while retaining public-address pinning, TLS verification, bounded responses, and redirect controls. Do not bypass SSRF protections merely to make discovery work.

Production-like issuer/discovery/JWKS/token endpoints must be HTTPS and explicitly trusted; reject metadata/private-network destinations. A local test issuer exception, if needed, must be an explicit development-only allowlist, disabled when `ENV=production`, and must not relax webhook/RSS guards. Mock protocol tests should need no exception.

## 8. MFA policy, service accounts, and recovery

- Default rollout: MFA optional; after enrollment tests, allow the admin to require it for human admins or all human users.
- By default, require CyberDash's enrolled TOTP even after SSO when local policy requires MFA. Do not infer MFA from an arbitrary provider claim. Trusting specific `acr/amr` values is a later provider-specific, explicitly tested policy.
- Introduce short-lived recent-reauthentication assertions for MFA reset, identity linking/unlinking, password-policy changes, and new admin-token creation. Do not make a long-lived session JWT's issuance time a permanent step-up proof.
- Machine API tokens remain non-interactive credentials governed by their own role, expiry, revocation, and rate limit. They do not satisfy a human MFA challenge and cannot change human MFA/linking state.
- Never count the presence of an SSO account as a recoverable local administrator. Preserve the primary account's local login and independently saved MFA recovery codes.
- Reject unlinking/disabling the last usable sign-in method. Changing an SSO-only account to local login requires an explicit verified password-setting/recovery workflow; a random unusable hash is not a recovery mechanism.
- Admin reset of another user's MFA requires recent admin MFA, a recorded reason, session/challenge revocation, and a forced re-enrollment state. It must not reveal an old secret or let an admin impersonate the user.
- Document a last-resort **operator-only** recovery command requiring direct host access, explicit confirmation, backup, and an audit record. No unauthenticated HTTP reset route and no “temporary universal password.”
- F1 data loss can remove all users/enrollments and reopen initial setup. Limit access during bootstrap/recovery and do not describe an ephemeral deployment as enterprise-ready identity storage.

## 9. Proposed API, pages, and code map

| Route | Access / behavior |
| --- | --- |
| `POST /api/auth/login` | Existing password entry point; returns either success or an explicit MFA-required challenge, never an authenticated cookie before completion |
| `POST /api/auth/mfa/verify` | Pending challenge only; TOTP or one-time recovery-code verification |
| `POST /api/auth/reauthenticate` | Human session + current factors; short-lived step-up assertion |
| `POST /api/auth/mfa/enroll/start`, `/confirm` | Freshly reauthenticated human or a valid enrollment-only challenge, with browser correlation/CSRF protections |
| `POST /api/auth/mfa/disable` | Current human user with recent MFA; cannot violate active required-MFA policy or remove the last recoverable admin path |
| `POST /api/auth/mfa/recovery-codes/regenerate` | User with recent MFA; old recovery codes revoked atomically |
| `GET /auth/oidc/login`, `GET /auth/oidc/callback` | Public protocol endpoints; strict correlation/state controls, no full session until all required factors complete |
| `POST /api/auth/identities/link`, `/unlink` | Current human user with fresh factors; link starts purpose-bound OIDC flow |
| `GET/POST /api/security/auth-policy` | Admin; writes require recent MFA; responses expose configuration status, never secrets |
| `POST /api/users/{username}/disable`, `/enable`, `/mfa-reset` | Human admin with recent MFA and reason; protect primary/recoverable-admin invariants |

- Add `oidc_service.py`, `mfa_service.py`, challenge/rate-limit services, typed schemas, and a narrowly scoped provider HTTP client.
- Extend `auth_service.py`, `main.py` dependencies, login modal/account UI, Settings Security, and `dashboard.js`; provider/config UI remains optional.
- Test partial-login cookie semantics, SameSite behavior for OIDC redirects, session invalidation, safe error messages, and accessibility. Disabled optional SSO must not break normal startup/login.

## 10. Tests and acceptance criteria

- Use RFC TOTP vectors and a controlled clock. Test drift boundaries, replayed steps, expired/used challenges, concurrent recovery-code consumption, missing encryption keys, and tampered ciphertext.
- A password-only or SSO-only result cannot reach protected APIs when MFA is required. Machine tokens do not become browser sessions or bypass factor-sensitive operations.
- Required-MFA users with no enrollment can complete the restricted bootstrap without obtaining general access; expired enrollment challenges and password-only attempts to disable an enrolled factor are rejected.
- Mock an OIDC provider: wrong state/nonce/issuer/audience, expired token, disallowed algorithms, malicious discovery endpoints, JWKS rotation, callback replay, open redirects, and token-endpoint failures must all fail safely.
- Email collisions, renamed email addresses, and same subject under different issuers cannot link accounts accidentally or escalate roles.
- Policy changes/account disable/MFA resets revoke affected sessions and pending challenges across both workers; protected primary-admin recovery remains possible.
- No tokens, TOTP seeds, raw recovery codes, authorization codes, or provider client secrets appear in logs, audit entries, general settings responses, or exports.
- A provider outage does not disable local recovery or trigger a paid fallback. Backup/restore tests use the same external encryption key; missing-key recovery limitations are explicit.
- Add fake-provider/browser tests plus the existing local-login/API-token regressions. Do not configure a real provider or enroll the user's real account without explicit approval.

## 11. Rollout and decisions before implementation

First enable local MFA optionally for a test analyst, verify recovery, then test an admin. Only then allow a mandatory policy. Add SSO with one test account before linking primary/admin identities. Provider disablement must revoke in-flight provider challenges and preserve safe local access; disabling a UI flag must not silently bypass an already-required MFA policy.

**Recommended defaults to approve:** local TOTP first, admin-provisioned/link-only SSO accounts, no auto-role mapping, independent local MFA after SSO, optional enforcement initially, and a separately stored encryption key. **Provider selection and callback origin** are genuine user decisions before the OIDC slice; local MFA and mocked protocol tests do not depend on them.
