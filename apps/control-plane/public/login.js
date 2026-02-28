const form = document.getElementById('login-form');
const errorElement = document.getElementById('error');

if (form) {
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    setError('');
    const formData = new FormData(form);
    const email = String(formData.get('email') || '').trim().toLowerCase();
    const password = String(formData.get('password') || '');
    const totpCode = String(formData.get('totp') || '').trim();

    if (!email || !password) {
      setError('Email and password are required.');
      return;
    }

    try {
      const response = await fetch('/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email, password, totpCode }),
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        const error = typeof payload.error === 'string' ? payload.error : 'login_failed';
        setError(toMessage(error));
        return;
      }
      window.location.assign('/');
    } catch {
      setError('Unable to contact control plane.');
    }
  });
}

function setError(value) {
  if (!errorElement) return;
  errorElement.textContent = value;
}

function toMessage(code) {
  if (code === 'mfa_required') return 'TOTP code is required for this account.';
  if (code === 'mfa_not_configured') return '2FA is enabled but not configured for this account. Set AUTH_OWNER_2FA_PASSKEY (or AUTH_OWNER_TOTP_SECRET).';
  if (code === 'invalid_totp') return 'Invalid TOTP code.';
  if (code === 'rate_limited') return 'Too many attempts. Try again later.';
  if (code === 'invalid_credentials') return 'Invalid email or password.';
  if (code === 'unsupported_auth_mode') return 'This deployment is configured for external identity.';
  return 'Sign-in failed.';
}
