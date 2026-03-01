const form = document.getElementById('login-form');
const errorElement = document.getElementById('error');
const totpGroup = document.getElementById('totp-group');
const totpInput = document.getElementById('totp');

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
        if (error === 'mfa_required') {
          showTotpField();
          setError('Enter the 6-digit code from your authenticator app.');
          return;
        }
        setError(toMessage(error));
        return;
      }
      window.location.assign('/');
    } catch {
      setError('Unable to contact control plane.');
    }
  });
}

function showTotpField() {
  if (totpGroup) {
    totpGroup.style.display = '';
  }
  if (totpInput) {
    totpInput.focus();
  }
}

function setError(value) {
  if (!errorElement) return;
  errorElement.textContent = value;
}

function toMessage(code) {
  if (code === 'mfa_required') return 'Enter the 6-digit code from your authenticator app.';
  if (code === 'mfa_not_configured') return 'Two-factor authentication is enabled but not configured for this account. An administrator needs to set up the authenticator secret.';
  if (code === 'invalid_totp') return 'Invalid authenticator code. Check your app and try again.';
  if (code === 'rate_limited') return 'Too many attempts. Try again later.';
  if (code === 'invalid_credentials') return 'Invalid email or password.';
  if (code === 'unsupported_auth_mode') return 'This deployment is configured for external identity.';
  return 'Sign-in failed.';
}
