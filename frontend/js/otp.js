/**
 * otp.js — OTP UI helpers
 */

const OTPHelper = (() => {

    /** Auto-format 6-digit OTP input and strip non-digits */
    function initOTPInput(inputId) {
        const el = document.getElementById(inputId);
        if (!el) return;
        el.addEventListener('input', () => {
            el.value = el.value.replace(/\D/g, '').slice(0, 6);
        });
        el.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') el.closest('form')?.requestSubmit() || el.blur();
        });
    }

    /** Display countdown for 30-second TOTP window */
    function startTOTPCountdown(elementId) {
        const el = document.getElementById(elementId);
        if (!el) return;
        function tick() {
            const sec = 30 - (Math.floor(Date.now() / 1000) % 30);
            const pct = (sec / 30) * 100;
            el.innerHTML = `
        <div style="display:flex;align-items:center;gap:8px;font-size:12px;color:var(--text3)">
          <svg width="24" height="24" viewBox="0 0 24 24">
            <circle cx="12" cy="12" r="10" fill="none" stroke="var(--border)" stroke-width="2"/>
            <circle cx="12" cy="12" r="10" fill="none" stroke="var(--accent)" stroke-width="2"
              stroke-dasharray="${(pct / 100) * 62.8} 62.8"
              stroke-linecap="round"
              transform="rotate(-90 12 12)"
              style="transition:stroke-dasharray 1s linear"/>
          </svg>
          Code valide pendant <strong style="color:${sec <= 10 ? 'var(--danger)' : 'var(--accent)'}">${sec}s</strong>
        </div>
      `;
        }
        tick();
        return setInterval(tick, 1000);
    }

    /** Validate OTP token format */
    function isValidOTP(token) {
        return /^\d{6}$/.test(token);
    }

    return { initOTPInput, startTOTPCountdown, isValidOTP };
})();
