/**
 * webauthn.js — WebAuthn biometric client
 * Supports: Fingerprint / Face ID / Windows Hello
 */

const WebAuthnClient = (() => {

    function _b64ToBuffer(b64) {
        const bin = atob(b64.replace(/-/g, '+').replace(/_/g, '/'));
        return Uint8Array.from(bin, c => c.charCodeAt(0)).buffer;
    }

    function _bufToB64(buf) {
        return btoa(String.fromCharCode(...new Uint8Array(buf)))
            .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }

    function isAvailable() {
        return !!(window.PublicKeyCredential && navigator.credentials);
    }

    /** Register biometric credential */
    async function registerBiometric(username, backendUrl) {
        const optRes = await fetch(`${backendUrl}/api/webauthn/register/options`, {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username }),
        });
        if (!optRes.ok) throw new Error('Impossible d\'obtenir les options WebAuthn');
        const options = await optRes.json();

        options.challenge = _b64ToBuffer(options.challenge);
        options.user.id = _b64ToBuffer(options.user.id);
        if (options.excludeCredentials) {
            options.excludeCredentials = options.excludeCredentials.map(c => ({
                ...c, id: _b64ToBuffer(c.id)
            }));
        }

        const credential = await navigator.credentials.create({ publicKey: options });
        const credJSON = {
            id: credential.id,
            rawId: _bufToB64(credential.rawId),
            type: credential.type,
            response: {
                clientDataJSON: _bufToB64(credential.response.clientDataJSON),
                attestationObject: _bufToB64(credential.response.attestationObject),
            },
        };

        const verRes = await fetch(`${backendUrl}/api/webauthn/register/verify`, {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, credential: credJSON }),
        });
        return verRes.json();
    }

    /** Authenticate with existing biometric credential */
    async function authenticate(username, backendUrl) {
        const optRes = await fetch(`${backendUrl}/api/webauthn/auth/options`, {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username }),
        });
        if (!optRes.ok) throw new Error('Biométrie non configurée pour cet utilisateur');
        const options = await optRes.json();

        options.challenge = _b64ToBuffer(options.challenge);
        if (options.allowCredentials) {
            options.allowCredentials = options.allowCredentials.map(c => ({
                ...c, id: _b64ToBuffer(c.id)
            }));
        }

        const assertion = await navigator.credentials.get({ publicKey: options });
        const assertJSON = {
            id: assertion.id,
            rawId: _bufToB64(assertion.rawId),
            type: assertion.type,
            response: {
                clientDataJSON: _bufToB64(assertion.response.clientDataJSON),
                authenticatorData: _bufToB64(assertion.response.authenticatorData),
                signature: _bufToB64(assertion.response.signature),
                userHandle: assertion.response.userHandle
                    ? _bufToB64(assertion.response.userHandle) : null,
            },
        };

        const verRes = await fetch(`${backendUrl}/api/webauthn/auth/verify`, {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, credential: assertJSON }),
        });
        return verRes.json();
    }

    return { isAvailable, registerBiometric, authenticate };
})();