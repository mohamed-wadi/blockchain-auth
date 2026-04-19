/**
 * CryptoClient — WebCrypto RSA-PSS 2048 helper
 * ⚠️ La clé privée ne quitte JAMAIS le navigateur.
 *    Seules les signatures sont envoyées au serveur.
 */
const CryptoClient = (() => {
    let _privateKey = null;
    let _publicKeyPEM = null;
    let _privateKeyPEM = null;

    // ── Generate RSA-2048 key pair ─────────────────
    async function generateKeyPair() {
        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: "RSA-PSS", modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256"
            },
            true, ["sign", "verify"]
        );
        _privateKey = keyPair.privateKey;

        // Export public key as PEM
        const pubExported = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
        _publicKeyPEM = _toPEM(pubExported, "PUBLIC KEY");

        // Export private key as PEM (for user to copy & save)
        const privExported = await window.crypto.subtle.exportKey("pkcs8", _privateKey);
        _privateKeyPEM = _toPEM(privExported, "RSA PRIVATE KEY");

        return { publicKey: _publicKeyPEM, privateKey: _privateKeyPEM };
    }

    // ── Import a private key from PEM string ───────
    // Used during login Phase 2 when user pastes their key
    async function importPrivateKeyPEM(pem) {
        try {
            const pemContents = pem
                .replace(/-----BEGIN [\w\s]+-----/, '')
                .replace(/-----END [\w\s]+-----/, '')
                .replace(/\s/g, '');
            const binaryDer = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0));

            _privateKey = await window.crypto.subtle.importKey(
                "pkcs8", binaryDer.buffer,
                { name: "RSA-PSS", hash: "SHA-256" },
                false, ["sign"]
            );
            return true;
        } catch (err) {
            console.error("Failed to import private key:", err);
            return false;
        }
    }

    // ── Sign a single challenge text ──────────────
    async function signChallenge(challengeText) {
        if (!_privateKey) throw new Error("Pas de clé privée chargée");
        const data = new TextEncoder().encode(challengeText);
        const signature = await window.crypto.subtle.sign(
            { name: "RSA-PSS", saltLength: 32 },
            _privateKey, data
        );
        return btoa(String.fromCharCode(...new Uint8Array(signature)));
    }

    // ── Sign multiple challenges (one per node) ───
    async function signChallenges(challengeMap) {
        if (!_privateKey) throw new Error("Pas de clé privée chargée");
        const signatures = {};
        for (const [nodeId, challenge] of Object.entries(challengeMap)) {
            try {
                signatures[nodeId] = await signChallenge(challenge);
            } catch (err) {
                console.error(`Sign failed for node ${nodeId}:`, err);
                signatures[nodeId] = null;
            }
        }
        return signatures;
    }

    // ── Save encrypted key to localStorage ────────
    async function saveKey(password) {
        if (!_privateKey) return false;
        const keyMaterial = await window.crypto.subtle.importKey(
            "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]
        );
        const salt = window.crypto.getRandomValues(new Uint8Array(16));
        const aesKey = await window.crypto.subtle.deriveKey(
            { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
            keyMaterial, { name: "AES-GCM", length: 256 }, false, ["encrypt"]
        );
        const privExported = await window.crypto.subtle.exportKey("pkcs8", _privateKey);
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const enc = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv }, aesKey, privExported
        );
        localStorage.setItem('bca_key', JSON.stringify({
            salt: btoa(String.fromCharCode(...salt)),
            iv: btoa(String.fromCharCode(...iv)),
            key: btoa(String.fromCharCode(...new Uint8Array(enc))),
            pub: _publicKeyPEM
        }));
        return true;
    }

    // ── Load encrypted key from localStorage ──────
    async function loadKey(password) {
        try {
            const stored = JSON.parse(localStorage.getItem('bca_key'));
            if (!stored) return false;
            const b64ToArr = b => Uint8Array.from(atob(b), c => c.charCodeAt(0));
            const keyMaterial = await window.crypto.subtle.importKey(
                "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]
            );
            const aesKey = await window.crypto.subtle.deriveKey(
                {
                    name: "PBKDF2", salt: b64ToArr(stored.salt),
                    iterations: 100000, hash: "SHA-256"
                },
                keyMaterial, { name: "AES-GCM", length: 256 }, false, ["decrypt"]
            );
            const decrypted = await window.crypto.subtle.decrypt(
                { name: "AES-GCM", iv: b64ToArr(stored.iv) },
                aesKey, b64ToArr(stored.key)
            );
            _privateKey = await window.crypto.subtle.importKey(
                "pkcs8", decrypted,
                { name: "RSA-PSS", hash: "SHA-256" }, true, ["sign"]
            );
            _publicKeyPEM = stored.pub;
            return true;
        } catch { return false; }
    }

    // ── PEM encoding helper ───────────────────────
    function _toPEM(buffer, label) {
        const b64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));
        return `-----BEGIN ${label}-----\n${b64.match(/.{1,64}/g).join('\n')}\n-----END ${label}-----`;
    }

    return {
        generateKeyPair,
        signChallenge,
        signChallenges,
        importPrivateKeyPEM,
        saveKey,
        loadKey,
        getPublicKey: () => _publicKeyPEM,
        getPrivateKeyPEM: () => _privateKeyPEM,
        hasKey: () => _privateKey !== null
    };
})();
