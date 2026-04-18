const CryptoClient = (() => {
    let _privateKey = null;
    let _publicKeyPEM = null;

    async function generateKeyPair() {
        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: "RSA-PSS", modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256"
            },
            true, ["sign", "verify"]
        );
        _privateKey = keyPair.privateKey;
        const exported = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
        _publicKeyPEM = _toPEM(exported, "PUBLIC KEY");
        return _publicKeyPEM;
    }

    // ⚠️ La clé privée ne quitte JAMAIS le navigateur
    async function signChallenge(challengeText) {
        if (!_privateKey) throw new Error("Pas de clé privée");
        const data = new TextEncoder().encode(challengeText);
        const signature = await window.crypto.subtle.sign(
            { name: "RSA-PSS", saltLength: 32 },
            _privateKey, data
        );
        return btoa(String.fromCharCode(...new Uint8Array(signature)));
    }

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

    function _toPEM(buffer, label) {
        const b64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));
        return `-----BEGIN ${label}-----\n${b64.match(/.{1,64}/g).join('\n')}\n-----END ${label}-----`;
    }

    return {
        generateKeyPair, signChallenge, saveKey, loadKey,
        getPublicKey: () => _publicKeyPEM,
        hasKey: () => _privateKey !== null
    };
})();
