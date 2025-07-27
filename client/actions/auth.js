import {pinnedFetch} from '@/cryptography/certificate';
import {handleRegistration} from '@/cryptography/handlers';
import {decryptWithPrivateKey} from '@/cryptography/asymmetric';
import {setSessionKeys} from '@/utils/session-util';

const cfg = {headers: {'Content-Type': 'application/json'}};

export async function register(userForm) {
    const payload = await handleRegistration(userForm);
    const res = await pinnedFetch("/api/user/register", {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload),
    });
    const data = await res.json();

    return {status: res.status, data};
}

export const login = async (username, code, keyPackage) => {
    try {
        if (!keyPackage || !keyPackage.privateKeyJwk) {
            return {status: 400, message: "No crypto package found. Import required."};
        }

        // Post username + code (TOTP) to backend
        const res = await pinnedFetch("/api/user/login", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({username, code}),
        });

        const data = await res.json();

        if (res.ok && data.accessToken) {
            localStorage.setItem("token", data.accessToken);

            // Fetch symmetric/HMAC keys (encrypted) for the session
            const cur = await pinnedFetch(
                "/api/user/current",
                {headers: {Authorization: `Bearer ${data.accessToken}`}},
            );

            if (cur.ok) {
                const userData = await cur.json();
                const {encrypted_symmetric_key, encrypted_hmac_key} = userData;

                try {
                    const privateKeyJwkCopy = {...keyPackage.privateKeyJwk};
                    delete privateKeyJwkCopy.alg;
                    delete privateKeyJwkCopy.key_ops;
                    // Decrypt symmetric/HMAC using imported privateKey (as PEM/JWK)
                    const privKey = await window.crypto.subtle.importKey(
                        'jwk',
                        privateKeyJwkCopy,
                        {name: 'RSA-OAEP', hash: 'SHA-256'},
                        true,
                        ['decrypt']
                    );

                    const symmB64 = await decryptWithPrivateKey(encrypted_symmetric_key, privKey);
                    const hmacB64 = await decryptWithPrivateKey(encrypted_hmac_key, privKey);

                    setSessionKeys(symmB64, hmacB64);
                } catch (e) {
                    console.error('Key-decryption failed:', e);
                    return {status: 500, message: "Key decryption failed"};
                }
            }

            return {status: 200, token: data.accessToken};
        }

        if (res.status === 400 && data.message?.includes("Invalid OTP")) {
            return {status: 400, message: "Invalid OTP"};
        }

        if (res.status === 401 && data.message?.includes("Device not recognized")) {
            return {status: 401, message: "Device not recognized"};
        }

        if (res.status === 403 && data.message?.includes("Email not verified")) {
            return {status: 403, message: "Email not verified"};
        }

        return {status: res.status, message: data.message || "Login failed"};
    } catch (err) {
        console.error(err);
        return {status: 500, message: "Server error"};
    }
};


export async function logout() {
    try {
        const token = localStorage.getItem('token');
        await pinnedFetch('/api/user/logout', {
            method: 'POST',
            headers: {...cfg.headers, Authorization: `Bearer ${token}`},
        });

        localStorage.removeItem('token');
        return {status: 200, message: 'Logged out'};
    } catch (err) {
        return {status: err.status || 500, message: err.message || "Logout error"};
    } finally {
        localStorage.removeItem("token");
    }
}
