import {pinnedFetch} from '@/cryptography/certificate';
import {handleRegistration} from '@/cryptography/handlers';
import {getKey} from '@/keys/indexed-keys';
import {decryptWithPrivateKey} from '@/cryptography/asymmetric';
import {setSessionKeys} from '@/keys/session-keys';

const cfg = {headers: {'Content-Type': 'application/json'}};

export const login = async (username, code) => {
    try {
        const deviceId = localStorage.getItem("device_id");
        const res = await pinnedFetch("/api/user/login", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({username, code, deviceId}),
        });

        const data = await res.json();
        if (res.ok && data.accessToken) {
            /* persist JWT */
            localStorage.setItem("token", data.accessToken);

            /* backend for device-lvl key blobs */
            const cur = await pinnedFetch(
                "/api/user/current",
                {headers: {Authorization: `Bearer ${data.accessToken}`}},
            );

            if (cur.ok) {
                const {encrypted_symmetric_key, encrypted_hmac_key} = await cur.json();
                try {
                    /* non‑extractable private key */
                    const privKey = await getKey(deviceId);
                    if (!privKey) throw new Error('Private key missing');

                    /* decrypt symm blobs */
                    const symmB64 = await decryptWithPrivateKey(encrypted_symmetric_key, privKey);
                    const hmacB64 = await decryptWithPrivateKey(encrypted_hmac_key, privKey);

                    /* session storage */
                    setSessionKeys(symmB64, hmacB64);
                } catch (e) {
                    console.error('Key‑decryption failed:', e);
                }
            }

            return {status: 200, token: data.accessToken};
        } else if (res.status === 202) {
            return {status: 202, message: data.message || "Device approval pending"};
        } else {
            return {status: res.status, message: data.message || "Login failed"};
        }
    } catch (err) {
        console.error(err);
        return {status: 500, message: "Server error"};
    }
};

export async function register(userForm) {
    const payload = await handleRegistration(userForm);
    const {deviceId} = payload;
    const res = await pinnedFetch("/api/user/register", {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload),
    });
    const data = await res.json();

    if (data.deviceCertificate && deviceId) {
        localStorage.setItem(`${deviceId}_certificate`, data.deviceCertificate);
    }
    if (data.organizationCertificate) {
        localStorage.setItem("organization_certificate", data.organizationCertificate);
    }

    return {status: res.status, data, deviceId};
}

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
