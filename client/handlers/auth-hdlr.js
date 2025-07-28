import {pinnedFetch} from '@/cryptography/certificate';
import {handleRegistration} from '@/handlers/crypto-hdlr';
import {clearSessionKeys} from '@/utils/session-util';

const cfg = {headers: {'Content-Type': 'application/json'}};

export async function register(userForm) {
    const {payload, userPackage, orgPackage} = await handleRegistration(userForm);
    const res = await pinnedFetch("/api/user/register", {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload),
    });
    const data = await res.json();

    return {status: res.status, data, userPackage, orgPackage};
}

export async function login(username, code) {
    const res = await pinnedFetch("/api/user/login", {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({username, code}),
    });
    const data = await res.json();

    return {status: res.status, message: data.message, token: data.accessToken};
}


export async function logout() {
    try {
        const token = localStorage.getItem('token');
        await pinnedFetch('/api/user/logout', {
            method: 'POST',
            headers: {...cfg.headers, Authorization: `Bearer ${token}`},
        });

        localStorage.removeItem('token');
        clearSessionKeys();
        return {status: 200, message: 'Logged out'};
    } catch (err) {
        return {status: err.status || 500, message: err.message || "Logout error"};
    } finally {
        localStorage.removeItem("token");
        clearSessionKeys();
    }
}