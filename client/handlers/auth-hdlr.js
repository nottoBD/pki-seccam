// Copyright (C) 2025 David Botton <david.botton@ulb.be>
// This file is part of PKI Seccam <https://github.com/nottoBD/pki-seccam>.
// Licensed under the WTFPL Version 2. See LICENSE file for details.
import {pinnedFetch} from '@/cryptography/certificate';
import {handleRegistration} from '@/handlers/crypto-hdlr';
import {clearSessionKeys} from '@/utils/session-util';
import {clearCryptoPackage} from "@/utils/transient-util";

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

    let data;
    try {
        data = await res.json();
    } catch (_) {
        return {status: res.status, message: 'Server returned invalid response.'};
    }

    if (!res.ok) {
        return {status: res.status, message: data.message || 'Login failed'};
    }
    return {status: res.status, message: 'Login successful'};
}


export async function logout() {
    try {
        const res = await pinnedFetch('/api/user/logout', {
            method: 'POST',
            headers: cfg.headers,
        });
        const data = await res.json();
        clearSessionKeys();
        clearCryptoPackage();
        return {status: res.status, message: data.message || 'Logged out'};
    } catch (err) {
        clearSessionKeys();
        clearCryptoPackage();
        return { status: err.status || 500, message: err.message || "Logout error" };
    }
}
