// Copyright (C) 2025 David Botton <david.botton@ulb.be>
// This file is part of PKI Seccam <https://github.com/nottoBD/pki-seccam>.
// Licensed under the WTFPL Version 2. See LICENSE file for details.

// Provides all browser-side AES-256-GCM encryption, decryption, and key generation utilities. We derive a 256-bit AES key from a user’s password using PBKDF2 (250k SHA-256 iterations) to encrypt the user’s “crypto passport” JSON. Every encryption uses a fresh 12-byte random IV, and the output package includes the salt, IV, and ciphertext. This ensures each encrypted blob (like credentials or video chunks) is uniquely protected with strong cryptography on the client side.

import {arrayBufferToBase64, base64ToArrayBuffer} from './asymmetric';

export async function reEncryptCryptoPassport(fileOrObject, currentPasswordOrNull, newPassword) {
    let payload;

    if (fileOrObject instanceof Blob || fileOrObject instanceof File) {
        if (!currentPasswordOrNull) throw new Error("Current password is required when a file is provided.");
        payload = await decryptCryptoPassportLogin(fileOrObject, currentPasswordOrNull);
    } else {
        payload = fileOrObject;
    }

    return await encryptCryptoPassportRegistration(payload, newPassword);
}

// When a user registers, we encrypt their sensitive data (credentials) with AES-GCM. Here we derive a key from the provided password (using PBKDF2 with a random salt) and then encrypt the JSON payload. The result is packed into a JSON blob (containing salt, iv, ciphertext) which the user downloads as their encrypted “passport”. This ensures only someone with the correct password can later decrypt and retrieve the original data.

export async function encryptCryptoPassportRegistration(json, password) {
    const encoder = new TextEncoder();
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const keyMaterial = await crypto.subtle.importKey(
        "raw", encoder.encode(password), "PBKDF2", false, ["deriveKey"]
    );
    const key = await crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt,
            iterations: 250000,
            hash: "SHA-256"
        },
        keyMaterial,
        {name: "AES-GCM", length: 256},
        false,
        ["encrypt"]
    );
    const data = encoder.encode(JSON.stringify(json));
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
        {name: "AES-GCM", iv},
        key,
        data
    ));

    const packageObj = {
        salt: Array.from(salt),
        iv: Array.from(iv),
        ciphertext: Array.from(ciphertext),
        version: 1
    };
    const blob = new Blob([JSON.stringify(packageObj)], {type: "application/json"});
    return blob;
}

// Used at login: given the user’s uploaded encrypted passport file and their password, we reverse the process. We parse the JSON, re-derive the AES key using the stored salt, and decrypt the ciphertext (verifying the GCM auth tag internally). If the password is wrong or the file is tampered, decryption fails. On success, we get back the original credentials JSON so the client can use it for authentication.

export async function decryptCryptoPassportLogin(file, password){
    const content = JSON.parse(await file.text());
    const {salt, iv, ciphertext} = content;

    if (!salt || !iv || !ciphertext) throw new Error("Malformed encrypted package.");

    const decoder = new TextDecoder();
    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(password),
        "PBKDF2",
        false,
        ["deriveKey"]
    );

    const key = await crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: new Uint8Array(salt),
            iterations: 250000,
            hash: "SHA-256"
        },
        keyMaterial,
        {name: "AES-GCM", length: 256},
        false,
        ["decrypt"]
    );

    const decrypted = await crypto.subtle.decrypt(
        {name: "AES-GCM", iv: new Uint8Array(iv)},
        key,
        new Uint8Array(ciphertext)
    );

    return JSON.parse(decoder.decode(decrypted));
}

export const exportCryptoKeyAsBase64 = async (key) => {
    const raw = await window.crypto.subtle.exportKey('raw', key);
    return arrayBufferToBase64(raw)
};

export const importKey = async (rawKey) => {
    const key = await window.crypto.subtle.importKey(
        'raw',
        rawKey,
        {
            name: 'AES-GCM',
        },
        true, // extractble
        ['encrypt', 'decrypt']
    );
    return key;
};

export const importHmacKey = async (rawKey) => {
    return await window.crypto.subtle.importKey(
        'raw',
        rawKey,
        {
            name: 'HMAC',
            hash: {name: 'SHA-256'}
        },
        true,
        ['sign', 'verify']
    );
};
export const encryptDatachunk = async (data, key) => {
    const iv = crypto.getRandomValues(new Uint8Array(12));

    let dataBuffer;
    if (data instanceof Blob) {
        dataBuffer = await data.arrayBuffer();
    } else {
        throw new Error("Data to encrypt must be a Blob.");
    }

    const encryptedBuffer = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv,
        },
        key,
        dataBuffer
    );

    return {
        encrypted_data: arrayBufferToBase64(encryptedBuffer),
        iv: arrayBufferToBase64(iv),
    };
};

export const encryptData = async (data, key) => {
    const encoder = new TextEncoder();
    const encoded_data = encoder.encode(data);

    const iv = crypto.getRandomValues(new Uint8Array(12));

    const encrypted_data = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        key,
        encoded_data
    );

    return {
        encrypted_data: arrayBufferToBase64(new Uint8Array(encrypted_data)),
        iv: arrayBufferToBase64(iv)
    };
};

export const decryptData = async (encryptedObject, key) => {
    const encryptedBuffer = base64ToArrayBuffer(encryptedObject.encrypted_data);
    const ivBuffer = base64ToArrayBuffer(encryptedObject.iv);

    const decryptedBuffer = await crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: ivBuffer
        },
        key,
        encryptedBuffer
    );

    const decoder = new TextDecoder();
    const decryptedData = decoder.decode(decryptedBuffer);

    return decryptedData;
};

export const generateSymmetricKey = async () => {
    const key = await window.crypto.subtle.generateKey(
        {
            name: 'AES-GCM',
            length: 256,
        },
        true,
        ['encrypt', 'decrypt']
    );
    return key;
};

export const generateHMACKey = async () => {
    return await window.crypto.subtle.generateKey(
        {
            name: 'HMAC',
            hash: {name: 'SHA-256'},
            length: 256,
        },
        true,
        ['sign', 'verify']
    );
};

export const generateMAC = async (message, key) => {
    const enc = new TextEncoder();
    const messageBuffer = enc.encode(message);

    const mac = await window.crypto.subtle.sign(
        {
            name: 'HMAC',
            hash: {name: 'SHA-256'}
        },
        key,
        messageBuffer
    );

    return arrayBufferToBase64(mac);
};

export const verifyMAC = async (message, mac, key) => {
    if (!mac) throw new Error('Missing MAC');
    const enc = new TextEncoder();
    const msg = (typeof message === 'string') ? message : JSON.stringify(message);
    const messageBuffer = enc.encode(msg);
    const macBuffer = base64ToArrayBuffer(mac);

    const isValid = await window.crypto.subtle.verify(
        {
            name: 'HMAC',
            hash: {name: 'SHA-256'},
        },
        key,
        macBuffer,
        messageBuffer
    );

    return isValid;
};

export const decryptDataChunk = async (encryptedObject, key) => {
    try {
        const encryptedBuffer = base64ToArrayBuffer(encryptedObject.encrypted_data);
        const ivBuffer = base64ToArrayBuffer(encryptedObject.iv);

        const decryptedBuffer = await crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: ivBuffer,
            },
            key,
            encryptedBuffer
        );

        return new Blob([decryptedBuffer], {type: "video/webm"});
    } catch (error) {
        console.error("Error decrypting data chunk:", error);
        throw new Error("Decryption failed.");
    }
};
