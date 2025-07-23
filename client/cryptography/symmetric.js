import {arrayBufferToBase64, base64ToArrayBuffer} from './asymmetric';

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
        ['encrypt', 'decrypt'] // Usages
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
    const enc = new TextEncoder();
    const messageBuffer = enc.encode(message);
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

export const exportCryptoKeyAsBase64 = async (key) => {
    const raw = await window.crypto.subtle.exportKey('raw', key);
    return btoa(String.fromCharCode(...new Uint8Array(raw)));
};
