import {deleteKey, getKey, getPublic, saveKey, savePublic} from '@/keys/indexed-keys';


export async function getOrCreateDeviceKeypair(deviceId) {
    let privateKey = await getKey(deviceId);
    let publicKeyPem = await getPublic(deviceId);

    if (privateKey && privateKey.extractable) {
        console.warn('[keystore] old extractable key found; deleting and regenerating');
        await deleteKey(deviceId);
        privateKey = undefined;
    }

    if (!privateKey || !publicKeyPem) {
        const {publicKey, privateKey: pk} = await crypto.subtle.generateKey(
            {
                name: 'RSA-OAEP',
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: 'SHA-256',
            }, false,
            ['encrypt', 'decrypt']
        );
        /*TODO: stop persisting  private key   locally */
        privateKey = pk;
        await saveKey(deviceId, pk);

        /* derive PEM from SPKI  */
        const spki = new Uint8Array(await crypto.subtle.exportKey('spki', publicKey));
        const b64 = btoa(String.fromCharCode(...spki));
        publicKeyPem =
            '-----BEGIN PUBLIC KEY-----\n' +
            b64.match(/.{1,64}/g).join('\n') +
            '\n-----END PUBLIC KEY-----';

        /* store public part alongside private key */
        await savePublic(deviceId, publicKeyPem);
    }

    return {publicKeyPem, privateKey};
}


export const arrayBufferToBase64 = (buffer) => {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    bytes.forEach(byte => binary += String.fromCharCode(byte));
    return window.btoa(binary);
};

export const base64ToArrayBuffer = (base64) => {
    const binary = window.atob(base64);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
};

export const encryptWithPublicKey = async (data, publicKey) => {
    const enc = new TextEncoder();
    const encoded = enc.encode(data);
    const encrypted = await window.crypto.subtle.encrypt(
        {name: "RSA-OAEP"},
        publicKey,
        encoded
    );
    return arrayBufferToBase64(encrypted);
};

export const importPrivateKey = async (input, useFor = "decrypt") => {
    try {
        const b64 = input
            .replace(/-----BEGIN [^-]+-----/g, "")
            .replace(/-----END [^-]+-----/g, "")
            .replace(/\s+/g, "");

        const keyBuffer = base64ToArrayBuffer(b64);
        const keyUsages = useFor === 'decrypt' ? ['decrypt'] : ['sign'];
        const algorithmName = useFor === 'decrypt' ? 'RSA-OAEP' : 'RSASSA-PKCS1-v1_5';

        const key = await window.crypto.subtle.importKey(
            "pkcs8",
            keyBuffer,
            {name: algorithmName, hash: "SHA-256"},
            true,
            keyUsages
        );

        return key;
    } catch (error) {
        console.error("Private Key Import Error, is PKCS format even?", error, {input, useFor});
        throw new Error(`Failed to import private key: ${error.message}`);
    }
};

export const importPublicKey = async (input, useFor = "encrypt") => {
    try {
        /* If given PEM */
        const b64 = input
            .replace(/-----BEGIN [^-]+-----/g, "")
            .replace(/-----END [^-]+-----/g, "")
            .replace(/\s+/g, "");
        /* b64 to arrayBuffer */
        const keyBuffer = base64ToArrayBuffer(b64);

        /* Map use-case */
        const alg =
            useFor === "verify"
                ? {name: "RSASSA-PKCS1-v1_5", hash: "SHA-256"}
                : {name: "RSA-OAEP", hash: "SHA-256"};

        const usages = [useFor]; // encrypt or verify

        /* import as spki */
        return await window.crypto.subtle.importKey(
            "spki",
            keyBuffer,
            alg,
            true,
            usages
        );
    } catch {
        console.error("❌ Failed to import public key:", err);
        throw new Error("Failed to import public key.");
    }
};

export const decryptWithPrivateKey = async (encryptedData, importedPrivateKey) => {
    const decrypted = await window.crypto.subtle.decrypt(
        {
            name: "RSA-OAEP",
        },
        importedPrivateKey,
        base64ToArrayBuffer(encryptedData)
    );

    return new TextDecoder().decode(decrypted);
};

export const verifySignatureWithPublicKey = async (data, signatureBase64, publicKeyBuffer) => {
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    const signatureBuffer = base64ToArrayBuffer(signatureBase64);

    const isValid = await window.crypto.subtle.verify(
        {
            name: "RSASSA-PKCS1-v1_5",
            hash: "SHA-256",
        },
        publicKeyBuffer,
        signatureBuffer,
        dataBuffer
    );

    return isValid;
};
