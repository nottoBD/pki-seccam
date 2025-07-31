// Copyright (C) 2025 David Botton <david.botton@ulb.be>
// This file is part of PKI Seccam <https://github.com/nottoBD/pki-seccam>.
// Licensed under the WTFPL Version 2. See LICENSE file for details.

export const arrayBufferToBase64 = (buffer) => {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    bytes.forEach(byte => binary += String.fromCharCode(byte));
    return window.btoa(binary);
};

  export function normalizeBase64(input) {
          if (input && typeof input === 'object' && input.type === 'Buffer' && Array.isArray(input.data)) {
              let bin = '';
              for (let i = 0; i < input.data.length; i++) bin += String.fromCharCode(input.data[i]);
              return btoa(bin);
          }
      let s = String(input ?? '').trim();
          s = s.replace(/-----BEGIN [^-]+-----/g, '')
               .replace(/-----END [^-]+-----/g, '')
           .replace(/\s+/g, '');
          s = s.replace(/-/g, '+').replace(/_/g, '/');
          const pad = s.length % 4;
      if (pad) s += '='.repeat(4 - pad);
      return s;
  }

  export const base64ToArrayBuffer = (b64Like) => {
      const b64 = normalizeBase64(b64Like);
      const binary = window.atob(b64);
      const len = binary.length;
      const bytes = new Uint8Array(len);
      for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
      return bytes.buffer;
  };

export async function getOrCreateUserKeypair(username) {
    const {publicKey, privateKey: pk} = await crypto.subtle.generateKey(
        {
            name: 'RSASSA-PKCS1-v1_5',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256',
        },
        true,
        ['sign', 'verify']
    );

    let privateJwk = await crypto.subtle.exportKey("jwk", pk);
    delete privateJwk.alg;
    delete privateJwk.key_ops;
    const spki = new Uint8Array(await crypto.subtle.exportKey('spki', publicKey));
    const b64 = btoa(String.fromCharCode(...spki));
    let publicKeyPem =
        '-----BEGIN PUBLIC KEY-----\n' +
        b64.match(/.{1,64}/g).join('\n') +
        '\n-----END PUBLIC KEY-----';

    let privateKey = await crypto.subtle.importKey(
        "jwk",
        privateJwk,
        {name: "RSASSA-PKCS1-v1_5", hash: "SHA-256"},
        false,
        ["sign"]
    );

    return {publicKeyPem, privateKey, privateJwk};
}

export const importPrivateKey = async (input, useFor = "sign") => {
    try {
          const keyUsages = useFor === "decrypt" ? ["decrypt"] : ["sign"];
          const algorithm = useFor === "decrypt"
            ? { name: "RSA-OAEP", hash: "SHA-256" }
                : { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
      
                  if (input && typeof input === "object" && input.kty) {
                const jwk = { ...input };
                    delete jwk.alg;
                delete jwk.key_ops;
                return await window.crypto.subtle.importKey(
                      "jwk",
                      jwk,
                      algorithm,
                      true,
                      keyUsages
                    );
              }
      
                  if (input instanceof ArrayBuffer || ArrayBuffer.isView(input)) {
                const buf = input instanceof ArrayBuffer ? input : input.buffer;
                return await window.crypto.subtle.importKey(
                      "pkcs8",
                      buf,
                      algorithm,
                      true,
                      keyUsages
                    );
              }
      
                  if (typeof input === "string") {
                const b64 = input
                      .replace(/-----BEGIN [^-]+-----/g, "")
                  .replace(/-----END [^-]+-----/g, "")
                  .replace(/\s+/g, "");
                const keyBuffer = base64ToArrayBuffer(b64);
                return await window.crypto.subtle.importKey(
                      "pkcs8",
                      keyBuffer,
                      algorithm,
                      true,
                      keyUsages
                    );
              }
      
              throw new Error("Unsupported private key format. Provide a JWK object or PEM/PKCS#8.");
        } catch (error) {
          console.error("Private Key Import Error:", error, { input, useFor });
          throw new Error(`Failed to import private key: ${error.message}`);
        }
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
    } catch (err){
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
