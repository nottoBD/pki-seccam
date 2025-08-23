// Copyright (C) 2025 David Botton <david.botton@ulb.be>
// This file is part of PKI Seccam <https://github.com/nottoBD/pki-seccam>.
// Licensed under the WTFPL Version 2. See LICENSE file for details.

// High-level client crypto handler coordinating key management for login, registration, and trust. This module ties together the low-level crypto routines to manage session keys and personal data. It deals with unwrapping shared keys for trusted users, wrapping a normal user’s keys to share with a trusted user, handling decryption of user data after login, and preparing all necessary encrypted payloads during user registration. Essentially, it’s the brain of the front-end security workflow, ensuring that sensitive keys and data are properly encrypted/decrypted at the right times.

import {
    decryptData,
    encryptData,
    exportCryptoKeyAsBase64,
    generateHMACKey,
    generateMAC,
    generateSymmetricKey,
    importHmacKey,
    importKey,
    verifyMAC
} from "@/cryptography/symmetric";

import {
    base64ToArrayBuffer,
    decryptWithPrivateKey,
    encryptWithPublicKey,
    getOrCreateUserKeypair,
    importPrivateKey,
    importPublicKey,
} from "@/cryptography/asymmetric";
import {
    buildOrganizationCSR,
    buildUserCSR,
    importPublicKeyFromCertificate,
    pinnedFetch
} from '@/cryptography/certificate';
import {setSessionKeys} from "@/utils/session-util";


// Used by a trusted user when they log in and need to access a normal user’s video. Given the normal user’s symmetric and HMAC keys wrapped with the trusted user’s public RSA key (as stored on the server), this function uses the trusted user’s RSA private key (JWK) to decrypt those (“unwrap” them). We import the private key for RSA-OAEP decryption and then decrypt each wrapped key. If successful, we end up with the raw symmetric key and HMAC key, which the trusted user can use to decrypt and verify the normal user’s video chunks. If anything goes wrong (e.g., wrong key or corrupted data), we throw an error – the trust relationship can’t be established.

export const unwrapKeysWithPrivateKey = async (wrappedSymmetricKey, wrappedHmacKey, privateKeyJwk) => {
    try {
        if (!privateKeyJwk) throw new Error('No privateKeyJwk provided for unwrap');
        const importedPrivateKey = await importPrivateKey(privateKeyJwk, 'decrypt');

        const symmetricKeyBase64 = await decryptWithPrivateKey(wrappedSymmetricKey, importedPrivateKey);
        const hmacKeyBase64 = await decryptWithPrivateKey(wrappedHmacKey, importedPrivateKey);

        const symmetricKey = await importKey(base64ToArrayBuffer(symmetricKeyBase64));
        const hmacKey = await importHmacKey(base64ToArrayBuffer(hmacKeyBase64));

        return { symmetricKey, hmacKey };
    } catch (err) {
        console.error('unwrapKeysWithPrivateKey error:', err);
        throw new Error('Failed to unwrap keys (RSA-OAEP).');
    }
};


// Invoked by a normal user who wants to share their videos with a trusted user. We take the normal user’s current session keys (their AES symmetric key and HMAC key, stored in sessionStorage) and encrypt each one with the trusted user’s RSA public key. This uses RSA-OAEP via encryptWithPublicKey, producing Base64-wrapped keys that only the trusted user can decrypt with their private key. We then send these to the backend /api/keywrap endpoint, which will store the relationship. Essentially, this is how a normal user “invites” a trusted user by securely sharing the keys needed to decrypt their content – without ever exposing the raw keys to the server.

export const setTrustForUser = async (trustedUser) => {
    try {
        const symmKeyBase64 = sessionStorage.getItem("session_symm");
        const hmacKeyBase64 = sessionStorage.getItem("session_hmac");

        const trustedUserPublicKey = await importPublicKey(trustedUser.public_key, 'encrypt');

        const wrappedSymmetricKey = await encryptWithPublicKey(symmKeyBase64, trustedUserPublicKey);
        const wrappedHmacKey = await encryptWithPublicKey(hmacKeyBase64, trustedUserPublicKey);

        const response = await pinnedFetch('/api/keywrap', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                trusted_user_id: trustedUser._id,
                wrapped_symmetric_key: wrappedSymmetricKey,
                wrapped_hmac_key: wrappedHmacKey,
            }),
        });

        if (!response.ok) throw new Error('Failed to set trust');

        return await response.json();
    } catch (err) {
        console.error(err);
        throw new Error('Error setting trust.');
    }
};


// Called after a successful login to initialize the client-side crypto context. We receive user_data from the server (which includes encrypted keys and possibly encrypted email, depending on user type) and an in-memory crypto package (the user’s private RSA key, loaded from their crypto passport). If the logged-in user is a trusted user, we delegate to handleTrustedUserSession for the more complex decryption flow. For a normal user, we proceed to decrypt their stored symmetric key and HMAC key using their RSA private key (these keys were originally encrypted with their own public key at registration and stored server-side). Once we recover the keys, we save them in session storage for easy use. We then use the symmetric key to decrypt the user’s email (which the server only ever stored encrypted). This whole process ensures the server never sees sensitive data like plaintext emails or raw keys – all that decryption happens here on the client, using the user’s private key from their crypto package.

export const handleAnyUserSession = async (user_data, inMemoryPackage = null, onError = (msg) => {
}) => {
    try {
        let keyPackage = inMemoryPackage;

        if (!keyPackage || !keyPackage.privateKeyJwk) {
            onError("Crypto package not found or private key malformed.");
            throw new Error("Crypto package not found.");
        }

        if (user_data.isTrustedUser) {
            return await handleTrustedUserSession(user_data, keyPackage);
        } else {
            console.log("Handling untrusted user session");
        }

        const privateKeyJwkCopy = {...keyPackage.privateKeyJwk};
        delete privateKeyJwkCopy.alg;

        const privKey = await window.crypto.subtle.importKey(
            'jwk',
            privateKeyJwkCopy,
            {name: 'RSA-OAEP', hash: 'SHA-256'},
            true,
            ['decrypt']
        );

        const symmetric_key_base64 = await decryptWithPrivateKey(
            user_data.encrypted_symmetric_key,
            privKey
        );
        const symmetric_key = await importKey(base64ToArrayBuffer(symmetric_key_base64));

        const hmac_key_base64 = await decryptWithPrivateKey(
            user_data.encrypted_hmac_key,
            privKey
        );
        const hmac_key = await importHmacKey(base64ToArrayBuffer(hmac_key_base64));

        setSessionKeys(symmetric_key_base64, hmac_key_base64);

        const enc_email = JSON.parse(user_data.email);
        const decrypted_email = await decryptData(enc_email, symmetric_key);

        return {
            username: user_data.username,
            email: decrypted_email,
        };
    } catch (error) {
        console.error("Decryption error:", error);
        onError('Unable to decrypt data. Import your crypto package.');
        throw Error('Unable to decrypt data.');
    }
};


// Similar to the above but for trusted users, who have more sensitive fields. After a trusted user logs in, we use their private RSA key to decrypt their personal symmetric and HMAC keys (which were encrypted with their own public key and stored in the TrustedUser record). With those keys, we verify the integrity of core fields like username, email, and fullname using HMACs that the server provided – if any of these HMAC checks fail, something’s wrong and we abort (this ensures none of the user’s PII was tampered with in storage). Once integrity checks pass, we decrypt the actual email and fullname with the symmetric key, and do the same for optional fields like organization and country if they exist. Finally, we stash the symmetric and HMAC keys in session storage for later, and return the decrypted profile info. The result is that even as a trusted user (with more data), all your personal details remain encrypted on the server and are only decrypted here in the browser after verifying nothing was altered.

export const handleTrustedUserSession = async (userData, decryptedPackage) => {
    try {
        const {
            username,
            hmac_username,
            email: encrypted_email,
            hmac_email,
            fullname: encrypted_fullname,
            hmac_fullname,
            organization: encrypted_org,
            hmac_organization,
            country: encrypted_country,
            hmac_country,
            encrypted_symmetric_key,
            encrypted_hmac_key,
        } = userData;

        const sourceJwk = decryptedPackage?.privateKeyJwk ?? decryptedPackage?.userPrivateKeyJwk;
        if (!sourceJwk) throw new Error('Missing private key JWK in package.');
        const userPrivateKeyJwkCopy = { ...sourceJwk };

        delete userPrivateKeyJwkCopy.alg;
        delete userPrivateKeyJwkCopy.key_ops;


        const privKey = await window.crypto.subtle.importKey(
            'jwk',
            userPrivateKeyJwkCopy,
            {name: 'RSA-OAEP', hash: 'SHA-256'},
            true,
            ['decrypt']
        );


        const symKeyBase64 = await decryptWithPrivateKey(encrypted_symmetric_key, privKey);
        const hmacKeyBase64 = await decryptWithPrivateKey(encrypted_hmac_key, privKey);

        const symKey = await importKey(base64ToArrayBuffer(symKeyBase64));
        const hmacKey = await importHmacKey(base64ToArrayBuffer(hmacKeyBase64));

        ['hmac_username','hmac_email','hmac_fullname'].forEach((k) => {
            const v = userData[k];
            if (typeof v !== 'string') console.warn(`${k} is not a string`, v);
            else if (!/^[A-Za-z0-9+/=_-]+$/.test(v.trim())) console.warn(`${k} contains non-base64 chars`, v);
        });

        const macOK_user = await verifyMAC(username, hmac_username, hmacKey);
        const macOK_email = await verifyMAC(encrypted_email, hmac_email, hmacKey);
        const macOK_name = await verifyMAC(encrypted_fullname, hmac_fullname, hmacKey);
        if (!macOK_user || !macOK_email || !macOK_name)
            throw new Error('Core PII integrity check failed');

        const emailObj = JSON.parse(encrypted_email);
        const fullnameObj = JSON.parse(encrypted_fullname);

        const decrypted_email = await decryptData(emailObj, symKey);
        const decrypted_fullname = await decryptData(fullnameObj, symKey);

        let decrypted_org = '';
        let decrypted_country = '';

        if (encrypted_org && hmac_organization) {
            const macOK_org = await verifyMAC(encrypted_org, hmac_organization, hmacKey);
            if (macOK_org) {
                decrypted_org = await decryptData(JSON.parse(encrypted_org), symKey);
            }
        }

        if (encrypted_country && hmac_country) {
            const macOK_cty = await verifyMAC(encrypted_country, hmac_country, hmacKey);
            if (macOK_cty) {
                decrypted_country = await decryptData(JSON.parse(encrypted_country), symKey);
            }
        }

        // Store session keys
        setSessionKeys(
            symKeyBase64,
            hmacKeyBase64
        );

        return {
            username,
            email: decrypted_email,
            fullname: decrypted_fullname,
            organization: decrypted_org,
            country: decrypted_country,
        };

    } catch (err) {
        console.error(err);
        throw new Error('Unable to decrypt data.');
    }
};


// Prepares all necessary cryptographic material when a new user registers. We generate a fresh RSA key pair for the user (the private part will be saved in the user’s browser as their “crypto package”). If the user is signing up as a trusted user (has fullname, org, etc.), we also create a CSR for their user certificate (trustedUserCsr) using that RSA key, and even generate a separate RSA key pair/CSR for their organization (to issue an org certificate). Next, we generate a random AES symmetric key and an HMAC key – these will secure the user’s personal data. We encrypt the user’s email with the symmetric key (AES-GCM) and compute an HMAC for it, so the server never sees the plaintext email. We then encrypt both the symmetric key and HMAC key with the user’s RSA public key (so only the user’s corresponding private key can recover them). All these pieces – encrypted keys, encrypted email, HMACs, public key, etc. – are bundled into a payload object and sent to the server as part of registration. The server will store those encrypted values but can’t read them. Meanwhile, we package up the user’s private key (and org’s private key if applicable) into userPackage/orgPackage so the client can keep them (e.g., prompting the user to download their crypto package file). In short, this function ensures a new user’s sensitive info and keys are locked down with encryption from the very start of account creation.

export const handleRegistration = async (userData) => {
    try {

        let publicKeyPem;
        let privateKeyJwk;
        let trustedUserCsr = null;
        const isTrustedUser = !!(userData.fullname && userData.organization);

        if (isTrustedUser) {
            const result = await buildUserCSR(userData.username);
            trustedUserCsr = result.csrPem;
            publicKeyPem = result.publicKeyPem;
            privateKeyJwk = result.privateJwk;
        } else {
            const keypair = await getOrCreateUserKeypair(userData.username);
            publicKeyPem = keypair.publicKeyPem;
            privateKeyJwk = keypair.privateJwk;
        }

        const userPublicKey = await importPublicKey(publicKeyPem, 'encrypt');

        const symmetricKey = await generateSymmetricKey();
        const hmacKey = await generateHMACKey();

        const symmetricKeyBase64 = await exportCryptoKeyAsBase64(symmetricKey);
        const hmacKeyBase64 = await exportCryptoKeyAsBase64(hmacKey);

        const encrypted_symmetric_key = await encryptWithPublicKey(symmetricKeyBase64, userPublicKey);
        const encrypted_hmac_key = await encryptWithPublicKey(hmacKeyBase64, userPublicKey);

        const encrypted_email = await encryptData(userData.email, symmetricKey);
        const emailBlob = JSON.stringify(encrypted_email);
        const email_hmac = await generateMAC(emailBlob, hmacKey);

        const payload = {
            username: userData.username,
            hmac_username: await generateMAC(userData.username, hmacKey),
            email: emailBlob,
            hmac_email: email_hmac,
            public_key: publicKeyPem,
            email_raw: userData.email,
            encrypted_symmetric_key,
            encrypted_hmac_key,
            isTrustedUser,
        };


        let orgPrivateJwk = null;
        let orgPublicKeyPem = null;

        if (isTrustedUser) {
            const encrypted_fullname = await encryptData(userData.fullname, symmetricKey);
            payload.fullname = JSON.stringify(encrypted_fullname);
            payload.hmac_fullname = await generateMAC(payload.fullname, hmacKey);
            payload.organization = userData.organization.trim();
            payload.country = userData.country.trim();
            payload.trustedUserCsr = trustedUserCsr;
            const orgResult = await buildOrganizationCSR(
                userData.fullname, payload.organization, payload.country
            );
            payload.orgCsr = orgResult.csrPem;
            orgPrivateJwk = orgResult.privateJwk;
            orgPublicKeyPem = orgResult.publicKeyPem;
        }

        const userPackage = {
            privateKeyJwk,
            publicKeyPem,
            certificate: null
        };
        if (!isTrustedUser) {
            userPackage.symmetricKey = symmetricKeyBase64;
            userPackage.hmacKey = hmacKeyBase64;
        }

        const orgPackage = isTrustedUser ? {
            privateKeyJwk: orgPrivateJwk,
            publicKeyPem: orgPublicKeyPem,
            certificate: null
        } : null;

        return {payload, userPackage, orgPackage};
    } catch (err) {
        console.error(err);
        throw new Error('Registration failed client-side.');
    }
};
