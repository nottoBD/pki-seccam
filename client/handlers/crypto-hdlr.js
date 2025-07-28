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
    importPublicKey,
    verifySignatureWithPublicKey
} from "@/cryptography/asymmetric";
import {buildOrganizationCSR, buildUserCSR} from '@/cryptography/certificate';
import {setSessionKeys} from "@/utils/session-util";

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

        const userPrivateKeyJwkCopy = {...decryptedPackage.userPrivateKeyJwk};
        delete userPrivateKeyJwkCopy.alg;
        delete userPrivateKeyJwkCopy.key_ops;

        const orgPublicPem = decryptedPackage.orgPublicKeyPem;

        const pubKey = await importPublicKey(orgPublicPem, 'verify');
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

        // MAC checks
        const macOK_user = await verifyMAC(username, hmac_username, hmacKey);
        const macOK_email = await verifyMAC(encrypted_email, hmac_email, hmacKey);
        const macOK_name = await verifyMAC(encrypted_fullname, hmac_fullname, hmacKey);
        if (!macOK_user || !macOK_email || !macOK_name)
            throw new Error('Core PII integrity check failed');

        // Decrypt user data
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
