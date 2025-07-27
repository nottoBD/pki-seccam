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
import {buildOrganizationCSR, buildUserCSR} from './certificate';
import {getUserKeyPackage, saveUserKeyPackage} from "@/utils/idb-util";
import {setSessionKeys} from "@/utils/session-util";

const toB64 = async k =>
    btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.exportKey("raw", k))));


export const handleRegistration = async (userData) => {
    try {
        const existingPackage = await getUserKeyPackage(userData.username);
        if (existingPackage) {
            throw new Error('Crypto package already exists for this username. Registration aborted to prevent duplicates.');
        }

        let publicKeyPem;
        let privateKeyJwk;
        let trustedUserCsr = null;
        let certificate = null;
        const isTrustedUser = !!(userData.fullname && userData.organization);

        if (isTrustedUser) {
            const result = await buildUserCSR(userData.username, navigator.userAgent);
            trustedUserCsr = result.csrPem;
            publicKeyPem = result.publicKeyPem;
            privateKeyJwk = result.privateJwk;
        } else {
            const keypair = await getOrCreateUserKeypair(userData.username);
            publicKeyPem = keypair.publicKeyPem;
            privateKeyJwk = keypair.privateJwk;
        }

        const devicePublicKey = await importPublicKey(publicKeyPem, 'encrypt');

        const symmetricKey = await generateSymmetricKey();
        const hmacKey = await generateHMACKey();

        const symmetricKeyBase64 = await exportCryptoKeyAsBase64(symmetricKey);
        const hmacKeyBase64 = await exportCryptoKeyAsBase64(hmacKey);

        const encrypted_symmetric_key = await encryptWithPublicKey(symmetricKeyBase64, devicePublicKey);
        const encrypted_hmac_key = await encryptWithPublicKey(hmacKeyBase64, devicePublicKey);

        const encrypted_email = await encryptData(userData.email, symmetricKey);
        const emailBlob = JSON.stringify(encrypted_email);
        const email_hmac = await generateMAC(emailBlob, hmacKey);

        const payload = {
            username: userData.username,
            hmac_username: await generateMAC(userData.username, hmacKey),
            email: emailBlob,
            hmac_email: email_hmac,
            public_key: publicKeyPem,
            deviceName: navigator.userAgent,
            email_raw: userData.email,
            encrypted_symmetric_key,
            encrypted_hmac_key,
            isTrustedUser,
        };


        if (isTrustedUser) {
            const encrypted_fullname = await encryptData(userData.fullname, symmetricKey);
            payload.fullname = JSON.stringify(encrypted_fullname);
            payload.hmac_fullname = await generateMAC(payload.fullname, hmacKey);
            payload.organization = userData.organization.trim();
            payload.country = userData.country.trim();
            payload.trustedUserCsr = trustedUserCsr;
            payload.orgCsr = await buildOrganizationCSR(
                userData.fullname, payload.organization, payload.country
            );
        }

        await saveUserKeyPackage(userData.username, {
            privateKeyJwk,
            publicKeyPem,
            certificate,
            symmetricKey: symmetricKeyBase64,
            hmacKey: hmacKeyBase64
        });

        return payload;
    } catch (err) {
        console.error(err);
        throw new Error('Registration failed client-side.');
    }
};

export const handleProfile = async (user_data, inMemoryPackage = null, onError = (msg) => {
}) => {
    try {
        let keyPackage = inMemoryPackage;

        if (!keyPackage || !keyPackage.privateKeyJwk) {
            onError("Crypto package not found or private key malformed.");
            throw new Error("Crypto package not found.");
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

export const handleProfileTrusted = async (user_data, orgKey = null) => {
    try {
        const {
            username,
            public_key: pkFromServer,
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
            signature_symmetric_key,
            encrypted_hmac_key,
            signature_hmac_key,
        } = user_data;

        if (!orgKey) {
            throw new Error("Organization key missing for trusted user.");
        }
        const orgPackage = await getOrgKeyPair(orgKey);
        if (!orgPackage || !orgPackage.jwk || !orgPackage.publicPem) {
            throw new Error('Organization key-pair missing in crypto package. Import org package.');
        }
        const privateKeyJwkCopy = {...keyPackage.privateKeyJwk};
        delete privateKeyJwkCopy.alg;
        delete privateKeyJwkCopy.key_ops;

        const pubKey = await importPublicKey(orgPackage.publicPem, 'verify');
        const privKey = await window.crypto.subtle.importKey(
            'jwk',
            privateKeyJwkCopy,
            {name: 'RSA-OAEP', hash: 'SHA-256'},
            true,
            ['decrypt']
        );

        // Signature verification on encrypted keys
        const sigOK_sym = await verifySignatureWithPublicKey(
            encrypted_symmetric_key, signature_symmetric_key, pubKey);
        const sigOK_hmac = await verifySignatureWithPublicKey(
            encrypted_hmac_key, signature_hmac_key, pubKey);
        if (!sigOK_sym || !sigOK_hmac) throw new Error('Wrapped key signature mismatch');

        // Decrypt keys
        const symKey = await importKey(
            base64ToArrayBuffer(
                await decryptWithPrivateKey(encrypted_symmetric_key, privKey)
            ));
        const hmacKey = await importHmacKey(
            base64ToArrayBuffer(
                await decryptWithPrivateKey(encrypted_hmac_key, privKey)
            ));

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
            btoa(String.fromCharCode(...new Uint8Array(await window.crypto.subtle.exportKey("raw", symKey)))),
            btoa(String.fromCharCode(...new Uint8Array(await window.crypto.subtle.exportKey("raw", hmacKey))))
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
