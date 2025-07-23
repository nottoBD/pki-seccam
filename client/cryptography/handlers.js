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
    importPrivateKey,
    importPublicKey,
    verifySignatureWithPublicKey
} from "@/cryptography/asymmetric";
import {buildDeviceCSR, buildOrganizationCSR} from './certificate';
import {getKey} from "@/keys/indexed-keys";
import {setSessionKeys} from "@/keys/session-keys";

const toB64 = async k =>
    btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.exportKey("raw", k))));

export async function shareKeysWithDevice(deviceId, certPem) {

}


export const handleRegistration = async (userData) => {
    try {
        const {deviceId, csrPem: deviceCsr, publicKeyPem} = await buildDeviceCSR(
            userData.username,
            navigator.userAgent
        );

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
            deviceId,
            public_key: publicKeyPem,
            deviceCsr,
            deviceName: navigator.userAgent,
            email_raw: userData.email,
            encrypted_symmetric_key,
            encrypted_hmac_key,
            isTrustedUser: !!(userData.fullname && userData.organization),
        };
        /* ---- extra fields for trusted users ---- */
        if (payload.isTrustedUser) {
            const encrypted_fullname = await encryptData(userData.fullname, symmetricKey);
            payload.fullname = JSON.stringify(encrypted_fullname);
            payload.hmac_fullname = await generateMAC(payload.fullname, hmacKey);
            payload.organization = userData.organization.trim();
            payload.country = userData.country.trim();
            payload.orgCsr = await buildOrganizationCSR(
                userData.fullname, payload.organization, payload.country
            );
        }
        return {...payload, deviceId};
    } catch (err) {
        console.error(err);
        throw new Error('Registration failed client-side.');
    }
};

export const handleProfile = async (user_data, onError = (msg) => {
}) => {
    try {
        const deviceId = localStorage.getItem("device_id");
        const imported_private_key = await getKey(deviceId);
        if (!imported_private_key) {
            onError("Device private key not found. Register this device.");
            throw new Error("Private key not found.");
        }

        const symmetric_key_base64 = await decryptWithPrivateKey(
            user_data.encrypted_symmetric_key,
            imported_private_key
        );
        const symmetric_key = await importKey(base64ToArrayBuffer(symmetric_key_base64));


        const hmac_key_base64 = await decryptWithPrivateKey(
            user_data.encrypted_hmac_key,
            imported_private_key
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
        onError('Unable to decrypt data. Register this device.');
        throw Error('Unable to decrypt data.');
    }
};

export const handleProfileTrusted = async (user_data) => {
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

        //pubkey locally
        let pub = localStorage.getItem(`${username}_public_key`);
        if (!pub && pkFromServer) {
            pub = pkFromServer;
            localStorage.setItem(`${username}_public_key`, pub);
        }

        const priv = localStorage.getItem(`${username}_private_key`);
        if (!pub || !priv) throw new Error('Missing user key-pair in browser');

        const pubKey = await importPublicKey(pub, 'verify');
        const privKey = await importPrivateKey(priv, 'decrypt');


        const sigOK_sym = await verifySignatureWithPublicKey(
            encrypted_symmetric_key, signature_symmetric_key, pubKey);
        const sigOK_hmac = await verifySignatureWithPublicKey(
            encrypted_hmac_key, signature_hmac_key, pubKey);
        if (!sigOK_sym || !sigOK_hmac) throw new Error('Wrapped key signature mismatch');


        const symKey = await importKey(
            base64ToArrayBuffer(
                await decryptWithPrivateKey(encrypted_symmetric_key, privKey)
            ));
        const hmacKey = await importHmacKey(
            base64ToArrayBuffer(
                await decryptWithPrivateKey(encrypted_hmac_key, privKey)
            ));


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

        setSessionKeys(await toB64(symKey), await toB64(hmacKey));


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
