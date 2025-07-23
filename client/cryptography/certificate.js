import forge from 'node-forge';
import {getOrCreateDeviceKeypair} from './asymmetric';


/* cache successful pins */
let lastCheckOK = false;
let lastCheckTs = 0;
const TEN_MIN = 5 * 60 * 1000;

function safe(str) {
    return str
        .replace(/[^A-Za-z0-9 '()+,.\-\/:=?]+/g, '-')   // underscore
        .replace(/ +/g, ' ')                            // collapse blanks
        .trim()                                         // no tail/head space
        .substring(0, 64);                              // length
}

const pinnedFingerprint =
    (typeof process !== 'undefined' && process.env.NEXT_PUBLIC_BACKEND_CERT_FINGERPRINT) ||
    '';


export async function buildDeviceCSR(username, deviceName) {
    const deviceId = crypto.randomUUID();
    const {publicKeyPem: encPubPem, privateKey: encPrivKey} =
        await getOrCreateDeviceKeypair(deviceId);

    /*TODO: unified pki-based multidevice login/register */
    const {publicKey: sigPub, privateKey: sigPriv} = await crypto.subtle.generateKey(
        {
            name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256'
        },
        /* extractable */ false,
        ['sign', 'verify']
    );
    localStorage.setItem('device_id', deviceId);

    const spki = await crypto.subtle.exportKey('spki', sigPub);
    const b64 = btoa(String.fromCharCode(...new Uint8Array(spki)));
    const sigPublicPem =
        '-----BEGIN PUBLIC KEY-----\n' +
        b64.match(/.{1,64}/g).join('\n') +
        '\n-----END PUBLIC KEY-----';
    const csr = forge.pki.createCertificationRequest();
    csr.publicKey = forge.pki.publicKeyFromPem(sigPublicPem);
    csr.setSubject([
        {name: 'commonName', value: username},
        {name: 'organizationalUnitName', value: safe(deviceName)},
    ]);

    const criAsn1 = forge.pki.getCertificationRequestInfo(csr);
    const criDerStr = forge.asn1.toDer(criAsn1).getBytes();
    const criU8 = Uint8Array.from(criDerStr, ch => ch.charCodeAt(0));

    const sigU8 = new Uint8Array(
        await crypto.subtle.sign(
            {name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256'},
            sigPriv,
            criU8
        )
    );

    const sigBin = String.fromCharCode(...sigU8);
    csr.signatureOid = forge.pki.oids.sha256WithRSAEncryption;
    csr.siginfo = csr.siginfo || {};
    csr.siginfo.algorithmOid = forge.pki.oids.sha256WithRSAEncryption;
    csr.signature = sigBin;

    const csrPem = forge.pki.certificationRequestToPem(csr);
    if (typeof window !== 'undefined') {
        localStorage.setItem('device_id', deviceId);
    }

    return {deviceId, csrPem, publicKeyPem: encPubPem};
}


export function buildOrganizationCSR(fullname, organization, country) {
    const {publicKey, privateKey} = forge.pki.rsa.generateKeyPair(2048);

    const csr = forge.pki.createCertificationRequest();
    csr.publicKey = publicKey;
    csr.setSubject([
        {name: 'commonName', value: fullname},
        {name: 'organizationName', value: organization},
        {name: 'countryName', value: country},
    ]);
    csr.sign(privateKey, forge.md.sha256.create());

    /* org’s id key locally */
    localStorage.setItem('org_identity_priv', forge.pki.privateKeyToPem(privateKey));

    return forge.pki.certificationRequestToPem(csr);
}


export async function pinnedFetch(path, options = {}) {
    const ok = await verifyPinnedCertificate(path);
    if (!ok) throw new Error('Certificate mismatch detected! Aborting request.');
    return fetch(path, options);
}

export async function verifyPinnedCertificate(path) {
    if (!pinnedFingerprint) {
        console.error('[Pinning] NEXT_PUBLIC_BACKEND_CERT_FINGERPRINT is empty → fail closed');
        return false;
    }

    // cached result
    if (lastCheckOK && Date.now() - lastCheckTs < TEN_MIN) return true;

    /* strip remote origin so the call is always same‑origin */
    const url = new URL(path, window.location.origin);
    const headResp = await fetch(url.pathname, {method: 'HEAD'});

    const header = headResp.headers.get('X-Server-Cert');
    if (!header) {
        console.error('[Pinning] X-Server-Cert header missing', headResp.headers);
        return false;
    }

    const pem =
        header.startsWith('-----BEGIN CERTIFICATE-----') ? header : atob(header);

    const cert = forge.pki.certificateFromPem(pem);
    const spki = forge.pki.publicKeyToSubjectPublicKeyInfo(cert.publicKey);
    const der = forge.asn1.toDer(spki).getBytes();
    const sha256 = forge.md.sha256.create();
    sha256.update(der);
    const remoteFp = forge.util.encode64(sha256.digest().getBytes());

    const match = remoteFp === pinnedFingerprint;
    lastCheckOK = match;
    lastCheckTs = Date.now();
    return match;
}
