// Copyright (C) 2025 David Botton <david.botton@ulb.be>
// This file is part of PKI Seccam <https://github.com/nottoBD/pki-seccam>.
// Licensed under the WTFPL Version 2. See LICENSE file for details.
import * as forge from 'node-forge';
import {getOrCreateUserKeypair, importPublicKey} from './asymmetric';


/* cache successful pins */
let lastCheckOK = false;
let lastCheckTs = 0;
const TEN_MIN = 5 * 60 * 1000;


function firstCertificatePem(pem) {
    const match = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/);
    if (!match) throw new Error('No X.509 certificate block found.');
    return match[0];
}

 export function publicKeyPemFromCertificate(pemChain) {
     const leafPem = firstCertificatePem(pemChain);
    const cert = forge.pki.certificateFromPem(leafPem);
     if (!('n' in cert.publicKey)) {
            throw new Error('Trusted user certificate does not contain an RSA public key (RSA‑OAEP required).');
         }
   return forge.pki.publicKeyToPem(cert.publicKey);
 }


export async function importPublicKeyFromCertificate(certPem, useFor = 'encrypt') {
    const pubKeyPem = publicKeyPemFromCertificate(certPem);
    return importPublicKey(pubKeyPem, useFor);
}

const pinnedFingerprint =
    (typeof process !== 'undefined' && process.env.NEXT_PUBLIC_BACKEND_CERT_FINGERPRINT) ||
    '';

export async function buildUserCSR(username) {
    const {publicKeyPem, privateKey, privateJwk} = await getOrCreateUserKeypair(username);

    const csr = forge.pki.createCertificationRequest();
    csr.publicKey = forge.pki.publicKeyFromPem(publicKeyPem);
    csr.setSubject([
        {name: 'commonName', value: username},
    ]);

    const criAsn1 = forge.pki.getCertificationRequestInfo(csr);
    const criDerStr = forge.asn1.toDer(criAsn1).getBytes();
    const criU8 = Uint8Array.from(criDerStr, ch => ch.charCodeAt(0));

    const sigU8 = new Uint8Array(
        await crypto.subtle.sign(
            'RSASSA-PKCS1-v1_5',
            privateKey,
            criU8
        )
    );

    csr.signatureOid = forge.pki.oids.sha256WithRSAEncryption;
    csr.signature = String.fromCharCode(...sigU8);

    const csrPem = forge.pki.certificationRequestToPem(csr);

    return {csrPem, publicKeyPem, privateJwk};
}

export async function buildOrganizationCSR(fullname, organization, country) {
    const orgKey = `${organization.trim()}_${country.trim()}`; //key uniq for org+country

    const {publicKeyPem, privateKey, privateJwk} = await getOrCreateUserKeypair(orgKey);

    const csr = forge.pki.createCertificationRequest();
    csr.publicKey = forge.pki.publicKeyFromPem(publicKeyPem);
    csr.setSubject([
        {name: 'commonName', value: fullname},
        {name: 'organizationName', value: organization},
        {name: 'countryName', value: country}
    ]);

    const criAsn1 = forge.pki.getCertificationRequestInfo(csr);
    const criDerStr = forge.asn1.toDer(criAsn1).getBytes();
    const criU8 = Uint8Array.from(criDerStr, ch => ch.charCodeAt(0));

    const sigU8 = new Uint8Array(
        await crypto.subtle.sign(
            'RSASSA-PKCS1-v1_5',
            privateKey,
            criU8  //raw TBSCSR
        )
    );

    csr.signatureOid = forge.pki.oids.sha256WithRSAEncryption;
    csr.signature = String.fromCharCode(...sigU8);

    const csrPem = forge.pki.certificationRequestToPem(csr);

    return {csrPem, publicKeyPem, privateJwk};
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

    if (lastCheckOK && Date.now() - lastCheckTs < TEN_MIN) return true;

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
