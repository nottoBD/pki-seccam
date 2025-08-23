// Copyright (C) 2025 David Botton <david.botton@ulb.be>
// This file is part of PKI Seccam <https://github.com/nottoBD/pki-seccam>.
// Licensed under the WTFPL Version 2. See LICENSE file for details.

// Client-side X.509 certificate handling and pinning logic. We leverage Forge libraries to parse certificates and create Certificate Signing Requests (CSRs), and we implement certificate pinning for the backend’s TLS cert. This means before making sensitive API calls, we verify the server’s SSL certificate fingerprint matches the expected value from our environment – aborting the request if there’s a mismatch (to prevent man-in-the-middle attacks).

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

// Helper to extract the public key from an X.509 certificate chain. We parse the first certificate (leaf) in the provided PEM chain and return its public key as a PEM string. This ensures that when we receive a trusted user’s certificate, we can pull out their RSA public key easily (for example, to verify signatures or encrypt data for them).

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

// Generates a new RSA key pair and constructs a CSR for a user. We use Forge to create a certification request with the username as the Common Name. The CSR’s data (SubjectPublicKeyInfo) is then signed using the generated private key via the Web Crypto API (RSASSA-PKCS1-v1_5 with SHA-256). The resulting CSR PEM, along with the user’s public key and private key JWK, will be sent to the server’s CA for signing. Essentially, this prepares the cryptographic identity for a trusted user during registration without exposing their private key.

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

// Custom fetch wrapper that enforces TLS certificate pinning. Before performing the actual fetch, we call verifyPinnedCertificate for the target path. That function makes a HEAD request to retrieve the server’s certificate (via a custom X-Server-Cert header), computes its SHA-256 fingerprint, and compares it against our known good fingerprint (NEXT_PUBLIC_BACKEND_CERT_FINGERPRINT). If the fingerprints don’t match, we throw an error to block the request – this means the server’s certificate isn’t the one we expect (could indicate a MITM or misconfiguration). Only if the check passes do we proceed with the real fetch call. We also cache a successful check for a short period to avoid repeating the heavy operation on every request.

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
