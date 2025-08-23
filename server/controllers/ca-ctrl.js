// Copyright (C) 2025 David Botton <david.botton@ulb.be>
// This file is part of PKI Seccam <https://github.com/nottoBD/pki-seccam>.
// Licensed under the WTFPL Version 2. See LICENSE file for details.

/*
   certificate authority controller – handles signing and verifying certs using step-ca and OpenSSL under the hood
   signCertificate takes a CSR and uses the smallstep CLI (`step ca sign`) to issue a cert from our CA (auth via env provisioner password)
   it writes the CSR to a temp file, calls the step CLI, reads back the signed cert, then cleans up – no manual crypto here, we let step-ca do the heavy lifting
   verifyCertificate uses OpenSSL to check a given PEM cert against our root + intermediate CA chain, ensuring it's valid
   also extracts the cert's CN via OpenSSL and returns it (so we know which user/device the cert belongs to)
*/

const fs = require('fs');
const { execFile, execSync, exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);
const tmp = require('tmp');

const STEP_CA_URL = process.env.STEP_CA_URL || 'https://step-ca:9000';
const STEP_ROOT = process.env.NODE_EXTRA_CA_CERTS || '/ca/certs/root_ca.crt';
const STEP_INTERMEDIATE = process.env.STEP_INTERMEDIATE || '/ca/certs/intermediate_ca.crt';
const STEP_PROVISIONER = process.env.STEP_PROVISIONER || 'seccam-provisioner';
const STEP_PASSWORD_FILE = process.env.STEP_PASSWORD_FILE || '/home/step/secrets/password';

async function signCertificate(body) {
    const { csr, notAfter, notBefore } = body;

    if (typeof csr !== 'string' || !csr.includes('BEGIN CERTIFICATE REQUEST')) {
        throw new Error('`csr` field with PEM CSR is required.');
    }

    const csrFile = tmp.fileSync({ postfix: '.csr' });
    fs.writeFileSync(csrFile.name, csr);

    try {
        const inspect = execSync(
            `step certificate inspect --insecure ${csrFile.name}`,
            { encoding: 'utf-8', timeout: 5000 }
        );
        console.log(`CSR Subject: ${inspect.match(/Subject:.+/)?.[0] || 'Not found'}`);
    } catch (err) {
        console.error('CSR inspection failed:', err.message);
    }

    const crtFile = tmp.tmpNameSync({ postfix: '.crt' });

    const args = [
        'ca', 'sign',
        csrFile.name,
        crtFile,
        '--password-file', STEP_PASSWORD_FILE,
        '--ca-url', STEP_CA_URL,
        '--root', STEP_ROOT,
        '--provisioner', STEP_PROVISIONER,
    ];

    if (notAfter) args.push('--not-after', String(notAfter));
    if (notBefore) args.push('--not-before', String(notBefore));

    const { stderr } = await execStep(args);
    if (stderr) console.error(stderr.trim());

    const certificate = fs.readFileSync(crtFile, 'utf8');

    csrFile.removeCallback();
    fs.unlinkSync(crtFile);

    return { certificate };
}

async function verifyCertificate(body) {
    let { cert } = body;

    if (typeof cert !== 'string' || !cert.includes('BEGIN CERTIFICATE')) {
        throw new Error('`cert` field with PEM certificate is required.');
    }

    cert = cert.split('-----END CERTIFICATE-----')[0] + '-----END CERTIFICATE-----\n';

    const certFile = tmp.fileSync({ postfix: '.pem' });
    fs.writeFileSync(certFile.name, cert);

    const rootCaPath = STEP_ROOT;
    const intermediateCaPath = STEP_INTERMEDIATE;

    const command = `openssl verify -CAfile ${rootCaPath} -untrusted ${intermediateCaPath} ${certFile.name}`;
    const { stdout, stderr } = await execPromise(command);

    if (!stdout.includes('OK')) {
        throw new Error(`Certificate verification failed: ${stderr || 'No stderr output'}`);
    }

    const inspectCommand = `openssl x509 -in ${certFile.name} -noout -subject -nameopt RFC2253`;
    const { stdout: inspectStdout } = await execPromise(inspectCommand);
    const cnMatch = inspectStdout.match(/CN=([^,]+)/);
    const cn = cnMatch ? cnMatch[1].trim() : null;

    certFile.removeCallback();

    return { valid: true, cn };
}

function execStep(args) {
    return new Promise((resolve, reject) => {
        execFile('step', args, { encoding: 'utf8' }, (err, stdout, stderr) => {
            if (err) {
                return reject(new Error(`Command failed: ${err.message}. Stderr: ${stderr || 'none'}. Stdout: ${stdout || 'none'}`));
            }
            resolve({ stdout, stderr });
        });
    });
}

module.exports = { signCertificate, verifyCertificate };
