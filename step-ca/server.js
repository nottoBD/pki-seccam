const express = require('express');
const fs = require('fs');
const {execFile, execSync, exec} = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);
const tmp = require('tmp');
const crypto = require('crypto');
const app = express();
const port = process.env.PORT || 3001;

const STEP_CA_URL = process.env.STEP_CA_URL || 'https://step-ca:9000';
const STEP_ROOT = process.env.STEP_ROOT || '/home/step/certs/root_ca.crt';
const STEP_PROVISIONER = process.env.STEP_PROVISIONER || 'seccam-provisioner';
const STEP_PASSWORD_FILE = process.env.STEP_PASSWORD_FILE || '/home/step/secrets/password';


app.use(express.json({limit: '2mb'}));

app.get('/health', (_, res) => res.json({status: 'ok'}));

app.post('/sign', async (req, res) => {
    try {
        const {csr, notAfter, notBefore} = req.body;

        if (typeof csr !== 'string' || !csr.includes('BEGIN CERTIFICATE REQUEST')) {
            return res.status(400).json({error: '`csr` field with PEM CSR is required.'});
        }

        console.log(`Received CSR request with notAfter: ${notAfter}, notBefore: ${notBefore}`);
        console.log(`CSR length: ${csr.length} chars`);
        console.log(`CSR starts with: ${csr.substring(0, 50).replace(/\n/g, '\\n')}`);
        console.log(`CSR ends with: ${csr.substring(Math.max(0, csr.length - 50)).replace(/\n/g, '\\n')}`);
        console.log(`CSR SHA-256: ${crypto.createHash('sha256').update(csr).digest('hex')}`);

        const csrFile = tmp.fileSync({postfix: '.csr'});
        fs.writeFileSync(csrFile.name, csr);

        const writtenCSR = fs.readFileSync(csrFile.name, 'utf8');
        console.log(`Temp file verification – Length: ${writtenCSR.length}, Match: ${writtenCSR === csr ? '✅' : '❌'}`);


        try {
            const inspect = execSync(
                `step certificate inspect --insecure ${csrFile.name}`,
                {encoding: 'utf-8', timeout: 5000}
            );
            console.log(`CSR Subject: ${inspect.match(/Subject:.+/)?.[0] || 'Not found'}`);
        } catch (err) {
            console.error('CSR inspection failed:', err.message);
        }

        const crtFile = tmp.tmpNameSync({postfix: '.crt'});

        /* Build CLI args
         *   step ca sign <csr> <crt> --password-file ... --provisioner ...
         */
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

        const {stderr} = await execStep(args);
        if (stderr) console.error(stderr.trim());

        const certificate = fs.readFileSync(crtFile, 'utf8');

        res.json({certificate});

        csrFile.removeCallback();
        fs.unlinkSync(crtFile);

    } catch (err) {
        console.error(err);
        res.status(500).json({error: 'Certificate signing failed', detail: err.message});
    }
});


app.post('/verify', async (req, res) => {
    try {
        let { cert } = req.body;

        if (typeof cert !== 'string' || !cert.includes('BEGIN CERTIFICATE')) {
            return res.status(400).json({ error: '`cert` field with PEM certificate is required.' });
        }

        cert = cert.split('-----END CERTIFICATE-----')[0] + '-----END CERTIFICATE-----\n';

        const certFile = tmp.fileSync({ postfix: '.pem' });
        fs.writeFileSync(certFile.name, cert);

        const rootCaPath = '/home/step/certs/root_ca.crt';
        const intermediateCaPath = '/home/step/certs/intermediate_ca.crt';

        const command = `openssl verify -CAfile ${rootCaPath} -untrusted ${intermediateCaPath} ${certFile.name}`; //untrusted needed to verify a leaf issued by an intermediate.
        const { stdout, stderr } = await execPromise(command);

        if (!stdout.includes('OK')) {
            throw new Error(`Certificate verification failed: ${stderr || 'No stderr output'}`);
        }

        // CN
        const inspectCommand = `openssl x509 -in ${certFile.name} -noout -subject -nameopt RFC2253`;
        const { stdout: inspectStdout } = await execPromise(inspectCommand);
        const cnMatch = inspectStdout.match(/CN=([^,]+)/);
        const cn = cnMatch ? cnMatch[1].trim() : null;

        res.json({ valid: true, cn });

        certFile.removeCallback();
    } catch (err) {
        console.error('VERIFY endpoint failed:', err);
        res.status(500).json({ error: 'Certificate verification failed', detail: err.message });
    }
});

function execStep(args) {
    return new Promise((resolve, reject) => {
        execFile('step', args, {encoding: 'utf8'}, (err, stdout, stderr) => {
            if (err) {
                return reject(new Error(`Command failed: ${err.message}. Stderr: ${stderr || 'none'}. Stdout: ${stdout || 'none'}`));
            }
            resolve({stdout, stderr});
        });
    });
}

app.listen(port, () => {
    console.log(`▶︎ Cert-signer listening on :${port}. In communication with ${STEP_CA_URL}`);
});
