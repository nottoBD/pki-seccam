'use client';

import React, {useEffect, useRef, useState} from 'react';
import {useRouter} from 'next/navigation';
import Navbar98 from "@/components/Navbar98";
import Window98 from "@/components/Window98";
import {login} from '@/handlers/auth-hdlr';
import {pinnedFetch} from "@/cryptography/certificate";
import {decryptCryptoPassportLogin} from "@/cryptography/symmetric"
import {handleAnyUserSession} from "@/handlers/crypto-hdlr";


export default function Login() {
    const router = useRouter();
    const [username, setUsername] = useState('');
    const [code, setCode] = useState('');
    const [cryptoFile, setCryptoFile] = useState<File | null>(null);
    const [password, setPassword] = useState('');
    const [message, setMessage] = useState('');
    const [isSubmitting, setIsSubmitting] = useState(false);
    const usernameRef = useRef<HTMLInputElement>(null);

    useEffect(() => {
        if (usernameRef.current) {
            usernameRef.current.focus();
        }
    }, []);

    useEffect(() => {
        (async () => {
            const t = localStorage.getItem('token');
            if (!t) return;
            try {
                const res = await pinnedFetch('/api/user/current', {
                    headers: {Authorization: `Bearer ${t}`}
                });
                if (res.ok) {
                    const userData = await res.json();
                    router.push(userData.isTrustedUser ? '/home-trust' : '/home');
                }
            } catch {
                localStorage.removeItem('token');
            }
        })();
    }, [router]);


    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setMessage('');
        setIsSubmitting(true);

        if (!cryptoFile || !password) {
            setMessage('Please upload your crypto package and enter your password.');
            setIsSubmitting(false);
            return;
        }

        let decryptedPackage;
        try {
            decryptedPackage = await decryptCryptoPassportLogin(cryptoFile, password);

            if (!decryptedPackage.privateKeyJwk && !decryptedPackage.userPrivateKeyJwk) {
                throw new Error('Missing private key in package.');
            }

            const isTrustedUser = !!decryptedPackage.userPrivateKeyJwk && !!decryptedPackage.orgPrivateKeyJwk && !!decryptedPackage.userCertificate && !!decryptedPackage.orgCertificate;

            if (isTrustedUser) {
                const rootPem = await (await pinnedFetch('/api/ca/root')).text();

                const rootLines = rootPem.split('\n').filter(l => !l.startsWith('-----'));
                const rootB64 = rootLines.join('');
                const rootBytes = Uint8Array.from(atob(rootB64), c => c.charCodeAt(0));
                const digest = await crypto.subtle.digest('SHA-256', rootBytes);
                const rootFp = Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('').toLowerCase();
                if (rootFp !== process.env.NEXT_PUBLIC_CA_ROOT_FINGERPRINT) {
                    throw new Error('Root CA certificate fingerprint mismatch. Potential MITM attack.');
                }

                const userVerifyResp = await pinnedFetch('/api/ca/verify', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ cert: decryptedPackage.userCertificate }),
                });
                const userVerifyData = await userVerifyResp.json();
                if (!userVerifyResp.ok || !userVerifyData.valid) {
                    throw new Error('User certificate chain verification failed.');
                }
                console.log('DEBUG: userVerifyData (from backend):', userVerifyData);
                console.log('DEBUG: userVerifyData.cn:', userVerifyData.cn);
                console.log('DEBUG: username field:', username, 'typeof:', typeof username, 'length:', username.length);
                console.log('DEBUG: CN field:', userVerifyData.cn, 'typeof:', typeof userVerifyData.cn, 'length:', (userVerifyData.cn || '').length);
                console.log('DEBUG: compare result:', userVerifyData.cn === username);

                if (userVerifyData.cn !== username) {
                    throw new Error('User certificate CN does not match username.');
                }
                const orgVerifyResp = await pinnedFetch('/api/ca/verify', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ cert: decryptedPackage.orgCertificate }),
                });
                const orgVerifyData = await orgVerifyResp.json();
                if (!orgVerifyResp.ok || !orgVerifyData.valid) {
                    throw new Error('Organization certificate chain verification failed.');
                }
            }
        } catch (err: any) {
            console.error('Package decryption or cert verification failed:', err);
            setMessage("Invalid password or corrupted package: " + err.message);
            setIsSubmitting(false);
            return;
        }

        // login w/ username, TOTP, decrypted package
        const loginResp = await login(username, code);
        if (loginResp.status === 200 && loginResp.token) {
            localStorage.setItem('token', loginResp.token);

            try {
                const res = await pinnedFetch('/api/user/current', {
                    headers: {Authorization: `Bearer ${loginResp.token}`}
                });
                if (!res.ok) throw new Error('Profile retrieval failed after login.');
                const userData = await res.json();

                if (!userData.isTrustedUser) {
                    await handleAnyUserSession(userData, decryptedPackage, (msg) => setMessage(msg));
                }

                router.push(userData.isTrustedUser ? '/home-trust' : '/home');
            } catch (err) {
                setMessage('Post-login error: unable to complete profile setup.');
            }
            setIsSubmitting(false);
            return;
        }

        if (loginResp.status === 400 && loginResp.message?.includes('Invalid OTP')) {
            setMessage('Invalid OTP. Please verify your TOTP and try again.');
        } else if (loginResp.status === 400 && loginResp.message?.includes('Missing')) {
            setMessage('Package validation failed: ' + loginResp.message);
        } else if (loginResp.status === 401 && loginResp.message?.includes('Device not recognized')) {
            setMessage('Device not recognized. Ensure the correct crypto package is imported.');
        } else if (loginResp.status === 403 && loginResp.message?.includes('Email not verified')) {
            setMessage('Email not verified. Please verify your email first.');
        } else {
            setMessage(loginResp.message || 'Login failed. Please try again.');
        }
        setIsSubmitting(false);
    };

    return (
        <>
            <Navbar98/>

            <main style={{display: "flex", justifyContent: "center", marginTop: 50}}>
                <Window98 title="SEC-CAM – Entrance" width={360}>
                    <form onSubmit={handleSubmit}>
                        <div className="field-row-stacked" style={{width: "100%"}}>
                            <label htmlFor="user"><b>Pseudonym</b></label>
                            <input
                                id="user"
                                value={username}
                                ref={usernameRef}
                                onChange={(e) => setUsername(e.target.value.trim())}
                                pattern="[A-Za-z0-9_.]{3,32}"
                                maxLength={32}
                                required
                            />

                        </div>
                        <div className="field-row-stacked">
                            <label htmlFor="cryptoFile"><b>Crypto Passport</b></label>
                            <input
                                id="cryptoFile"
                                type="file"
                                accept=".sec.json,.json"
                                onChange={e => setCryptoFile(e.target.files?.[0] || null)}
                                required
                            />
                        </div>
                        <div className="field-row-stacked">
                            <label htmlFor="password"><b>Package Password</b></label>
                            <input
                                id="password"
                                type="password"
                                value={password}
                                onChange={e => setPassword(e.target.value)}
                                required
                            />
                        </div>
                        <div className="field-row-stacked" style={{width: "100%"}}>
                            <label htmlFor="totp"><b>TOTP Code</b></label>
                            <input
                                id="totp"
                                type="text"
                                inputMode="numeric"
                                pattern="\d{6}"
                                maxLength={6}
                                value={code}
                                onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
                                required
                            />
                        </div>
                        <button
                            className="default"
                            style={{width: "100%", marginTop: 16}}
                            type="submit"
                            disabled={code.length !== 6 || username.length < 3 || isSubmitting}
                        >
                            Log In
                        </button>
                    </form>
                    {message && <p>{message}</p>}
                    <p style={{marginTop: 8}}>
                        <a href="/register">Register</a> instead?
                    </p>
                </Window98>
            </main>
        </>
    );
}
