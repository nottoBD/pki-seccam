'use client';

import React, {useEffect, useRef, useState} from 'react';
import {useRouter} from 'next/navigation';
import Navbar98 from "@/components/Navbar98";
import Window98 from "@/components/Window98";
import {login} from '@/actions/auth';
import {handleProfile} from "@/cryptography/handlers";
import {pinnedFetch} from "@/cryptography/certificate";
import {decryptWithPrivateKey} from "@/cryptography/asymmetric";


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
                if (res.ok) router.push('/home');
            } catch {
                localStorage.removeItem('token');
            }
        })();
    }, [router]);

    async function decryptPackageFile(file: File, password: string): Promise<any> {
        const content = JSON.parse(await file.text());
        const {salt, iv, ciphertext} = content;

        if (!salt || !iv || !ciphertext) throw new Error("Malformed encrypted package.");

        const decoder = new TextDecoder();
        const keyMaterial = await crypto.subtle.importKey(
            "raw",
            new TextEncoder().encode(password),
            "PBKDF2",
            false,
            ["deriveKey"]
        );

        const key = await crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: new Uint8Array(salt),
                iterations: 250000,
                hash: "SHA-256"
            },
            keyMaterial,
            {name: "AES-GCM", length: 256},
            false,
            ["decrypt"]
        );

        const decrypted = await crypto.subtle.decrypt(
            {name: "AES-GCM", iv: new Uint8Array(iv)},
            key,
            new Uint8Array(ciphertext)
        );

        return JSON.parse(decoder.decode(decrypted));
    }


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
            decryptedPackage = await decryptPackageFile(cryptoFile, password);
            if (!decryptedPackage.privateKeyJwk) {
                throw new Error('Missing private key in package.');
            }
        } catch (err: any) {
            setMessage("Invalid password or corrupted package: " + err.message);
            setIsSubmitting(false);
            return;
        }

        // login w/ username, TOTP, decrypted package
        const loginResp = await login(username, code, decryptedPackage);
        if (loginResp.status === 200 && loginResp.token) {
            localStorage.setItem('token', loginResp.token);

            try {
                const currentRes = await pinnedFetch('/api/user/current', {
                    headers: {Authorization: `Bearer ${loginResp.token}`}
                });
                if (!currentRes.ok) throw new Error('Profile retrieval failed after login.');
                const userData = await currentRes.json();

                await handleProfile(userData, decryptedPackage, (msg) => setMessage(msg));

                // symmK set if not normal user
                if (!userData.isTrustedUser) {
                    const symKeyResponse = await pinnedFetch("/api/user/getSymmetric", {
                        headers: {Authorization: `Bearer ${loginResp.token}`},
                    });
                    const symKeyData = await symKeyResponse.json();
                    const encryptedSymmetricKey = symKeyData.encryptedSymmetricKey;

                    // Import private key from JWK
                    const importedPrivateKey = await crypto.subtle.importKey(
                        "jwk",
                        decryptedPackage.privateKeyJwk,
                        {
                            name: "RSA-OAEP",
                            hash: "SHA-256",
                        },
                        false,
                        ["decrypt"]
                    );

                    //  decrypt & store ba64 symmetric key in session
                    const symmetricKeyBase64 = await decryptWithPrivateKey(encryptedSymmetricKey, importedPrivateKey);
                    sessionStorage.setItem('symmK', symmetricKeyBase64);
                }

                router.push('/home');
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
                            <label htmlFor="user">Pseudonym</label>
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

                        <div className="field-row-stacked" style={{width: "100%"}}>
                            <label htmlFor="totp">TOTP Code</label>
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
                        <div className="field-row-stacked">
                            <label htmlFor="cryptoFile">Crypto Package (.sec.json)</label>
                            <input
                                id="cryptoFile"
                                type="file"
                                accept=".sec.json,.json"
                                onChange={e => setCryptoFile(e.target.files?.[0] || null)}
                                required
                            />
                        </div>
                        <div className="field-row-stacked">
                            <label htmlFor="password">Package Password</label>
                            <input
                                id="password"
                                type="password"
                                value={password}
                                onChange={e => setPassword(e.target.value)}
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
                        Register instead? <a href="/register">Sign up</a>
                    </p>
                </Window98>
            </main>
        </>
    );
}
