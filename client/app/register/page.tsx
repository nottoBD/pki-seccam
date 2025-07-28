'use client';

import React, {useEffect, useRef, useState} from 'react';
import {countries} from 'countries-list';
import {register} from '@/handlers/auth-hdlr';
import Navbar98 from "@/components/Navbar98";
import Window98 from "@/components/Window98";
import {useRouter} from "next/navigation";

import {encryptCryptoPassportRegistration} from "@/cryptography/symmetric";

const USERNAME_REGEX = /^[A-Za-z0-9_.]{5,16}$/;  // 5–16 chars, letters/digits/._
const FULLNAME_REGEX = /^[A-Za-zÀ-ÿ' ]{6,24}$/; // 6–24, letters + accents, spaces, '
const ORG_REGEX = /^[A-Za-z0-9&' ]{5,32}$/;      // 5–32, letters/digits/&,spaces'


const Register = () => {
    const router = useRouter();

    const [username, setUsername] = useState('');
    const [email, setEmail] = useState('');
    const [isTrustedUser, setIsTrustedUser] = useState(false);
    const [fullName, setFullName] = useState('');
    const [organization, setOrganization] = useState('');
    const [country, setCountry] = useState('');
    const [emailError, setEmailError] = useState('');
    const [message, setMessage] = useState('');
    const [qrCode, setQrCode] = useState('');
    const [secret, setSecret] = useState('');
    const [userErr, setUserErr] = useState('');
    const [fullErr, setFullErr] = useState('');
    const [orgErr, setOrgErr] = useState('');
    const [countryErr, setCountryErr] = useState('');
    const [isSubmitting, setIsSubmitting] = useState(false);
    const usernameRef = useRef<HTMLInputElement>(null);
    const passwordRef = useRef<HTMLInputElement>(null);

    const [showExportModal, setShowExportModal] = useState(false);
    const [password, setPassword] = useState('');
    const [password2, setPassword2] = useState('');

    const [exportError, setExportError] = useState('');
    const [exportDone, setExportDone] = useState(false);

    const [cryptoPackage, setCryptoPackage] = useState<any>(null);

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const countryList = Object.entries(countries).map(([code, c]) => ({
        code,
        name: c.name,
    }));

    useEffect(() => {
        if (usernameRef.current) {
            usernameRef.current.focus();
        }
    }, []);

    useEffect(() => {
        if (!isTrustedUser) {
            setFullErr('');
            setOrgErr('');
            setCountryErr('');
        } else {
            setCountryErr(country ? '' : 'Country required');
        }
    }, [isTrustedUser, country]);

    const handleExportDownload = async () => {
        setExportError('');
        if (!password || password.length < 8) {
            setExportError("Password must be at least 8 characters.");
            return;
        }
        if (password !== password2) {
            setExportError("Passwords do not match.");
            return;
        }
        try {
            if (!cryptoPackage) throw new Error("No package data found");
            const blob = await encryptCryptoPassportRegistration(cryptoPackage, password);
            const link = document.createElement('a');
            link.href = URL.createObjectURL(blob);
            link.download = `${username}-crypto-package.sec.json`;
            link.click();
            setExportDone(true);
            setShowExportModal(false);
            setPassword('');
            setPassword2('');
        } catch (err: any) {
            setExportError("Failed to export package: " + err.message);
        }
    };

    const handleEmailChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const value = e.target.value;
        setEmail(value);
        setEmailError(emailRegex.test(value) ? '' : 'Email invalid.');
    };

    const handleRegister = async (e: React.FormEvent) => {
        e.preventDefault();
        if (isSubmitting) return;
        setIsSubmitting(true);
        setMessage('');

        if (!username || !email || (isTrustedUser && (!fullName || !organization || !country))) {
            setMessage('All fields required');
            setIsSubmitting(false);
            return;
        }
        if (emailError || userErr || fullErr || orgErr || countryErr) {
            setIsSubmitting(false);
            return;
        }

        const userData: any = {username, email, isTrustedUser};
        if (isTrustedUser) {
            userData.fullname = fullName;
            userData.organization = organization;
            userData.country = country;
        }

        try {
            const resp: any = await register(userData);

            if (resp.status === 200 && resp.data.qrcode_image) {
                setQrCode(resp.data.qrcode_image);

                let packageToExport;
                if (isTrustedUser) {
                    const userPackage = resp.userPackage;
                    const orgPackage = resp.orgPackage;
                    if (resp.data.userCertificate) {
                        userPackage.userCertificate = resp.data.userCertificate;
                    }
                    if (resp.data.organizationCertificate) {
                        orgPackage.orgCertificate = resp.data.organizationCertificate;
                    }
                    packageToExport = {
                        userPrivateKeyJwk: userPackage.privateKeyJwk,
                        userPublicKeyPem: userPackage.publicKeyPem,
                        userCertificate: userPackage.userCertificate,
                        orgPrivateKeyJwk: orgPackage.privateKeyJwk,
                        orgPublicKeyPem: orgPackage.publicKeyPem,
                        orgCertificate: orgPackage.orgCertificate
                    };
                } else {
                    packageToExport = resp.userPackage;
                }

                setCryptoPackage(packageToExport);
                setShowExportModal(true);
                setMessage('Registered with great success! Verify your email to login');
            } else {
                setMessage(resp.data.message || 'Registration failed..');
            }
        } catch (err: any) {
            setMessage(err.message || 'An error occurred!');
        } finally {
            setIsSubmitting(false);
        }
    };

    useEffect(() => {
        if (showExportModal && passwordRef.current) {
            passwordRef.current.focus();
        }
    }, [showExportModal]);


    const exportModal = showExportModal && (
        <div style={{
            position: "fixed", top: 0, left: 0, width: "100vw", height: "100vh",
            background: "rgba(0,0,0,0.4)", zIndex: 1000,
            display: "flex", alignItems: "center", justifyContent: "center"
        }}>
            <Window98 title={`Download ${isTrustedUser ? "Privileged" : "User"} Access`} width={450}>
                <p style={{fontSize: 14, marginTop: 4}}>
                    Set a strong passphrase to ensure your own access. <br/> <b>No data recoverable if forgotten.</b>
                </p>
                <div style={{display: "flex", gap: 16}}>
                    <div style={{flex: 1}}>
                        <div className="field-row-stacked" style={{width: "225px", marginBottom: 16}}>
                            <label htmlFor="password"><b>Password</b></label>
                            <input
                                id="password"
                                type="password"
                                ref={passwordRef}
                                placeholder="Password"
                                value={password}
                                onChange={e => setPassword(e.target.value)}
                                minLength={8}
                                required
                            />
                        </div>
                        <div className="field-row-stacked" style={{width: "225px"}}>
                            <label htmlFor="password2"><b>Repeat Password</b></label>
                            <input
                                id="password2"
                                type="password"
                                placeholder="Repeat Password"
                                value={password2}
                                onChange={e => setPassword2(e.target.value)}
                                minLength={8}
                                required
                            />
                        </div>
                        <button
                            className="default"
                            style={{width: "225px", marginBottom: 1, marginTop: 2}}
                            onClick={handleExportDownload}
                        ><b>Download</b></button>
                        {exportError && <p style={{color: "red"}}>{exportError}</p>}
                    </div>
                    {qrCode && (
                        <div style={{display: "flex", alignItems: "center", justifyContent: "center", marginTop: -20}}>
                            <fieldset>
                                <legend>TOTP</legend>
                                <img src={qrCode} alt="QR Code" style={{maxWidth: 130}}/>
                            </fieldset>
                        </div>
                    )}
                </div>
                <p style={{color: "#555", fontSize: 14, marginTop: 8}}>
                    <b><i>{isTrustedUser ? "Company Premium" : "Seccam User"} Crypto-Passport™</i> at Your {isTrustedUser ? "Orders" : "Service"}!</b>
                </p>
            </Window98>
        </div>
    );

    return (
        <>
            <Navbar98/>
            <main style={{display: "flex", justifyContent: "center", marginTop: 50}}>
                <Window98 title="SEC-CAM – Register" width={360}>
                    <form onSubmit={handleRegister}>
                        <div className="field-row-stacked" style={{width: "100%"}}>
                            <label htmlFor="username"><b>Pseudonym</b></label>
                            <input
                                id="username"
                                value={username}
                                ref={usernameRef}
                                onChange={(e) => {
                                    const v = e.target.value.trim();
                                    setUsername(v);
                                    setUserErr(USERNAME_REGEX.test(v) ? '' : '5‑16 letters, digits, ._');
                                }}
                                pattern="[A-Za-z0-9_.]{5,16}"
                                maxLength={16}
                                required
                            />
                            {userErr && <small>{userErr}</small>}
                        </div>
                        <div className="field-row-stacked" style={{width: "100%"}}>
                            <label htmlFor="email"><b>Email</b></label>
                            <input
                                id="email"
                                type="email"
                                value={email}
                                onChange={handleEmailChange}
                                required
                            />
                            {emailError && <p>{emailError}</p>}
                        </div>
                        <div className="field-row">
                            <input
                                id="isTrustedUser"
                                type="checkbox"
                                checked={isTrustedUser}
                                onChange={(e) => setIsTrustedUser(e.target.checked)}
                            />
                            <label htmlFor="isTrustedUser">Part of a Company?</label>
                        </div>

                        {isTrustedUser && (
                            <>
                                <div className="field-row-stacked" style={{width: "100%"}}>
                                    <label htmlFor="fullName"><b>Full Name</b></label>
                                    <input
                                        id="fullName"
                                        value={fullName}
                                        onChange={(e) => {
                                            const v = e.target.value;
                                            setFullName(v);
                                            setFullErr(FULLNAME_REGEX.test(v) ? '' : '6‑24 letters no digits');
                                        }}
                                        pattern="[A-Za-zÀ-ÿ' ]{6,24}"
                                        maxLength={24}
                                        required
                                    />
                                </div>

                                <div className="field-row-stacked" style={{width: "100%"}}>
                                    <label htmlFor="organization"><b>Company Name</b></label>
                                    <input
                                        id="organization"
                                        value={organization}
                                        onChange={(e) => {
                                            const v = e.target.value.trim();
                                            setOrganization(v);
                                            setOrgErr(ORG_REGEX.test(v) ? '' : '5‑32 valid characters');
                                        }}
                                        pattern="[A-Za-z0-9&' ]{5,32}"
                                        maxLength={32}
                                        required
                                    />
                                </div>

                                <div className="field-row-stacked" style={{width: "100%"}}>
                                    <label htmlFor="country"><b>Country</b></label>
                                    <select
                                        id="country"
                                        value={country}
                                        onChange={(e) => setCountry(e.target.value)}
                                        required
                                    >
                                        <option value="" disabled>
                                            Country
                                        </option>
                                        {countryList.map(({code, name}) => (
                                            <option key={code} value={code}>
                                                {name}
                                            </option>
                                        ))}
                                    </select>
                                </div>
                            </>
                        )}
                        <button
                            className="default"
                            style={{width: "100%", marginTop: 16}}
                            type="submit"
                            disabled={isSubmitting || !!emailError || !!userErr || !!fullErr || !!orgErr}
                        >
                            <b>Register</b>
                        </button>
                    </form>
                    {message && <p>{message}</p>}
                    <p style={{marginTop: 8}}>
                        <a href="/login">Log in</a> instead?
                    </p>
                </Window98>
            </main>
            {exportModal}
        </>
    );
}

export default Register;
