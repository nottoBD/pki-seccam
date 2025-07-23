'use client';

import React, {useState} from 'react';
import {countries} from 'countries-list';
import {register} from '@/actions/auth';
import Navbar98 from "@/components/Navbar98";
import Window98 from "@/components/Window98";
import {useRouter} from "next/navigation";
import {decryptWithPrivateKey} from "@/cryptography/asymmetric";
import {getKey} from "@/keys/indexed-keys";

const USERNAME_REGEX = /^[A-Za-z0-9_.]{5,16}$/;  // 5–16 chars, letters/digits/._
const FULLNAME_REGEX = /^[A-Za-zÀ-ÿ' ]{10,64}$/; // 10–64, letters + accents, spaces, '
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
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const countryList = Object.entries(countries).map(([code, c]) => ({
        code,
        name: c.name,
    }));

    const handleEmailChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const value = e.target.value;
        setEmail(value);
        setEmailError(emailRegex.test(value) ? '' : 'Email invalid.');
    };

    const handleRegister = async (e: React.FormEvent) => {
        e.preventDefault();

        if (
            !username ||
            !email ||
            (isTrustedUser && (!fullName || !organization || !country))
        ) {
            setMessage('All fields are required.');
            return;
        }
        if (emailError || userErr || fullErr || orgErr) return;

        const payload: any = {
            username,
            email,
        };
        if (isTrustedUser) {
            Object.assign(payload, {
                fullname: fullName,
                organization,
                country,
            });
        }

        try {
            const resp: any = await register(payload);

            const {status, data, deviceId} = resp;
            if (status !== 200) {
                setMessage('Registration failed');
                return;
            }

            if (data.qrcode_image) {
                setQrCode(data.qrcode_image);
                if (data.encrypted_secret) {
                    const privKey = await getKey(deviceId);
                    if (privKey) {
                        try {
                            const decrypted = await decryptWithPrivateKey(data.encrypted_secret, privKey);
                            setSecret(decrypted);
                        } catch (e) {

                        }
                    }
                }
            }
            setMessage(data.message || 'Registration successful!');
        } catch (err: any) {
            setMessage(err.message || 'An error occurred. Please try again.');
        }
    };


    return (
        <>
            <Navbar98/>
            <main style={{display: "flex", justifyContent: "center", marginTop: 50}}>
                <Window98 title="SEC-CAM – Register" width={360}>
                    <form onSubmit={handleRegister}>
                        <div className="field-row-stacked" style={{width: "100%"}}>
                            <label htmlFor="username">Pseudonym</label>
                            <input
                                id="username"
                                value={username}
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
                            <label htmlFor="email">Email</label>
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
                            <label htmlFor="isTrustedUser">Representing a Company?</label>
                        </div>

                        {isTrustedUser && (
                            <>
                                <div className="field-row-stacked" style={{width: "100%"}}>
                                    <label htmlFor="fullName">Full Label</label>
                                    <input
                                        id="fullName"
                                        value={fullName}
                                        onChange={(e) => {
                                            const v = e.target.value;
                                            setFullName(v);
                                            setFullErr(FULLNAME_REGEX.test(v) ? '' : '10‑64 letters no digits');
                                        }}
                                        pattern="[A-Za-zÀ-ÿ' ]{10,64}"
                                        maxLength={64}
                                        required
                                    />
                                </div>

                                <div className="field-row-stacked" style={{width: "100%"}}>
                                    <label htmlFor="organization">Company Name</label>
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
                                    <label htmlFor="country">Country</label>
                                    <select
                                        id="country"
                                        value={country}
                                        onChange={(e) => setCountry(e.target.value)}
                                        required
                                    >
                                        <option value="" disabled>
                                            Select your country
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
                            disabled={!!emailError || !!userErr || !!fullErr || !!orgErr}
                        >
                            Register
                        </button>

                        {qrCode && (
                            <fieldset style={{marginTop: 16}}>
                                <legend>TOTP</legend>
                                <img src={qrCode} alt="QR Code"/>
                                {secret && <p>Alternative Password: {secret}</p>}
                            </fieldset>
                        )}
                    </form>
                    {message && <p>{message}</p>}
                    <p style={{marginTop: 8}}>
                        Login instead? <a href="/login">Log in</a>
                    </p>
                </Window98>
            </main>
        </>
    );
}

export default Register;
