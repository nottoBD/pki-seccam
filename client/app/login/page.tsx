'use client';

import React, {useEffect, useState} from 'react';
import {useRouter} from 'next/navigation';
import Navbar98 from "@/components/Navbar98";
import Window98 from "@/components/Window98";
import {login} from '@/actions/auth';
import {io} from 'socket.io-client';
import {handleProfile} from "@/cryptography/handlers";
import {pinnedFetch} from "@/cryptography/certificate";

export default function Login() {
    const [username, setUsername] = useState('');
    const [code, setCode] = useState('');
    const [message, setMessage] = useState('');
    const router = useRouter();

    useEffect(() => {
        (async () => {
            const t = localStorage.getItem('token');
            if (!t) return;
            try {
                const res = await pinnedFetch('/api/user/current', {
                    headers: {Authorization: `Bearer ${t}`}
                });
                if (res.ok) router.push('/home');
                // else localStorage.removeItem('token');
            } catch {
                localStorage.removeItem('token');
            }
        })();
    }, []);

    useEffect(() => {
        const deviceId = localStorage.getItem("device_id");
        if (!deviceId) return;

        const socket = io("", {
            transports: ["websocket"],
            secure: true,
            reconnection: true,
            reconnectionAttempts: 3,
            reconnectionDelay: 1000,
            reconnectionDelayMax: 5000,
            randomizationFactor: 0.5,
            rejectUnauthorized: true,
            timeout: 15000,
            extraHeaders: {"Host": "localhost"}
        });

        socket.on("connect_error", (err) => {
            console.error("Socket connection error:", err);
        });

        socket.on("error", (err) => {
            console.error("Socket error:", err);
        });

        // room w/ device_id
        socket.emit("identify", deviceId);

        socket.on("device-approved", async ({certificate, token}) => {
            try {
                localStorage.setItem("token", token);
                const deviceId = localStorage.getItem("device_id");
                if (certificate) localStorage.setItem(`${deviceId}_certificate`, certificate);

                const res = await pinnedFetch("/api/user/current", {
                    headers: {Authorization: `Bearer ${token}`}
                });

                if (!res.ok) throw new Error("Failed to fetch profile");
                const user = await res.json();

                await handleProfile(user, (errMsg) => setMessage(errMsg));
                router.push("/home");
            } catch (err) {
                console.error("Device approval handling failed:", err);
                setMessage("Device approval handling failed. Please try again.");
            }
        });

        return () => {
            socket.off("device-approved");
            socket.disconnect();
        };
    }, [router]);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        const {status, message: msg, token} = await login(username, code);

        if (status === 200 && token) {
            localStorage.setItem("token", token);
            router.push('/home');
        } else if (status === 202) {
            setMessage('Device approval pending...');
        } else {
            setMessage(msg);
        }
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

                        <button
                            className="default"
                            style={{width: "100%", marginTop: 16}}
                            type="submit"
                            disabled={code.length !== 6 || username.length < 3}
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
