'use client';

import React, {useEffect} from "react";
import {useRouter} from "next/navigation";
import Navbar98 from "@/components/Navbar98";
import Window98 from "@/components/Window98";
import {logout} from "@/handlers/auth-hdlr";
import {pinnedFetch} from "@/cryptography/certificate";


const parseJWT = (t: string) => {
    try {
        const b64 = t.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
        return JSON.parse(atob(b64));
    } catch {
        return null;
    }
};

const HomePage = () => {
    const router = useRouter();

    useEffect(() => {
        (async () => {
            try {
                const token = localStorage.getItem('token');
                if (!token) return;

                const p = parseJWT(token);
                if (!p || (p.exp && p.exp * 1000 < Date.now())) {
                    await logout();
                    router.push('/');
                    return;
                }

                const response = await pinnedFetch('/api/user/current', {
                    headers: {Authorization: `Bearer ${token}`},
                });

                if (response.ok) {
                    router.push('/home');
                } else {
                    await logout();
                    router.push('/');
                }
            } catch (error) {
                console.error('Error verifying authentication:', error);
                await logout();
                router.push('/');
            }
        })();
    }, []);


    return (
        <>
            <Navbar98/>
            <main style={{display: "flex", justifyContent: "center", marginTop: 40}}>
                <Window98 title="Welcome to SEC CAM" width={320}>
                    <p>You must login or register.</p>
                    <div style={{display: "flex", gap: 8, justifyContent: "center"}}>
                        <button onClick={() => router.push("/login")}>Login</button>
                        <button onClick={() => router.push("/register")}>Register</button>
                    </div>
                </Window98>
            </main>
        </>
    );
}

export default HomePage;