'use client';

import React, {useEffect, useState} from "react";
import { useRouter} from "next/navigation";
import Navbar98 from "@/components/Navbar98";
import Window98 from "@/components/Window98";
import {pinnedFetch} from "@/cryptography/certificate";
import { assertAuthAndContext } from "@/utils/guard-util";

const HomePage = () => {
    const router = useRouter();
    const [isAuthenticated, setIsAuthenticated] = useState(false);

    useEffect(() => {
        (async () => {
            try {
                const result = await assertAuthAndContext(router);
                if (result.ok) {
                    setIsAuthenticated(true);
                    const userData = result.user;
                    router.push(userData.isTrustedUser ? '/home-trust' : '/home');
                }
            } catch (error) {
                console.error('Error verifying authentication:', error);
                setIsAuthenticated(false);
            }
        })();
    }, [router]);

    return (
        <>
            {isAuthenticated && <Navbar98 />}
            <main style={{display: "flex", justifyContent: "center", marginTop: 40}}>
                <Window98 title="Welcome to SEC CAM" width={320}>
                    <p>You must login or register. Change <a href="/passport">password</a> instead?</p>
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
