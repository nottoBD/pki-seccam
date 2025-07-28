"use client";

import React, {useEffect, useState} from "react";
import {useRouter} from "next/navigation";
import Navbar98 from "@/components/Navbar98";
import Window98 from "@/components/Window98";
import {pinnedFetch} from "@/cryptography/certificate";

const HomeTrustPage = () => {
    const [profile, setProfile] = useState<any>(null);
    const [message, setMessage] = useState("");
    const [checkingAuth, setCheckingAuth] = useState(true);
    const router = useRouter();

    useEffect(() => {
        (async () => {
            const token = localStorage.getItem("token");

            if (!token) {
                setCheckingAuth(false);
                return router.replace("/");
            }
            try {
                const res = await pinnedFetch("/api/user/current", {
                    headers: {Authorization: `Bearer ${token}`}
                });
                if (!res.ok) {
                    setCheckingAuth(false);
                    return router.replace("/");
                }
                const user = await res.json();
                if (!user.isTrustedUser) {
                    setCheckingAuth(false);
                    return router.replace("/home");
                }
                setProfile(user);
            } catch (err) {
                setMessage("Failed to load profile. Please log in again.");
                router.replace("/");
            } finally {
                setCheckingAuth(false);
            }
        })();
    }, [router]);

    return (
        <>
            <Navbar98/>
            <main style={{display: "flex", justifyContent: "center", marginTop: 40}}>
                <Window98 title="Organization Home" width={480}>

                </Window98>
            </main>
        </>
    );
};

export default HomeTrustPage;
