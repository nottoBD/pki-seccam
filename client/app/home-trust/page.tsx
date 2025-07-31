"use client";

import React, {useEffect, useState} from "react";
import {useRouter} from "next/navigation";
import Navbar98 from "@/components/Navbar98";
import Window98 from "@/components/Window98";
import {assertAuthAndContext, hardLogout} from "@/utils/guard-util";

const HomeTrustPage = () => {
    const [profile, setProfile] = useState<any>(null);
    const [message, setMessage] = useState("");
    const [checkingAuth, setCheckingAuth] = useState(true);
    const router = useRouter();

    useEffect(() => {
        (async () => {
            try {
                const result = await assertAuthAndContext(router, "trusted");
                if (!result.ok) return;
                setProfile(result.user);
            } catch (err) {
                setMessage("Failed to load profile. Please log in again.");
                await hardLogout(router);
            } finally {
                setCheckingAuth(false);
            }
        })();
    }, []);

    return (
        <>
            <Navbar98/>
            <main style={{display: "flex", justifyContent: "center", marginTop: 40}}>
                <Window98 title="Organization Home" width={480}>
                    <h2>SEC CAM</h2>
                </Window98>
            </main>
        </>
    );
};

export default HomeTrustPage;
