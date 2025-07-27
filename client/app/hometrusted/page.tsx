"use client";

import React, {useEffect, useState} from "react";
import {useRouter} from "next/navigation";
import Navbar98 from "@/components/Navbar98";
import Window98 from "@/components/Window98";
import {handleProfileTrusted} from "@/cryptography/handlers";
import {pinnedFetch} from "@/cryptography/certificate";

const HomeTrustedPage = () => {
    const [profile, setProfile] = useState<any>(null);
    const [message, setMessage] = useState("");
    const router = useRouter();

    useEffect(() => {
        (async () => {
            try {
                const token = localStorage.getItem("token");
                if (!token) return router.replace("/");

                const res = await pinnedFetch("/api/user/current", {
                    headers: {Authorization: `Bearer ${token}`},
                });
                if (!res.ok) return router.replace("/");

                const resData = await res.json();
                if (!resData.isTrustedUser) return router.replace("/home");

                const p = await handleProfileTrusted(resData);
                setProfile(p);
                setMessage("");
            } catch (err: any) {
                setMessage("Authentication or decryption failed. Please re-import your org crypto package or login again.");
                setTimeout(() => router.replace("/"), 2500);
            }
        })();
    }, [router]);

    return (
        <>
            <Navbar98/>
            <main style={{display: "flex", justifyContent: "center", marginTop: 40}}>
                <Window98 title="Organization Home" width={480}>
                    {profile ? (
                        <>
                            <h2>Welcome, {profile.fullname}!</h2>
                            <p>
                                <b>Organization:</b> {profile.organization || "—"}
                                <br/>
                                <b>Country:</b> {profile.country || "—"}
                            </p>
                            <div style={{marginTop: 16}}>
                                <a href="/videos" style={{fontWeight: "bold"}}>See Videos</a>
                                <div style={{fontSize: 13, color: "#555"}}>
                                    Here is where you can see the dashcam videos
                                </div>
                            </div>
                        </>
                    ) : (
                        <div>
                            <p>Loading profile...</p>
                            {message && <div style={{color: "red"}}>{message}</div>}
                        </div>
                    )}
                </Window98>
            </main>
        </>
    );
};

export default HomeTrustedPage;
