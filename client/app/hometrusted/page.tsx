"use client";

import React, {useEffect, useState} from "react";
import {useRouter} from "next/navigation";
import Navbar98 from "@/components/Navbar98";
import Window98 from "@/components/Window98";
import {pinnedFetch} from "@/cryptography/certificate";

const HomeTrustedPage = () => {
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
