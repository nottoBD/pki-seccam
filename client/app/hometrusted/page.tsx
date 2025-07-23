"use client";

import React, {useEffect, useState} from "react";
import {useRouter} from "next/navigation";
import Navbar98 from "@/components/Navbar98";
import Window98 from "@/components/Window98";
import {handleProfileTrusted} from "@/cryptography/handlers";
import {logout} from "@/actions/auth";
import {pinnedFetch} from "@/cryptography/certificate";


const HomeTrustedPage = () => {
    const [name, setName] = useState("");
    const [showProjects, setShowProjects] = useState(false);
    const [fadeClass, setFadeClass] = useState("opacity-0");
    const [cursorPosition, setCursorPosition] = useState({x: 0, y: 0});
    const router = useRouter();

    const [projects, setProjects] = useState([
        {
            title: "See Videos",
            description: "Here is where you can see the dashcam videos",
            link: "/videos",
        },
    ]);

    useEffect(() => {
        (async () => {
            try {
                const token = localStorage.getItem("token");
                if (!token) return router.replace("/");

                const res = await pinnedFetch("/api/user/current", {
                    headers: {Authorization: `Bearer ${token}`},
                });
                if (!res.ok) return router.replace("/home");
                const resData = await res.json();

                if (!resData.isTrustedUser) return router.replace("/home"); // non-trusted

                const profile = await handleProfileTrusted(resData);
                setName(profile.fullname);

                try {
                    const devRes = await pinnedFetch("/api/device/list", {
                        headers: {Authorization: `Bearer ${token}`},
                    });

                    if (devRes.status === 200) {
                        const devData = await devRes.json();
                        const primary = devData.find((d: any) => d.isPrimary);
                        const localId = localStorage.getItem("device_id");
                        if (primary && localId && primary.deviceId === localId) {
                            setProjects(prev =>
                                prev.some(p => p.link === "/multidevice")
                                    ? prev
                                    : [
                                        ...prev,
                                        {
                                            title: "Multi Device Access",
                                            description: "Manage secondary device requests",
                                            link: "/multidevice",
                                        },
                                    ]
                            );
                        }
                    }
                } catch (err) {
                    console.error("Could not fetch device list:", err);
                }

                setTimeout(() => {
                    setShowProjects(true);
                    setFadeClass("opacity-100 transition-opacity duration-1000");
                }, 1500);
            } catch (err: any) {
                if (err?.response?.status === 412) {
                    setTimeout(() => router.refresh(), 5000);
                    return;
                }
                console.error("Auth check failed:", err);
                await logout();
                router.replace("/");
            }
        })();
    }, []);

    return (
        <>
            <Navbar98/>

            <main style={{display: "flex", justifyContent: "center", marginTop: 40}}>
                <Window98 title="Organization Home" width={480}>
                </Window98>
            </main>
        </>
    );
}

export default HomeTrustedPage;
