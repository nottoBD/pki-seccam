"use client";

import Link from "next/link";
import {useEffect, useState} from "react";
import {useRouter} from "next/navigation";
import {pinnedFetch} from "@/cryptography/certificate";


export default function Navbar98() {
    const [links, setLinks] = useState<{ href: string; label: string }[]>([]);
    const [name, setName] = useState<string>("user");
    const router = useRouter();

    const handleLogout = () => {
        localStorage.removeItem("token");
        router.replace("/");
    };

    useEffect(() => {
        const token = localStorage.getItem("token");
        if (!token) return; // unauth pages

        (async () => {
            try {
                const res = await pinnedFetch(
                    "/api/user/current",
                    {headers: {Authorization: `Bearer ${token}`}}
                );

                if (res.status === 401 || res.status === 403) {
                    localStorage.removeItem("token");
                    router.replace("/");
                    return;
                }
                if (!res.ok) throw new Error(`HTTP ${res.status}`);

                const user = await res.json();
                setName(user.displayName ?? user.username ?? "user");

                const nav: { href: string; label: string }[] = [
                    {href: "/home", label: "Home"},
                    {href: "/videos", label: "Videos"},
                ];
                if (user.role !== "trusteduser") nav.push({href: "/users", label: "Users"});

                /** primary‑device check */
                try {
                    const devRes = await pinnedFetch(
                        "/api/device/list",
                        {headers: {Authorization: `Bearer ${token}`}}
                    );
                    if (devRes.ok) {
                        const devs = await devRes.json();
                        const localId = localStorage.getItem("device_id");
                        const primary = devs.find((d: any) => d.isPrimary);
                        if (primary && primary.deviceId === localId) {
                            nav.push({href: "/multidevice", label: "Multidevice"});
                        }
                    }
                } catch {/* not fatal */
                }

                setLinks(nav);
            } catch {
                console.error("Navbar bootstrap failed:", err);
            }
        })();
    }, [router]);

    if (links.length === 0) return null; // unauth ⇒ no navbar

    return (
        <nav
            role="toolbar"
            style={{
                display: "flex",
                alignItems: "center",
                padding: 2,
                background: "#C0C0C0",
                borderBottom: "2px solid #FFF",
                gap: 4,
            }}
        >
            {links.map((l) => (
                <Link key={l.href} href={l.href}>
                    <button>{l.label}</button>
                </Link>
            ))}

            <div style={{marginLeft: "auto"}} className="field-row">
                <p style={{margin: 0}}>Hello, {name}!</p>
                <button onClick={handleLogout}>Logout</button>
            </div>
        </nav>
    );
}
