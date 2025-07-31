"use client";

import Link from "next/link";
import {useEffect, useState} from "react";
import {useRouter, usePathname} from "next/navigation";
import {hardLogout, assertAuthAndContext} from "@/utils/guard-util";


export default function Navbar98() {
    const [links, setLinks] = useState<{ href: string; label: string }[]>([]);
    const [name, setName] = useState<string>("user");
    const router = useRouter();
    const pathname = usePathname();

    const handleLogout = async () => {
        await hardLogout(router);
        router.replace("/");
    };

    useEffect(() => {
        (async () => {
            try {
                const result = await assertAuthAndContext(router);
                if (!result.ok) {
                    setLinks([]);
                    return;
                }

                const user = result.user;
                setName(user.displayName ?? user.username ?? "user");

                const homeHref = user.isTrustedUser ? "/home-trust" : "/home";
                const nav: { href: string; label: string }[] = [
                    {href: homeHref, label: "Home"},
                    {href: "/playback", label: "Videos"},
                ];

                if (!user.isTrustedUser) {
                    nav.push({href: "/users", label: "Users"});
                }

                setLinks(nav);
            } catch (err) {
                console.error("Navbar bootstrap failed:", err);
                setLinks([]);
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
                <p style={{margin: 0}}>Hello, <a href="/passport">{name}</a>!</p>
                <button onClick={handleLogout}>Logout</button>
            </div>
        </nav>
    );
}
