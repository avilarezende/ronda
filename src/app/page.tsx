"use client";

import dynamic from "next/dynamic";

const Desk = dynamic(() => import("@/components/desk").then((mod) => mod.Desk), {
  ssr: false,
  loading: () => (
    <p className="min-h-screen bg-[#e8e2d6] p-8 text-sm text-[#5c564c]">Abrindo o plantão…</p>
  ),
});

export default function Home() {
  return <Desk />;
}
