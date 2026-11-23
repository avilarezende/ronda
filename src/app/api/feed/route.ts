import { NextResponse } from "next/server";
import { loadFeed } from "@/lib/feeds";

export async function GET(request: Request) {
  const refresh = new URL(request.url).searchParams.get("refresh") === "1";
  try {
    const body = await loadFeed(refresh);
    return NextResponse.json(body);
  } catch {
    return NextResponse.json(
      { error: "Não foi possível montar o plantão." },
      { status: 500 },
    );
  }
}
