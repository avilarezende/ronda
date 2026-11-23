import { NextResponse } from "next/server";
import { searchNist } from "@/lib/feeds";

export async function GET(request: Request) {
  const query = new URL(request.url).searchParams.get("q") ?? "";
  try {
    return NextResponse.json(await searchNist(query));
  } catch {
    return NextResponse.json(
      { query, ok: false, error: "O NIST não respondeu.", vulnerabilities: [] },
      { status: 502 },
    );
  }
}
