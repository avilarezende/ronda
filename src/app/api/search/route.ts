import { searchAdvisories } from "@/lib/advisory-search";
import { NextResponse } from "next/server";

export async function GET(request: Request) {
  const query = new URL(request.url).searchParams.get("q") ?? "";
  try {
    return NextResponse.json(await searchAdvisories(query));
  } catch {
    return NextResponse.json(
      { query, ok: false, error: "A busca não respondeu.", note: "A busca não respondeu.", vulnerabilities: [] },
      { status: 502 },
    );
  }
}
