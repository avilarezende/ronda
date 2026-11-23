const FORTALEZA_OFFSET_HOURS = 3;

export const COLLECTION_HOURS = [2, 8, 14, 20] as const;

export function nextUpdate(now: Date): Date {
  const parts = fortalezaParts(now);
  for (const hour of COLLECTION_HOURS) {
    const slot = fortalezaUtc(parts.year, parts.month, parts.day, hour);
    if (slot.getTime() > now.getTime()) return slot;
  }
  const nextDay = new Date(Date.UTC(parts.year, parts.month - 1, parts.day + 1));
  return fortalezaUtc(
    nextDay.getUTCFullYear(),
    nextDay.getUTCMonth() + 1,
    nextDay.getUTCDate(),
    COLLECTION_HOURS[0],
  );
}

export function formatUpdateHour(iso: string): string {
  const hour = new Intl.DateTimeFormat("en-GB", {
    timeZone: "America/Fortaleza",
    hour: "2-digit",
    hourCycle: "h23",
  }).format(new Date(iso));
  return `${hour}h`;
}

function fortalezaParts(now: Date): { year: number; month: number; day: number } {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: "America/Fortaleza",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).formatToParts(now);
  const value = (type: string) => Number(parts.find((part) => part.type === type)?.value);
  return { year: value("year"), month: value("month"), day: value("day") };
}

function fortalezaUtc(year: number, month: number, day: number, hour: number): Date {
  return new Date(Date.UTC(year, month - 1, day, hour + FORTALEZA_OFFSET_HOURS, 0, 0, 0));
}
