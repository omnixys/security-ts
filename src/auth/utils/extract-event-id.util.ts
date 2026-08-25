/* eslint-disable @typescript-eslint/no-explicit-any */

const ACTIVE_EVENT_COOKIE = 'activeEvent';

function readCookie(req: any, name: string): string | undefined {
  const parsed = req.cookies?.[name];

  if (typeof parsed === 'string') {
    return parsed;
  }

  const header = req.headers?.cookie;

  if (typeof header !== 'string') {
    return undefined;
  }

  const pairs = header.split(';');

  for (const pair of pairs) {
    const separator = pair.indexOf('=');

    if (separator === -1) {
      continue;
    }

    const key = pair.slice(0, separator).trim();

    if (key === name) {
      return pair.slice(separator + 1).trim();
    }
  }

  return undefined;
}

function parseActiveEventCookie(raw: string | undefined): string | null {
  if (!raw) {
    return null;
  }

  const candidates = [raw];

  try {
    candidates.push(decodeURIComponent(raw));
  } catch {
    // Keep the raw cookie as the only parse candidate.
  }

  for (const candidate of candidates) {
    try {
      const parsed = JSON.parse(candidate) as { id?: unknown };

      if (typeof parsed.id === 'string' && parsed.id.trim()) {
        return parsed.id;
      }
    } catch {
      const looksEncodedJson = /%7[Bb]|%7[Dd]/.test(candidate);

      if (candidate.trim() && !candidate.includes('{') && !looksEncodedJson) {
        return candidate;
      }
    }
  }

  return null;
}

export function extractEventId(req: any): string | null {
  const vars = req.body?.variables ?? {};

  if (typeof vars.eventId === 'string') {
    return vars.eventId;
  }

  if (
    vars.input &&
    typeof vars.input === 'object' &&
    typeof vars.input.eventId === 'string'
  ) {
    return vars.input.eventId;
  }

  if (Array.isArray(vars.input)) {
    const first = vars.input[0];

    if (
      first &&
      typeof first === 'object' &&
      typeof first.eventId === 'string'
    ) {
      return first.eventId;
    }
  }

  if (
    vars.filter &&
    typeof vars.filter === 'object' &&
    typeof vars.filter.eventId === 'string'
  ) {
    return vars.filter.eventId;
  }

  return parseActiveEventCookie(readCookie(req, ACTIVE_EVENT_COOKIE));
}
