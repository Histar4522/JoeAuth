export const MAX_IMAGE_BYTES = 128 * 1024; // 128 KiB (131072 bytes)
export const IMAGE_DIMENSION = 256;

const PNG_SIGNATURE = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];

export interface AvatarPaletteEntry {
  bg: string;
  fg: string;
}

export const MILD_AVATAR_PALETTE: readonly AvatarPaletteEntry[] = [
  { bg: '#dbeafe', fg: '#1e3a8a' },
  { bg: '#dcfce7', fg: '#14532d' },
  { bg: '#fae8ff', fg: '#701a75' },
  { bg: '#fef3c7', fg: '#78350f' },
  { bg: '#ffe4e6', fg: '#881337' },
  { bg: '#e0e7ff', fg: '#312e81' },
  { bg: '#ccfbf1', fg: '#134e4a' },
  { bg: '#ffedd5', fg: '#7c2d12' },
];

export function pickRandomMildColor(): string {
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  return MILD_AVATAR_PALETTE[buf[0] % MILD_AVATAR_PALETTE.length].bg;
}

export function getAvatarPaletteEntry(color?: string | null): AvatarPaletteEntry {
  const normalized = (color || '').trim().toLowerCase();
  return MILD_AVATAR_PALETTE.find((entry) => entry.bg === normalized) ?? MILD_AVATAR_PALETTE[0];
}

export function getUserInitial(name?: string | null, email?: string | null): string {
  const source = (name || '').trim() || (email || '').trim() || '?';
  return source.charAt(0).toUpperCase();
}

export function validatePng256(bytes: Uint8Array): { ok: true; bytes: Uint8Array } | { ok: false; message: string } {
  if (bytes.byteLength === 0) {
    return { ok: false, message: 'Image file is empty.' };
  }
  if (bytes.byteLength > MAX_IMAGE_BYTES) {
    return { ok: false, message: 'Image must be 128 KiB or smaller.' };
  }
  if (bytes.byteLength < 33) {
    return { ok: false, message: 'Invalid PNG image.' };
  }
  for (let i = 0; i < PNG_SIGNATURE.length; i++) {
    if (bytes[i] !== PNG_SIGNATURE[i]) {
      return { ok: false, message: 'Only PNG images are allowed.' };
    }
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const ihdrLen = view.getUint32(8, false);
  const ihdrType =
    bytes[12] === 0x49 && bytes[13] === 0x48 && bytes[14] === 0x44 && bytes[15] === 0x52;
  if (!ihdrType || ihdrLen !== 13) {
    return { ok: false, message: 'Malformed PNG header.' };
  }

  const width = view.getUint32(16, false);
  const height = view.getUint32(20, false);
  if (width !== IMAGE_DIMENSION || height !== IMAGE_DIMENSION) {
    return { ok: false, message: `Image must be exactly ${IMAGE_DIMENSION}x${IMAGE_DIMENSION} pixels.` };
  }

  return { ok: true, bytes };
}

function escapeXml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

export function renderInitialAvatarSvg(name: string | null | undefined, color: string | null | undefined, email?: string | null): string {
  const palette = getAvatarPaletteEntry(color);
  const initial = escapeXml(getUserInitial(name, email));
  return `<svg xmlns="http://www.w3.org/2000/svg" width="256" height="256" viewBox="0 0 256 256" role="img" aria-label="${initial}">
  <rect width="256" height="256" fill="${palette.bg}" />
  <text x="128" y="132" text-anchor="middle" dominant-baseline="central" font-family="system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif" font-size="118" font-weight="700" fill="${palette.fg}">${initial}</text>
</svg>`;
}

export function getUserAvatarUrl(origin: string, userId: string, avatarVersion: number): string {
  return `${origin.replace(/\/+$/, '')}/media/avatars/${encodeURIComponent(userId)}?v=${avatarVersion}`;
}

export function getAppLogoUrl(origin: string, appId: string, logoVersion: number): string {
  return `${origin.replace(/\/+$/, '')}/media/app-logos/${encodeURIComponent(appId)}?v=${logoVersion}`;
}

export async function extractUploadedPng(
  request: Request,
  fieldNames: string[] = ['file', 'image']
): Promise<{ ok: true; bytes: Uint8Array } | { ok: false; message: string }> {
  const contentType = (request.headers.get('content-type') || '').toLowerCase();

  if (contentType.includes('multipart/form-data')) {
    let formData: FormData;
    try {
      formData = await request.formData();
    } catch {
      return { ok: false, message: 'Invalid multipart form payload.' };
    }
    let fileEntry: Blob | null = null;
    for (const name of fieldNames) {
      const value = formData.get(name);
      if (value && typeof value === 'object' && 'arrayBuffer' in value) {
        fileEntry = value;
        break;
      }
    }
    if (!fileEntry) {
      return { ok: false, message: 'No image file provided.' };
    }
    if (fileEntry.size > MAX_IMAGE_BYTES) {
      return { ok: false, message: 'Image must be 128 KiB or smaller.' };
    }
    return validatePng256(new Uint8Array(await fileEntry.arrayBuffer()));
  }

  if (contentType.startsWith('image/png') || contentType.startsWith('application/octet-stream')) {
    const lenHeader = Number(request.headers.get('content-length') || '0');
    if (lenHeader > MAX_IMAGE_BYTES) {
      return { ok: false, message: 'Image must be 128 KiB or smaller.' };
    }
    const buf = await request.arrayBuffer();
    return validatePng256(new Uint8Array(buf));
  }

  return { ok: false, message: 'Send a 256x256 PNG via multipart/form-data or image/png.' };
}

