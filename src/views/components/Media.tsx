import type { FC } from 'hono/jsx';
import type { UserRow } from '../../types';
import { getAvatarPaletteEntry, getUserAvatarUrl, getUserInitial } from '../../lib/images';

export const UserAvatar: FC<{
  user: Pick<UserRow, 'id' | 'name' | 'email' | 'avatar_key' | 'avatar_color' | 'avatar_version'>;
  size?: number;
  id?: string;
}> = ({ user, size = 38, id }) => {
  if (user.avatar_key) {
    return (
      <img
        id={id}
        src={getUserAvatarUrl('', user.id, user.avatar_version)}
        alt={user.name || user.email}
        width={size}
        height={size}
        class="rounded-circle object-fit-cover border flex-shrink-0"
        style={`width:${size}px;height:${size}px;`}
      />
    );
  }

  const palette = getAvatarPaletteEntry(user.avatar_color);
  const initial = getUserInitial(user.name, user.email);
  return (
    <span
      id={id}
      class="avatar-circle"
      style={`width:${size}px;height:${size}px;background:${palette.bg};color:${palette.fg};font-size:${Math.round(size * 0.42)}px;`}
    >
      {initial}
    </span>
  );
};

export const AppLogo: FC<{
  appName: string;
  logoUrl?: string | null;
  size?: number;
}> = ({ appName, logoUrl, size = 40 }) => {
  if (logoUrl) {
    return (
      <img
        src={logoUrl}
        alt={`${appName} logo`}
        width={size}
        height={size}
        class="rounded border object-fit-cover flex-shrink-0"
        style={`width:${size}px;height:${size}px;`}
      />
    );
  }

  return (
    <span
      class="app-icon-badge"
      style={`width:${size}px;height:${size}px;font-size:${Math.round(size * 0.52)}px;`}
    >
      <i class="bi bi-app-indicator"></i>
    </span>
  );
};
