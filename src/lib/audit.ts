import { nowSec } from './crypto';

export interface AuditEntry {
  actorId: string | null;
  action: string;
  targetType?: string;
  targetId?: string;
  ipHash?: string | null;
  metadata?: Record<string, unknown>;
}

export async function writeAuditLog(db: D1Database, entry: AuditEntry): Promise<void> {
  try {
    await db
      .prepare(
        'INSERT INTO audit_logs (id, actor_id, action, target_type, target_id, ip_hash, metadata, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
      )
      .bind(
        crypto.randomUUID(),
        entry.actorId,
        entry.action,
        entry.targetType ?? null,
        entry.targetId ?? null,
        entry.ipHash ?? null,
        entry.metadata ? JSON.stringify(entry.metadata) : null,
        nowSec()
      )
      .run();
  } catch (err) {
    console.error('Audit log insert failed:', err);
  }
}
