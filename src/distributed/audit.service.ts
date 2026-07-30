import { SecurityAuditEvent } from './audit.types.js';
import { Inject, Injectable, Optional } from '@nestjs/common';
import { ContextAccessor } from '@omnixys/context-ts';
import { OmnixysLogger } from '@omnixys/logger-ts';

@Injectable()
export class SecurityAuditService {
  constructor(
    @Inject('AUDIT_PRODUCER')
    private readonly producer: {
      send(topic: string, message: unknown): Promise<void>;
    },
    @Optional() private readonly logger?: OmnixysLogger,
  ) {}

  async log(event: SecurityAuditEvent): Promise<void> {
    const context = ContextAccessor.get();
    await this.producer.send('security.audit', {
      ...event,
      timestamp: Date.now(),
      requestId: event.requestId ?? context?.requestId ?? 'unscoped',
      correlationId:
        event.correlationId ?? context?.correlationId ?? context?.requestId ?? 'unscoped',
      traceId: event.traceId ?? context?.trace?.traceId,
      actorId: event.actorId ?? context?.principal?.actorId,
      tenantId: event.tenantId ?? context?.tenant?.tenantId ?? context?.principal?.tenantId,
    });
    this.logger?.child(SecurityAuditService.name).info('Security audit event emitted', {
      auditType: event.type,
    });
  }
}
