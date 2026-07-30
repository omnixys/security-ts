import { createParamDecorator, type ExecutionContext } from '@nestjs/common';
import { getRequest } from '@omnixys/context-ts';

export const RESOLVED_EVENT_ID_REQUEST_KEY = 'resolvedEventId';

export type RequestWithResolvedEventId = {
  [RESOLVED_EVENT_ID_REQUEST_KEY]?: string;
};

export const CurrentEventId = createParamDecorator(
  (_data: unknown, context: ExecutionContext): string | undefined => {
    const req = getRequest(context) as RequestWithResolvedEventId | undefined;

    return req?.[RESOLVED_EVENT_ID_REQUEST_KEY];
  },
);
