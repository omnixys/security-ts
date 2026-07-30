import { type ExecutionContext, Injectable } from '@nestjs/common';

import { extractBearerToken } from '../utils/token-extractor.util.js';
import { AuthGuard } from '@nestjs/passport';
import { getRequest } from '@omnixys/context-ts';

@Injectable()
export class HeaderAuthGuard extends AuthGuard('jwt') {
  getRequest(context: ExecutionContext) {
    const req = getRequest(context);

    const token = extractBearerToken(req);

    if (token) {
      req.headers.authorization = `Bearer ${token}`;
    }

    return req;
  }
}
