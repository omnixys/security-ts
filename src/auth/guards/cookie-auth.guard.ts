import { type ExecutionContext, Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { getRequest } from '@omnixys/context-ts';

@Injectable()
export class CookieAuthGuard extends AuthGuard('jwt') {
  getRequest(context: ExecutionContext) {
    const req = getRequest(context);

    const token = req.cookies?.access_token;

    if (token) {
      req.headers.authorization = `Bearer ${token}`;
    }

    return req;
  }
}
