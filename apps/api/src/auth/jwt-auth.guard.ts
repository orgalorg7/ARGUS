import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import type { Request } from "express";
import { PrismaService } from "../database/prisma.service.js";
import type { AuthenticatedUser } from "./auth.types.js";

interface JwtPayload {
  sub: string;
  email: string;
  systemAdmin: boolean;
}

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(
    private readonly jwt: JwtService,
    private readonly prisma: PrismaService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();
    const authorization = request.headers.authorization;
    if (!authorization?.startsWith("Bearer "))
      throw new UnauthorizedException("Bearer token required.");
    let payload: JwtPayload;
    try {
      payload = await this.jwt.verifyAsync<JwtPayload>(authorization.slice(7));
    } catch {
      throw new UnauthorizedException("Bearer token is invalid or expired.");
    }
    const user = await this.prisma.user.findFirst({ where: { id: payload.sub, isActive: true } });
    if (!user) throw new UnauthorizedException("User is disabled or no longer exists.");
    request.user = {
      id: user.id,
      email: user.email,
      isSystemAdmin: user.isSystemAdmin,
    } satisfies AuthenticatedUser;
    return true;
  }
}
