import { Injectable, UnauthorizedException } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import argon2 from "argon2";
import { PrismaService } from "../database/prisma.service.js";
import type { AuthenticatedUser } from "./auth.types.js";

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
  ) {}

  async login(
    emailInput: string,
    password: string,
  ): Promise<{ accessToken: string; user: AuthenticatedUser }> {
    const email = emailInput.trim().toLowerCase();
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user || !user.isActive || !(await argon2.verify(user.passwordHash, password))) {
      throw new UnauthorizedException("Invalid email or password.");
    }
    const authenticatedUser = { id: user.id, email: user.email, isSystemAdmin: user.isSystemAdmin };
    const accessToken = await this.jwt.signAsync({
      sub: user.id,
      email: user.email,
      systemAdmin: user.isSystemAdmin,
    });
    return { accessToken, user: authenticatedUser };
  }
}
