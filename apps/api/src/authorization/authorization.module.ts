import { Module } from "@nestjs/common";
import {
  AuthorizationController,
  AuthorizationMatrixController,
} from "./authorization.controller.js";
import { AuthorizationService } from "./authorization.service.js";

@Module({
  controllers: [AuthorizationController, AuthorizationMatrixController],
  providers: [AuthorizationService],
  exports: [AuthorizationService],
})
export class AuthorizationModule {}
