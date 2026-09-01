import { Module } from "@nestjs/common";
import { ScansController } from "./scans.controller.js";
import { ScansService } from "./scans.service.js";

@Module({ controllers: [ScansController], providers: [ScansService], exports: [ScansService] })
export class ScansModule {}
