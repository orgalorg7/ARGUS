import { ArgumentsHost, Catch, type ExceptionFilter } from "@nestjs/common";
import { GovernanceError } from "@aasp/engagement-engine";
import type { Response } from "express";

@Catch(GovernanceError)
export class GovernanceFilter implements ExceptionFilter {
  catch(error: GovernanceError, host: ArgumentsHost): void {
    host
      .switchToHttp()
      .getResponse<Response>()
      .status(error.status)
      .json({ statusCode: error.status, code: error.code, message: error.message });
  }
}
