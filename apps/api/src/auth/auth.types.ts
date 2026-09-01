export interface AuthenticatedUser {
  id: string;
  email: string;
  isSystemAdmin: boolean;
}

declare module "http" {
  interface IncomingMessage {
    user?: AuthenticatedUser;
  }
}
