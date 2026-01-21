export interface CraftaAuthRoutes {
  register?: string;
  login?: string;
  verify?: string;
  forgotPassword?: string;
  resetPassword?: string;
  refreshToken?: string;
  profile?: string;
  twoFactor?: string;
  roles?: string;
  permissions?: string;
}

export interface PasswordPolicyConfig {
  minLength?: number;
  requireUppercase?: boolean;
  requireLowercase?: boolean;
  requireNumbers?: boolean;
  requireSpecialChars?: boolean;
  expiryDays?: number;
  minStrength?: number;
}

export interface SmtpConfig {
  host: string;
  port: number;
  auth: {
    user: string;
    pass: string;
  };
  from: string;
}

export interface SocialGoogleConfig {
  clientID: string;
  clientSecret: string;
  callbackURL: string;
}

export interface SocialConfig {
  google?: SocialGoogleConfig | null;
  facebook?: any;
  github?: any;
}

export interface EnvConfig {
  JWT_SECRET: string;
  [key: string]: any;
}

export interface AuthConfig {
  strategy?: 'jwt';
  fields?: string[];
  routes?: CraftaAuthRoutes;
  mongoUrl?: string;
  maxLoginAttempts?: number;
  emailVerification?: boolean;
  loginAlerts?: boolean;
  passwordPolicy?: PasswordPolicyConfig;
  smtp?: SmtpConfig | null;
  social?: SocialConfig;
  env?: EnvConfig;
  accessTokenExpiry?: string;
  refreshTokenDays?: number;
  enableCSRF?: boolean;
  limits?: {
    loginMax?: number;
    twoFAMax?: number;
    forgotPasswordMax?: number;
    refreshMax?: number;
  };
  baseUrl?: string;
  emailTemplateDir?: string;
}

export class ApiError extends Error {
  status: number;
  constructor(message: string, status?: number);
}

export function auth(config?: AuthConfig): (app: any) => void;