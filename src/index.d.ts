export function register(email: string, password: string): Promise<any>;
export function login(email: string, password: string): Promise<any>;
export function verifyToken(token: string): boolean;

export interface User {
  email: string;
  password?: string;
  role?: string;
}

export function getUser(id: string): Promise<User>;
export function logout(): Promise<void>;