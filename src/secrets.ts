import dotenv from 'dotenv';

dotenv.config({ path: '.env' })

export const PORT = process.env.NODE_PORT;
export const NODE_ORIGIN = process.env.NODE_ORIGIN!;

export const SALT_ROUNDS = process.env.SALT_ROUNDS;

export const ACTIVATION_TOKEN_SECRET = process.env.ACTIVATION_TOKEN_SECRET!;
export const ACTIVATION_TOKEN_EXPIRE = process.env.ACTIVATION_TOKEN_EXPIRE!;

export const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET!;
export const ACCESS_TOKEN_EXPIRE = process.env.ACCESS_TOKEN_EXPIRE!;

export const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET!;
export const REFRESH_TOKEN_EXPIRE = process.env.REFRESH_TOKEN_EXPIRE!;

export const DATABASE_EXTERNAL_SERVICE_NAME: string = process.env.DATABASE_EXTERNAL_SERVICE_NAME!;
export const DATABASE_EXTERNAL_HOSTNAME: string = process.env.DATABASE_EXTERNAL_HOSTNAME!;
export const DATABASE_EXTERNAL_PORT: string = process.env.DATABASE_EXTERNAL_PORT!;
export const DATABASE_EXTERNAL_USERNAME: string = process.env.DATABASE_EXTERNAL_USERNAME!;
export const DATABASE_EXTERNAL_PASSWORD: string = process.env.DATABASE_EXTERNAL_PASSWORD!;


export const REDIS_HOSTNAME = process.env.REDIS_HOSTNAME;
export const REDIS_PORT = process.env.REDIS_PORT;
export const REDIS_PASSWORD = process.env.REDIS_PASSWORD;
export const REDIS_SESSION_EXPIRE = process.env.REDIS_SESSION_EXPIRE!;

export const SMTP_SERVICE = process.env.SMTP_SERVICE;
export const SMTP_HOST = process.env.SMTP_HOST;
export const SMTP_PORT = process.env.SMTP_PORT;
export const SMTP_CIPHERS = process.env.SMTP_CIPHERS;
export const SMTP_MAIL = process.env.SMTP_MAIL;
export const SMTP_PASSWORD = process.env.SMTP_PASSWORD;

export const MAIL_NO_REPLY = process.env.MAIL_NO_REPLY;
