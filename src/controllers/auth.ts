import { NextFunction, Request, Response } from "express";
import ejs from "ejs";
import path from "path";
import bcrypt from "bcrypt";
import jwt, { JwtPayload, Secret } from "jsonwebtoken";

import prismaClient from "../libs/prismadb";
import sendMail from "../libs/utils/sendMail";
import { accessTokenOptions, expiredFormat, refreshTokenOptions, sendToken } from "../libs/utils/jwt";
import { isValidPassword, passwordPolicy } from "../libs/utils/validator";
import HttpException, { ErrorCode } from "../exceptions/http-exception";
import BadRequestException from "../exceptions/bad-requests";
import NotFoundException from "../exceptions/not-found";
import { ACCESS_TOKEN_EXPIRE, ACCESS_TOKEN_SECRET, ACTIVATION_TOKEN_EXPIRE, ACTIVATION_TOKEN_SECRET, MAIL_NO_REPLY, REDIS_SESSION_EXPIRE, REFRESH_TOKEN_EXPIRE, REFRESH_TOKEN_SECRET, SALT_ROUNDS } from "../secrets";

import { EventType } from "../constants/enum";
import { UserEntity } from "../entities/user";
import { signUpSchema } from "../schema/users";
import ConfigurationException from "../exceptions/configuration";
import { redis } from "../libs/utils/redis";
import UnauthorizedException from "../exceptions/unauthorized";


//-----------------------------------------------------------------------------
//              Register User  /register  /signup
//-----------------------------------------------------------------------------

// IRegisterRequest
interface IRegisterRequest {
    name: string;
    email: string;
    password: string;
    avatar?: string;
}

// Handling the user registration(signup) process.
export const signup =
    async (req: Request, res: Response, next: NextFunction) => {
        // Validate input
        signUpSchema.parse(req.body);
        const { name, email, password } = req.body as IRegisterRequest;

        if (!name || !email || !password) {
            throw new BadRequestException("Please enter your name, email and password", ErrorCode.UNFULLFIELD_REQUIRED_FIELD);
        }

        if (!isValidPassword(password)) {
            throw new BadRequestException(`Invalid Password : ${passwordPolicy}`, ErrorCode.INVALID_DATA);
        }

        // check if the email already exists in the database
        const isEmailExist = await prismaClient.user.findFirst({ where: { email: email } });
        if (isEmailExist) {
            throw new BadRequestException("Email already exist", ErrorCode.RESSOURCE_ALREADY_EXISTS);
        }

        const user: IRegisterRequest = {
            name,
            email,
            password,
        };

        const activationToken = createActivationToken(user);
        // activationCode
        const activationCode = activationToken.activationCode;
        // TTL of the activation token
        const activationCodeExpire = Math.floor(
            parseInt(ACTIVATION_TOKEN_EXPIRE) / 60
        );

        const data = {
            user: { name: user.name },
            activationCode,
            activationCodeExpire,
            supportmail: MAIL_NO_REPLY
        };

        const html = await ejs.renderFile(
            path.join(__dirname, "../mails/activation.mail.ejs"),
            data
        );

        try {
            await sendMail({
                email: user.email,
                subject: "Activation of your account",
                template: "activation.mail.ejs",
                data,
            });

            res.status(201).json({
                success: true,
                message: `Please check your email : ${user.email} to activate your account`,
                activationToken: activationToken.token,
            });
        } catch (error: any) {
            throw new HttpException(error.message, 500, ErrorCode.INTERNAL_EXCEPTION, null);
        }

    };


// IActivationToken
interface IActivationToken {
    token: string;
    activationCode: string;
}

/**
 * Generates an activation token containing a random activation code for a user.
 * @param {any} user - The `user` parameter in the `createActivationToken` function is an object that
 * represents the user for whom the activation token is being created. It likely contains information
 * about the user, such as their username, email, and other relevant details.
 * @returns returns an object with two properties: `token` and `activationCode`. 
 */
export const createActivationToken = (user: any): IActivationToken => {
    const activationCode = Math.floor(1000 + Math.random() * 9000).toString();
    const token = jwt.sign(
        { user, activationCode },
        ACTIVATION_TOKEN_SECRET as Secret,
        { expiresIn: expiredFormat(ACTIVATION_TOKEN_EXPIRE) }
    );

    return { token, activationCode };
};


export interface IUser extends Document {
    name: string;
    email: string;
    password: string;
    role: string;
    isVerified: boolean;
    comparePassword: (password: string) => Promise<boolean>;
    signAccessToken: () => string;
    signRefreshToken: () => string;
}

//-----------------------------------------------
//               Activate User  /activate
//-----------------------------------------------

// IActivationRequest
interface IActivationRequest {
    activation_token: string;
    activation_code: string;
}

export const activate =
    async (req: Request, res: Response, next: NextFunction) => {
        const { activation_token, activation_code } =
            req.body as IActivationRequest;
        if (activation_token === undefined || activation_code === undefined) {
            throw new BadRequestException(
                "Invalid request, please provide activation_code and activation_token",
                ErrorCode.INVALID_DATA
            );
        }

        const newUser: { user: IUser; activationCode: string } = jwt.verify(
            activation_token,
            ACTIVATION_TOKEN_SECRET as string
        ) as { user: IUser; activationCode: string };

        if (newUser.activationCode !== activation_code) {
            throw new BadRequestException("Invalid activation code", ErrorCode.INVALID_DATA);
        }

        const { name, email, password } = newUser.user;

        const existUser = await prismaClient.user.findFirst({
            where: { email }
        });
        if (existUser) throw new NotFoundException("Email already exist", ErrorCode.RESSOURCE_ALREADY_EXISTS);


        const userEntity = new UserEntity({ name, email, password });
        const isPasswordMatched = await userEntity.comparePassword(password);
        const user = await prismaClient.user.create({
            data: {
                name,
                email,
                password: await bcrypt.hash(password, parseInt(SALT_ROUNDS || '10')),
            }
        });
        // Étape 2: Associer le rôle à l'utilisateur
        const roleName = 'USER';
        const role = await prismaClient.role.findUnique({
            where: { name: roleName },
        });

        if (role) {
            await prismaClient.userRole.create({
                data: {
                    userId: user.id,
                    roleId: role.id,
                },
            });
            console.log(`Assigned role '${roleName}' to user '${user.name}'.`);
        } else {
            console.error(`Role '${roleName}' not found.`);
        }

        res.status(201).json({
            success: true,
            message: `Your account is activate`,
        });

    };


//-----------------------------------------------------------------------------
//               Login User  /login  /signin
//-----------------------------------------------------------------------------

// ILoginRequest
interface ILoginRequest {
    email: string;
    password: string;
    roleId?: string;
}

// Handling the user login(signin) process
export const signin =
    async (req: Request, res: Response, next: NextFunction) => {

        const { email, password, roleId }: ILoginRequest = req.body;

        // Validation of user inputs
        if (!email || !password) {
            throw new BadRequestException("Please enter both Email and Password", ErrorCode.UNFULLFIELD_REQUIRED_FIELD);
        }

        // Check if user exists in the database
        const user = await prismaClient.user.findFirst({
            where: { email: email },
            include: { roles: true }, // Include roles relation
        });

        if (!user) {
            throw new NotFoundException("Invalid Email or Password", ErrorCode.INVALID_DATA);
        }

        if (user.roles.length === 0) {
            return next(new ConfigurationException("User has no roles assigned", ErrorCode.BAD_CONFIGURATION));
        }
        let role
        // If user has multiple roles, check if a role is specifie
        if (user.roles.length > 1) {
            if (!roleId) throw new BadRequestException("Please specify a role to sign in", ErrorCode.INVALID_DATA);

            // Check if the specified role exists in the user's roles
            const roleExists = user.roles.some(userRole => userRole.roleId === roleId);
            if (!roleExists) {
                return next(new BadRequestException("Invalid role specified", ErrorCode.BAD_CONFIGURATION));
            }
            role = await prismaClient.role.findFirst({
                select: {
                    id: true,
                    name: true,
                },
                where: { id: roleId },
            });
        } else {
            role = await prismaClient.role.findFirst({
                select: {
                    id: true,
                    name: true,
                },
                where: { id: user.roles[0].roleId },
            });
        }

        const userEntity = new UserEntity({ ...user, role });
        const isPasswordMatched = await userEntity.comparePassword(password);
        if (!isPasswordMatched) {
            return next(new BadRequestException("Invalid Email or Password", ErrorCode.INVALID_DATA));
        }

        // Connection History
        await prismaClient.connectionHistory.create({
            data: {
                userId: user.id,
                ipAddress: req.ip || '0.0.0.0',
                eventType: EventType.LOGIN
            },
        });

        // When every thing is ok send Token to user
        sendToken(userEntity, 200, res);
    };



//-----------------------------------------------
//               Logout User /logout
//-----------------------------------------------

export const signout =
    async (req: Request, res: Response, next: NextFunction) => {

        res.cookie("access_token", "", { maxAge: 1 });
        res.cookie("refresh_token", "", { maxAge: 1 });

        // Delete in redis the user_id
        const userId = req.user?.id!;
        redis.del(userId);

        // TODO : enregistrer la date de deconnection
        res.status(200).json({
            success: true,
            message: "Logged out successfully",
        });

    };


//-----------------------------------------------
//              Update User Access Token /user/refresh
//-----------------------------------------------

export const updateAccessToken =
    async (req: Request, res: Response, next: NextFunction) => {
        // const refresh_token = req.headers.refresh_token;
        const refresh_token = req.cookies.refresh_token as string;

        const message = "Could not refresh token , please login for access this ressource.";
        if (!refresh_token) throw new UnauthorizedException(message, ErrorCode.UNAUTHORIZE);


        const decoded = jwt.verify(
            refresh_token,
            REFRESH_TOKEN_SECRET as string
        ) as JwtPayload;
        if (!decoded) {
            throw new UnauthorizedException(message, ErrorCode.UNAUTHORIZE);
        }

        const session = await redis.get(decoded.id);
        if (!session) {
            throw new UnauthorizedException(message, ErrorCode.UNAUTHORIZE);
        }

        const user = JSON.parse(session);

        const accessToken = jwt.sign(
            { id: user._id },
            ACCESS_TOKEN_SECRET,
            { expiresIn: expiredFormat(ACCESS_TOKEN_EXPIRE) }
        );

        const refreshToken = jwt.sign(
            { id: user._id },
            REFRESH_TOKEN_SECRET,
            { expiresIn: expiredFormat(REFRESH_TOKEN_EXPIRE) }
        );

        // Add User in the request to user it in any request
        req.user = user;

        res.cookie("access_token", accessToken, accessTokenOptions);
        res.cookie("refresh_token", refreshToken, refreshTokenOptions);

        //Update redis session
        redis.set(user.id, JSON.stringify(user), "EX", REDIS_SESSION_EXPIRE);

        res.status(200).json({
            success: true,
            accessToken,
            refreshToken,
        });

    };



//-----------------------------------------------
//              Get User /me
//-----------------------------------------------

// Handling the me process
export const me =
    async (req: Request, res: Response, next: NextFunction) => {
        res.status(200).json({
            success: true,
            user: req.user,
        });
    };

