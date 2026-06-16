import type { RequestHandler } from 'express';
import bycript from "bcrypt"
import {z} from "zod/v4"
import jwt from 'jsonwebtoken';
import { randomUUID } from 'node:crypto';
import { ACCESS_JWT_SECRET, ACCESS_TOKEN_TTL, REFRESH_TOKEN_TTL, SALT_ROUNDS } from '#config';
import type { registerSchema } from '#schemas';
import { Types } from 'mongoose';
import { RefreshToken, User } from '#models';

type UserInputDTO = z.infer<typeof registerSchema>
type UserDTO = UserInputDTO & {
  _id: InstanceType<typeof Types.ObjectId>;
  createdAt: Date;
}
type AuthResponse = {
  message: string,
  accessToken: string
}
type ErrorResponse = {message:string}
type IdParams = {id: string}

export const register: RequestHandler<unknown, AuthResponse | ErrorResponse, UserInputDTO> = async (req, res) => {
  // TODO: Implement user registration
  try {    
    // Query the DB for an existing user with that email
    const found = await User.findOne({email: req.body.email})
    
    // Throw an error if a user with that email is found
    if (found) {
      res.status(400).json({message: "User already exists"})
      return
    }
    
      // Salt and hash the user's password
    const salt = await bycript.genSalt(SALT_ROUNDS);
    const hashedPW = await bycript.hash(req.body.password, salt) // password is destructured from the request body
    
    // Save the user to the database with the hashed password
    req.body.password = hashedPW
    const user = await User.create({...req.body} satisfies UserInputDTO)
    
    // Generate access token (JWT) and refresh token (random string saved to database)
    const payload = {roles: user.roles}
    const secret = ACCESS_JWT_SECRET
    const tokenOptions = {
      expiresIn: ACCESS_TOKEN_TTL, 
      subject: user._id.toString()
    };
    const accessToken = jwt.sign(payload, secret, tokenOptions)
   
    const refreshToken = randomUUID()
    await RefreshToken.create({
      token: refreshToken,
      userId: user._id
    })

    const isProduction = process.env.NODE_ENV === "production"
    const cookieOptions = {
      httpOnly: true,
      sameSite: isProduction ? ("none" as const) : ("lax" as const),
      secure: isProduction,
      maxAge: REFRESH_TOKEN_TTL * 1000 // in milliseconds
    }

    // Send the access token (in the response body) and the refresh token (in a cookie)
    res.cookie("refreshToken", refreshToken, cookieOptions)
    res.status(201).json({
      message: `User registered successfully`,
      accessToken,
    })
    return
  } catch (error: unknown) {
    if (error instanceof Error){
      res.status(500).json({message: error.message})
      return
    } else{
      res.status(500).json({message: "An unknown error occured"})
      return
    }
  }
};

export const login: RequestHandler = async (req, res) => {
  // TODO: Implement user login
  //   Query the DB for an existing user with that email (make sure to .select('+password') so we can compare it to the hashed password)
  // Throw an error is a user with that email is NOT found
  // Compare the hashed password to the password the user provided
  // Throw an error if the passwords don't match
  // Delete all refresh tokens from that user
  // Generate access token (JWT) and refresh token (random string saved to database)
  // Send the access token (in the response body) and the refresh token (in a cookie)
  res.json({ message: 'POST /login', body: req.body });
};

export const refresh: RequestHandler = async (req, res) => {
  // TODO: Implement access token refresh and refresh token rotation
  // Destructure the refreshToken from req.cookies
  // Throw an error if there is no refreshToken cookie
  // Query the database for the matching stored refresh token
  // Throw an error if no stored token was found
  // Delete the stored token (since we'll be rotating it with a new refresh token)
  // Query the database for the user associated with that token
  // Throw an error if no user is found
  // Generate access token (JWT) and refresh token (random string saved to database)
  // Send the access token (in the response body) and the refresh token (in a cookie)
  res.json({ message: 'POST /refresh' });
};

export const logout: RequestHandler = async (req, res) => {
  // TODO: Implement logout by removing the tokens
  //   Get the refreshToken cookie
  // If a refreshToken cookie is found, delete the corresponding stored token from the database
  // Clear the refreshToken cookie
  // Send a success message in the response body
  res.json({ message: 'DELETE /refresh' });
};

export const me: RequestHandler = async (req, res, next) => {
  // TODO: Implement a me handler
  // Get the access token from the request headers
  // Get the Authorization header from the request
  // Isolate the access token
  // Throw an error if there is not access token
  // Verify the access token
  // If token is expired, add code: ACCESS_TOKEN_EXPIRED to error
  // Query the database for the user who is the sub of the access token
  // Throw an error if no user is found
  // Send user profile with success message in response body
  res.json({ message: 'GET /me' });
};
