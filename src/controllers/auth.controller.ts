import type { RequestHandler } from 'express';
import bcrypt from 'bcrypt';
import { z } from 'zod/v4';
import jwt from 'jsonwebtoken';
import { ACCESS_JWT_SECRET, SALT_ROUNDS } from '#config';
import type { loginSchema, registerSchema } from '#schemas';
import { RefreshToken, User } from '#models';
import { createTokens, setAuthCookie } from '#utils';
import { Types } from 'mongoose';

export type RegisterInputDTO = z.infer<typeof registerSchema>;
// type RegisterDTO = RegisterInputDTO & {
//   _id: InstanceType<typeof Types.ObjectId>;
//   createdAt: Date;
// };
type LoginInputDTO = z.infer<typeof loginSchema>;
type AuthResponse = {
  message: string;
  accessToken: string;
};
type UserDTO = {
  firstName: string;
  lastName: string;
  email: string;
  _id: InstanceType<typeof Types.ObjectId>;
  roles: string[];
  createdAt: Date;
  updatedAt: Date;
  __v: number;
};
type VerifyResponse = {
  message: string,
  user: UserDTO
}
type ErrorResponse = { message: string };

export const register: RequestHandler<  unknown,  AuthResponse | ErrorResponse,  RegisterInputDTO> = async (req, res) => {
  // TODO: Implement user registration
  try {
    //Destructuring would look like this: const {email, password} = req.body
    // Query the DB for an existing user with that email
    const found = await User.findOne({ email: req.body.email });

    // Throw an error if a user with that email is found
    if (found) {
      res.status(409).json({ message: 'User already exists' });
      return;
    }

    // Salt and hash the user's password
    const salt = await bcrypt.genSalt(SALT_ROUNDS);
    const hashedPW = await bcrypt.hash(req.body.password, salt); // password is destructured from the request body

    // Save the user to the database with the hashed password
    req.body.password = hashedPW;
    const user = await User.create({ ...req.body } satisfies RegisterInputDTO);
    //statt vorher req.body.password = hashedPW zu setzen könnte man auch {...req.body, password: hashedPW} bei der create operation nutzen
    
    // Generate access token (JWT) and refresh token (random string saved to database)
    const { accessToken, refreshToken } = await createTokens(user);
    // wenn man nicht res und refreshtoken senden will, kann man auch das hier nutzen: const cookieOptions = await setAuthCookie(); und dann in setAuthCookie statt <res.cookie("refreshToken", refreshToken, cookieOptions)> <return cookieOptions> nutzen, dann muss man hier noch res.cookie('refreshToken', refreshToken, cookieOptions); ergänzen

    // Send the access token (in the response body) and the refresh token (in a cookie)
    setAuthCookie(res, refreshToken)
    res.status(201).json({
      message: `User registered successfully`,
      accessToken
    });
    return;
  } catch (error: unknown) {
    if (error instanceof Error) {
      res.status(500).json({ message: error.message });
      return;
    } else {
      res.status(500).json({ message: 'An unknown error occured' });
      return;
    }
  }
};

export const login: RequestHandler<unknown, AuthResponse | ErrorResponse, LoginInputDTO> = async (
  req,
  res
) => {
  // TODO: Implement user login
  try {
    //   Query the DB for an existing user with that email (make sure to .select('+password') so we can compare it to the hashed password)
    const user = await User.findOne({ email: req.body.email });
    const password = req.body.password;
    // Throw an error is a user with that email is NOT found
    if (!user) {
      res.status(404).json({ message: "A user with this email adress doesn't exist" }); //vielleicht eher "Incorrect credentials" als message nutzen, damit nicht klar ist ob email oder passwort falsch sind
      return; 
    }
    // Compare the hashed password to the password the user provided
    const match = await bcrypt.compare(password, user.password);
    // Throw an error if the passwords don't match
    if (!match) {
      res.status(401).json({ message: 'Incorrect password' }); //vielleicht eher "Incorrect credentials" als message nutzen, damit nicht klar ist ob email oder passwort falsch sind
      return;
    }
    // Delete all refresh tokens from that user
    await RefreshToken.deleteMany({
      userId: user._id
    });
    // Generate access token (JWT) and refresh token (random string saved to database)
    const { accessToken, refreshToken } = await createTokens(user);
    // Send the access token (in the response body) and the refresh token (in a cookie)
    setAuthCookie(res, refreshToken);
    res.status(200).json({
      message: `Logged in successfully`,
      accessToken
    });
    return;
  } catch (error: unknown) {
    if (error instanceof Error) {
      res.status(500).json({ message: error.message });
      return;
    } else {
      res.status(500).json({ message: 'An unknown error occured' });
      return;
    }
  }
};
export const refresh: RequestHandler <unknown, AuthResponse | ErrorResponse> = async (req, res) => {
  // TODO: Implement access token refresh and refresh token rotation
  try {
    // Destructure the refreshToken from req.cookies   
    // Throw an error if there is no refreshToken cookie
    if (!req.cookies.refreshToken) {
      res.status(401).json({ message: 'RefreshToken is required' });
      return;
    }
    // Query the database for the matching stored refresh token
    const existingRefreshToken = await RefreshToken.findOne({ token: req.cookies.refreshToken });
    
    // Throw an error if no stored token was found
    if (!existingRefreshToken) {
      res.status(403).json({ message: 'RefreshToken not found' });
      return;
    }
    
    // Delete the stored token (since we'll be rotating it with a new refresh token)
    await RefreshToken.deleteOne({ token: req.cookies.refreshToken });    
    
    // Query the database for the user associated with that token
    const user = await User.findOne({ _id: existingRefreshToken.userId });
    
    // Throw an error if no user is found
    if (!user) {
      res.status(403).json({ message: 'User not found' });
      return;
    }
    // Generate access token (JWT) and refresh token (random string saved to database)
    const { accessToken, refreshToken } = await createTokens(user);
    // Send the access token (in the response body) and the refresh token (in a cookie)
    setAuthCookie(res, refreshToken);
    res.status(200).json({
      message: `Refreshed successfully`,
      accessToken
    });
    return;
  } catch (error) {
    if (error instanceof Error) {
      res.status(500).json({ message: error.message });
      return;
    } else {
      res.status(500).json({ message: 'An unknown error occured' });
      return;
    }
  }
};

export const logout: RequestHandler = async (req, res) => {
  // TODO: Implement logout by removing the tokens
  // Get the refreshToken cookie 
  // If a refreshToken cookie is found, delete the corresponding stored token from the database
  if (req.cookies.refreshToken) {
   await RefreshToken.findOneAndDelete({ token: req.cookies.refreshToken })
  }
  // Clear the refreshToken cookie
  res.clearCookie('refreshToken')
  // Send a success message in the response body
  res.json({ message: 'Logged out successfully' });
};

export const me: RequestHandler<unknown, VerifyResponse | ErrorResponse> = async (req, res, next) => {
  // TODO: Implement a me handler
  try {
    // Get the access token from the request headers
    // Get the Authorization header from the request
    const authHeader = req.header('authorization');
    // Isolate the access token
    const accessToken = authHeader?.startsWith('Bearer ') && authHeader.split(' ')[1];
    // Throw an error if there is not access token
    if (!accessToken) {
      res.status(401).json({ message: 'Access token is required.' });
      return;
    }
    // Verify the access token
    const decoded = jwt.verify(accessToken, ACCESS_JWT_SECRET) as jwt.JwtPayload;
    // If token is expired, add code: ACCESS_TOKEN_EXPIRED to error
    if (!decoded.sub) throw new Error('Invalid or expired Access Token.', { cause: { status: 403}})

    // Query the database for the user who is the sub of the access token
    const user = await User.findById({ _id: decoded.sub }).select("-password").lean()
    // Throw an error if no user is found
    if (!user) {
      res.status(404).json({ message: 'User not found' });
      return;
    }
    // Send user profile with success message in response body
    res.json({ message: 'Success', user: user });
  } catch (error) {
    // If token is expired, add code: ACCESS_TOKEN_EXPIRED to error

    if (error instanceof jwt.TokenExpiredError) {
      next(
        new Error('Expired access token', {
          cause: { status: 401, code: 'ACCESS_TOKEN_EXPIRED' }
        })
      );
    } else {
      next(new Error('Invalid access token.', { cause: { status: 401 } }));
    }
  }
};
