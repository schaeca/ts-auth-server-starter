import { ACCESS_JWT_SECRET, ACCESS_TOKEN_TTL } from "#config"
import { randomUUID } from "node:crypto"
import jwt from "jsonwebtoken"
import { RefreshToken} from "#models"
import { Types } from "mongoose"

type User = {
    _id: Types.ObjectId,
    roles: string[]
}
type Tokens = {
    accessToken: string,
    refreshToken: string
}
export const createTokens = async (user: User): Promise<Tokens> => {

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
    
    return {accessToken, refreshToken}
}