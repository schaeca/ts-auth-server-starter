import { REFRESH_TOKEN_TTL } from "#config"
import type { Response } from "express"

export const setAuthCookie = async (res: Response, refreshToken: string) => {
    const isProduction = process.env.NODE_ENV === "production"
    const cookieOptions = {
        httpOnly: true,
        sameSite: isProduction ? ("none" as const) : ("lax" as const),
        secure: isProduction,
        maxAge: REFRESH_TOKEN_TTL * 1000 // in milliseconds
    }
    res.cookie("refreshToken", refreshToken, cookieOptions)
}
