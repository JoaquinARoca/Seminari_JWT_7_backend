import { Request, Response, NextFunction } from "express";
import { verifyToken } from "../utils/jwt.handle.js";
import jwt, { JwtPayload } from "jsonwebtoken";

interface RequestExt extends Request {
    user?: string | JwtPayload;
}

const checkJwt = (req: RequestExt, res: Response, next: NextFunction) => {
    try {
        // 1. Obtener el token de múltiples fuentes
        const authHeader = req.headers.authorization 
                        || req.headers.Authorization
                        || req.body?.token
                        || req.query?.token;

        if (!authHeader) {
            console.log('Headers recibidos:', req.headers); // Debug
            return res.status(401).json({ 
                message: 'SESSION_NO_VALID',
                details: 'Token not provided in headers, body or query',
                receivedHeaders: Object.keys(req.headers) // Para debug
            });
        }

        // 2. Extraer el token del formato Bearer
        const token = authHeader.toString().startsWith('Bearer ') 
            ? authHeader.split(' ')[1] 
            : authHeader;

        if (!token) {
            return res.status(401).json({
                message: 'SESSION_NO_VALID',
                details: 'Invalid token format. Use: Bearer <token>'
            });
        }

        // 3. Verificar el token
        const decoded = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET!);
        req.user = decoded;
        next();

    } catch (error: any) {
        console.error('JWT Error:', error);
        return res.status(401).json({
            message: 'SESSION_NO_VALID',
            details: error.message,
            errorType: error.name
        });
    }
};


export { checkJwt };
