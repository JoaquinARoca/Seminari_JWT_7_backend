import { Request, Response } from "express";
import { registerNewUser, loginUser, googleAuth } from "../auth/auth_service.js";
import { generateAccessToken,generateRefreshToken } from "../../utils/jwt.handle.js";
import jwt from 'jsonwebtoken'
import { getUserByMail } from "../users/user_service.js";

const registerCtrl = async ({body}: Request, res: Response) => {
    try{
        const responseUser = await registerNewUser(body);
        res.json(responseUser);
    } catch (error: any){
        res.status(500).json({ message: error.message });
    }
};



const loginCtrl = async ({ body }: Request, res: Response) => {
    try {
        const { name, email, password } = body;
        const responseUser = await loginUser({ name, email, password });

        if (responseUser === 'INCORRECT_PASSWORD') {
            return res.status(403).json({ message: 'Contraseña incorrecta' });
        }

        if (responseUser === 'NOT_FOUND_USER') {
            return res.status(404).json({ message: 'Usuario no encontrado' });
        }

        // Configura la cookie de refresh token
        res.cookie('refreshToken', responseUser.reftoken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 días
            path: '/api/auth/refresh' // Solo accesible por esta ruta
        });

        
        return res.json({ 
            user: {
                email: responseUser.user.email,
                name: responseUser.user.name
            },
            accestoken:responseUser.token
        });
    } catch (error: any) {
        return res.status(500).json({ message: error.message });
    }
};


const googleAuthCtrl = async(req: Request, res: Response) =>{
    const redirectUri = process.env.GOOGLE_OAUTH_REDIRECT_URL;
    if (!redirectUri) {
        console.error(" ERROR: GOOGLE_OAUTH_REDIRECT_URL no està definida a .env");
        return res.status(500).json({ message: "Error interno de configuración" });
    }
    const rootUrl = 'https://accounts.google.com/o/oauth2/v2/auth'; //ojo tema versió
    const options = new URLSearchParams({ // codi amb el que google respon
        redirect_uri: process.env.GOOGLE_OAUTH_REDIRECT_URL!,
        client_id: process.env.GOOGLE_CLIENT_ID!,
        access_type: 'offline',
        response_type: 'code',
        prompt: 'consent',
        scope: 'https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email openid',
        
    });
    const fullUrl= `${rootUrl}?${options.toString()}`;
    console.log("Redireccionando a:", fullUrl); 
    res.redirect(fullUrl);
};

const googleAuthCallback = async (req: Request, res: Response) => {
    try {
        const code = req.query.code as string;
        
        if (!code) {
            return res.status(400).json({ message: 'Código de autorización faltante' });
        }

        const authData = await googleAuth(code);
        
        if (!authData) {
            return res.redirect('/login?error=authentication_failed');
        }
        
        console.log(authData.accessToken)
        // Configurar cookies no https (secure)--> acces des del web.
        res.cookie('token', authData.accessToken, {
            httpOnly: true,
            secure: false, 
            sameSite: 'none',
            maxAge: 86400000 // 1 día
        });  
        console.log(authData.accessToken);
        res.redirect(`http://localhost:4200/?token=${authData.refreshToken}`);   
    } catch (error: any) {
        console.error('Error en callback de Google:', error);
        res.redirect('/login?error=server_error');
    }
};

const refreshTokenHandler = async (req: Request, res: Response) => {
    console.log('Cookies recibidas:', req.cookies); // Debug
    
    const refreshToken = req.cookies?.refreshToken || req.body?.refreshToken;
    
    if (!refreshToken) {
        console.error('No se recibió refresh token');
        return res.status(401).json({ 
            message: 'Refresh token required',
            receivedCookies: req.cookies // Para debug
        });
    }

    try {
        const decoded: any = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET!);
        console.log('Token decodificado:', decoded); // Debug

        // Verifica que el usuario exista
        const user = getUserByMail(decoded.email);
        if (!user) {
            return res.status(401).json({ message: 'User not found' });
        }

        const newAccessToken = generateRefreshToken(user);
        
        return res.json({ 
            success: true,
            refreshToken: newAccessToken 
        });
        
    } catch (error: any) {
        console.error('Error al verificar refresh token:', error.message);
        return res.status(401).json({ 
            message: 'Invalid refresh token',
            error: error.message // Solo para desarrollo
        });
    }
};

export { registerCtrl, loginCtrl,googleAuthCtrl, googleAuthCallback,refreshTokenHandler };