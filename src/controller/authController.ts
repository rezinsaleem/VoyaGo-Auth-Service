import jwt, { Secret, JwtPayload, TokenExpiredError, JsonWebTokenError } from 'jsonwebtoken';
import 'dotenv/config';

interface AuthTokenPayload extends JwtPayload {
  id: string;
  role: string;
}

interface RefreshTokenResponse {
  access_token?: string;
  refresh_token?: string;
  message?: string;
}

export class Authcontroller {
  isAuthenticated = async (
    call: { request: { token: string; requiredRole?: string } },
    callback: (error: any, result?: any) => void
  ): Promise<void> => {
    try {
      console.log('Validating token...');
      console.log(call.request);
      const token = call.request.token;
      const requiredRole = call.request.requiredRole || '';
      const secret = process.env.ACCESS_TOKEN as Secret;
  
      // Ensure token is provided
      if (!token) {
        return callback(null, { message: 'Token is required' });
      }
  
      // Ensure the secret is set
      if (!secret) {
        throw new Error('ACCESS_TOKEN secret is not set in environment variables');
      }
  
      const decodedToken = jwt.decode(token) as AuthTokenPayload | null;
    console.log('Decoded token (before verification):', decodedToken);
      // Verify the token
      const decoded = jwt.verify(token, secret) as AuthTokenPayload;
  
      console.log('Decoded token:', decoded);  // Log for debugging
  
      // Check if the required role matches the decoded role
      if (requiredRole && requiredRole !== decoded.role) {
        return callback(null, { message: 'Access denied. Insufficient role.' });
      }
  
      // Return user information if token is valid
      callback(null, { userId: decoded.id, role: decoded.role });
    } catch (e: any) {
      console.error("JWT verification error:", e.message);
      callback(e, { message: "Something went wrong in authentication" });
  }
  };
  
  
  refreshToken = async (call: { request: { token: string } }, callback: (error: any, result?: RefreshTokenResponse) => void): Promise<void> => {
    try {
        console.log('Refreshing token');
        const refreshToken = call.request.token;
        const refreshSecret = process.env.REFRESH_TOKEN as Secret;
        const accessSecret = process.env.ACCESS_TOKEN as Secret;

        if (!refreshSecret || !accessSecret) {
            throw new Error('Token secrets are not set in environment variables');
        }

        // Verify the refresh token
        const decoded = jwt.verify(refreshToken, refreshSecret) as AuthTokenPayload;
        console.log('Decoded refresh token:', decoded);

        // Check if the user has permission to refresh the token (optional check)
        if (decoded.role !== 'user') {  // Example of a permission check
            return callback(null, { message: 'User is not authorized to refresh the token.' });
        }

        console.log("token refreshed ");
        const refresh_token = jwt.sign({id: decoded.id, role: decoded.role}, process.env.REFRESH_TOKEN || 'Rezin' as Secret, {
            expiresIn: "7d"
        })
        const access_token = jwt.sign({id: decoded.id, role: decoded.role}, process.env.ACCESS_TOKEN ||"Rezin"as Secret, {
            expiresIn: "15m"
        })
        const response = {access_token, refresh_token}
        callback(null, response)
    } catch(e:any){
      console.log(e);  
      callback(e, {message:"something gone wrong in authentication "})
  }
};

}  