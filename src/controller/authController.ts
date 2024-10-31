import jwt, { Secret, JwtPayload, TokenExpiredError, JsonWebTokenError } from 'jsonwebtoken';
import 'dotenv/config';

interface AuthTokenPayload extends JwtPayload {
  id: string;
  role: string;
  type: string;
}

interface RefreshTokenResponse {
  access_token?: string;
  refresh_token?: string;
  message?: string;
}

export class Authcontroller {
  isAuthenticated = async (call: { request: { token: string } }, callback: (error: any, result?: any) => void): Promise<void> => {
    try {
      console.log('Validating token');
      const token = call.request.token;
      const secret = process.env.ACCESS_TOKEN as Secret;

      if (!secret) {
        throw new Error('ACCESS_TOKEN secret is not set in environment variables');
      }

      const decoded = jwt.verify(token, secret) as AuthTokenPayload;
      callback(null, { userId: decoded.id, role: decoded.role });
    } catch (error) {
      if (error instanceof TokenExpiredError) {
        console.log('Token expired:', error);
        callback(null, { message: 'Token expired, please login again.' });
      } else if (error instanceof JsonWebTokenError) {
        console.log('Invalid token:', error);
        callback(null, { message: 'Invalid token' });
      } else {
        console.log('Unexpected error in authentication:', error);
        callback(error, { message: 'Something went wrong in authentication' });
      }
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

      const decoded = jwt.verify(refreshToken, refreshSecret) as AuthTokenPayload;

      const newRefreshToken = jwt.sign(
        { id: decoded.id, role: decoded.role, type: 'refresh' },
        refreshSecret,
        { expiresIn: '7d' }
      );
      const newAccessToken = jwt.sign(
        { id: decoded.id, role: decoded.role, type: 'access' },
        accessSecret,
        { expiresIn: '15m' }
      );

      callback(null, { access_token: newAccessToken, refresh_token: newRefreshToken });
    } catch (error) {
      if (error instanceof TokenExpiredError) {
        console.log('Refresh token expired:', error);
        callback(null, { message: 'Refresh token expired, please re-authenticate.' });
      } else if (error instanceof JsonWebTokenError) {
        console.log('Invalid refresh token:', error);
        callback(null, { message: 'Invalid refresh token' });
      } else {
        console.log('Unexpected error in token refresh:', error);
        callback(error, { message: 'Something went wrong in token refresh' });
      }
    }
  };
}
