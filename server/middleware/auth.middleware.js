import jwt from "jsonwebtoken";
import { errorHandler } from "../utils/error.js";

const verifyToken = (req, res, next) => {
    const token = req.cookies?.access_token;
    if (!token) return next(errorHandler(401, " Unauthorized: Access Token Missing"));
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
      if (err) return next(errorHandler(403, "Invalid or Expired Access Token"));
  
      req.user = user;
      next();
    });
  };

  const verifyRefreshToken = (req, res, next) => {
    const refreshToken = req.cookies?.refresh_token;
  
    if (!refreshToken) {
      return next(errorHandler(401, "Unauthorized: Refresh Token Missing"));
    }
  
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
      if (err) {
        return next(errorHandler(403, "Invalid or Expired Refresh Token"));
      }
  
      req.user = user;
      next();
    });
  };


  const authorize = (requiredRoles) => (req, res, next) => {
    if (!req.user || !req.user.role) {
      return next(errorHandler(401, "Unauthorized: User roles not found"));
    }
  
    const hasRole = req.user.role.some((role) => requiredRoles.includes(role));
  
    if (!hasRole) {
      return next(errorHandler(403, "Forbidden: Insufficient Permissions"));
    }
  
    next();
  };

  export {verifyToken,verifyRefreshToken, authorize };