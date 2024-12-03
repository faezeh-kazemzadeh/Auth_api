import jwt from "jsonwebtoken";

const generateAccessToken = (res, user) => {
  const token = jwt.sign( user , process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: "15m",
  });
  res.cookie("access_token", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV !== "development",
    sameSite: "strict",
    maxAge: 15 * 60 * 1000,
  });
};


const generateRefreshToken =(res,user)=>{
    const token = jwt.sign(user , process.env.REFRESH_TOKEN_SECRET,{
        expiresIn: "30d",
    })
    res.cookie("refresh_token", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV !== "development",
        sameSite: "strict",
        maxAge: 30 * 24 * 60 * 60 * 1000,
        });
}

const generateTokens = (res, user) => {
    const accessToken = generateAccessToken(res, user);
    const refreshToken = generateRefreshToken(res, user);
    return { accessToken, refreshToken };
  };
  
  export { generateAccessToken, generateRefreshToken, generateTokens };