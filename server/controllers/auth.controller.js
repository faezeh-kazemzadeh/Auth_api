import _ from "lodash";
import bcrypt from "bcrypt";
import crypto from "crypto";

import asyncHandler from "express-async-handler";
import { User } from "../models/user.model.js";
import { errorHandler } from "../utils/error.js";
import { generateTokens } from "../utils/token.js";
import { sendEmail } from "../utils/sendEmail.js";
//  @Destination    Register User
//  @Route          POST /api/users/signup
//  @Access         Public
export const signup = asyncHandler(async (req, res, next) => {
  const { error } = User.validateUser(req.body);
  if (error) return next(errorHandler(400, error.details[0].message));
  let user = await User.findOne({ email: req.body.email });
  if (user) return next(errorHandler(400, "User exist"));

  user = new User(
    _.pick(req.body, ["firstname", "lastname", "email", "password", "phone"])
  );
  await user.save();

  res.status(200).json(_.pick(user, ["firstname", "lastname", "email"]));
});

//  @Destination    Authenticate User
//  @Route          POST /api/users/signin
//  @Access         Public
export const signin = asyncHandler(async (req, res, next) => {
  const { email, password } = req.body;
  const validUser = await User.findOne({ email });
  if (validUser && (await bcrypt.compare(password, validUser.password))) {
    generateTokens(res, { _id: validUser._id, role: validUser.roles });
    const { password: pass, ...userDetails } = validUser._doc;
    res.status(200).json({
      success: true,
      message: "Login successful",
      user: userDetails,
    });
  } else {
    return next(
      errorHandler(401, "Please provide a valid email address and password.")
    );
  }
});

//  @Destination    Logout User
//  @Route          POST /api/users/signout
//  @Access         Public
export const signout = asyncHandler(async (req, res) => {
  res.clearCookie("access_token", {
    httpOnly: true,
    secure: process.env.NODE_ENV !== "development",
    sameSite: "strict",
  });

  res.clearCookie("refresh_token", {
    httpOnly: true,
    secure: process.env.NODE_ENV !== "development",
    sameSite: "strict",
  });

  res.status(200).json({
    success: true,
    message: "Signed out successfully",
  });
});

//  @Destination    refreshToken
//  @Route          POST /api/auth/refreshtoken
//  @Access         Public
export const refreshToken = asyncHandler(async (req, res) => {
  const user = req.user;
  const { iat, exp, ...userData } = user;
  generateTokens(res, { _id: userData._id, role: userData.roles });

  res.status(200).json({ message: "Tokens refreshed successfully" });
});

//  @Destination    Forgot Password
//  @Route          POST /api/auth/forgot-password
//  @Access         Public
export const forgotPassword = asyncHandler(async (req, res, next) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user) {
    return next(errorHandler(404, "User not found"));
  }
  const resetToken = user.getResetPasswordToken();
  await user.save({ validateBeforeSave: false });
  const resetURL = `${req.protocol}://${req.get(
    "host"
  )}/reset-password/${resetToken}`;
  const message = `You are recieving this email because you (or someone else) has requested the reset of a password . Please make a PUT request to : \n\n ${resetURL}`;
  try {
    await sendEmail({
      email: user.email,
      subject: "Password reset Token",
      message,
    });
    res.status(200).json({ success: true });
  } catch (err) {
    console.log(err);
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save({ validateBeforeSave: false });
    return next(errorHandler(500, "Error sending email"));
  }
});

//  @Destination     Validate Token
//  @Route           POST /api/auth/validate-token/:token
//  @Access          Public
export const validateToken = asyncHandler(async (req, res, next) => {
  const { token } = req.params;


  const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

  const user = await User.findOne({
    resetPasswordToken: hashedToken,
    resetPasswordExpires: { $gt: Date.now() - 10 * 60 * 1000 },
  });

  if (!user) {
    return res.status(400).json({ message: "Invalid or expired token" });
  }

  res.status(200).json({ message: "Token is valid" });
});


//  @Destination     Reset Password
//  @Route           PUT /api/auth/reset-password
//  @Access          Public
export const resetPassword = asyncHandler(async (req, res, next) => {

  const resetPasswordToken = crypto
    .createHash("sha256")
    .update(req.params.resettoken)
    .digest("hex");
  const user = await User.findOne({
    resetPasswordToken,
    resetPasswordExpires: { $gt: Date.now() - 10 * 60 * 1000 },
  });
  if (!user) return next(errorHandler(400, "Invalid Token"));

  user.password = req.body.password;
  user.resetPasswordToken = undefined;
  user.resetPasswordExpires = undefined;
  await user.save();
  res.status(200).json({ success :true });
});


//  @Destination    Get User Pofile
//  @Route          GET /api/users/profile
//  @Access         Public
export const getUserProfile = asyncHandler(async (req, res, next) => {
  const user = await User.findById(req.user._id).select("-password");
  if (!user) return next(errorHandler(404, "User not found"));
  res.status(200).json(user);
});


//  @Destination    Update User Profile
//  @Route          PUT /api/users/profile
//  @Access         Private
export const updateUserProfile = asyncHandler(async (req, res, next) => {
  const { error } = User.validateUserProfile(req.body);
  if (error) return next(errorHandler(400, error.details[0].message));
  let updateFields = { ...req.body };

  const updatedUser = await User.findByIdAndUpdate(req.user._id, updateFields, {
    new: true,
  });
  const { password, ...rest } = updatedUser._doc;
  res.status(200).json({ success: true,
    message: "Profile Update successful",user: rest });
});