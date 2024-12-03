import mongoose from "mongoose";
import Joi from "joi";
import { joiPasswordExtendCore } from "joi-password";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import crypto from "crypto";

const joiPassword = Joi.extend(joiPasswordExtendCore);

const UserSchema = mongoose.Schema(
  {
    email: {
      type: String,
      minlength: 12,
      maxlength: 250,
      required: true,
      unique: true,
    },
    firstname: {
      type: String,
      minlength: 3,
      maxlength: 150,
    },
    lastname: {
      type: String,
      minlength: 3,
      maxlength: 150,
    },
    phone: {
      type: String,
    },
    password: {
      type: String,
      minlength: 5,
      maxlength: 100,
      trim: true,
      required: function () {
        return !this.googleId; 
      },
    },
    roles: {
      type: [String],
      enum: ["admin", "user", "moderator", "guest"],
      default: "user",
    },
    active: {
      type: Boolean,
      default: false,
    },
    resetPasswordToken: String,
    resetPasswordExpires: Date,
    googleId: {
      type: String,
      unique: true,
      sparse: true, 
    },
  },
  { timestamps: true }
);

UserSchema.statics.validateUser = (user) => {
  const schema = Joi.object({
    firstname: Joi.string().min(3).max(150),
    lastname: Joi.string().min(3).max(150),
    phone: Joi.string(),
    email: Joi.string().min(12).max(250).required().email(),
    roles: Joi.array().items(
      Joi.string().valid("admin", "user", "moderator", "guest")
    ),
    password: joiPassword
      .string()
      .minOfSpecialCharacters(1)
      .minOfLowercase(1)
      .minOfUppercase(1)
      .minOfNumeric(2)
      .noWhiteSpaces()
      .onlyLatinCharacters()
      .required()
      .messages({
        "password.minOfUppercase":
          "{#label} should contain at least {#min} uppercase character",
        "password.minOfSpecialCharacters":
          "{#label} should contain at least {#min} special character",
        "password.minOfLowercase":
          "{#label} should contain at least {#min} lowercase character",
        "password.minOfNumeric":
          "{#label} should contain at least {#min} numeric character",
        "password.noWhiteSpaces": "{#label} should not contain white spaces",
        "password.onlyLatinCharacters":
          "{#label} should contain only latin characters",
      }),
    confirmPassword: Joi.string()
      .valid(Joi.ref("password")) 
      .required()
      .messages({
        "any.only": "Passwords do not match",
      }),
  });
  return schema.validate(user, { abortEarly: false });
};

UserSchema.statics.validateUserProfile = (user) => {
  const schema = Joi.object({
    firstname: Joi.string().min(3).max(150),
    lastname: Joi.string().min(3).max(150),
    
  });
  return schema.validate(user, { abortEarly: false });
};

UserSchema.pre("save", async function (next) {
  if (!this.isModified("password")) {
    next();
  }
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

UserSchema.methods.getResetPasswordToken = function(){
  
  const resetToken = crypto.randomBytes(20).toString('hex');
  this.resetPasswordToken= crypto.createHash('sha256').update(resetToken).digest('hex')
  this.resetPasswordExpires = Date.now() + 10 * 60 * 1000 
  return resetToken;
}

export const User = mongoose.model("User", UserSchema);

