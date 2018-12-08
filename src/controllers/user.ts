import async from "async";
import crypto from "crypto";
import nodemailer from "nodemailer";
import passport from "passport";
import { default as User, UserModel, AuthToken } from "../models/User";
import { Request, Response, NextFunction } from "express";
import { IVerifyOptions } from "passport-local";
import { WriteError } from "mongodb";
import JWT from "jsonwebtoken";

import "../auth/passport";

/**
 * create Token
 * using specific format and keeping the profile data
 */
const signToken = (user: UserModel) => {
  return JWT.sign(
    {
      iss: "letsgiftme",
      sub: user.id,
      profile: user.profile,
      iat: new Date().getTime(), // current time
      exp: new Date().setDate(new Date().getDate() + 1) // current time + 1 day ahead
    },
    process.env.JWT_SECRET
  );
};

/**
 * POST /login
 * Sign in using email and password.
 */
export let postLogin = (req: Request, res: Response, next: NextFunction) => {
  req.assert("email", "Email is not valid").isEmail();
  req.assert("password", "Password cannot be blank").notEmpty();
  req.sanitize("email").normalizeEmail({ gmail_remove_dots: false });

  const errors = req.validationErrors();

  if (errors) {
    return res.status(403).json({ errors });
  }

  const user = new User({
    email: req.body.email,
    password: req.body.password
  });

  passport.authenticate(
    "local",
    (err: Error, user: UserModel, info: IVerifyOptions) => {
      if (err) {
        return next(err);
      }
      if (!user) {
        return res.status(403).json({ error: "User not found" });
      }
      const token = signToken(user);
      res.status(200).json({ token });
    }
  )(req, res, next);
};

/**
 * POST /signup
 * Create a new local account.
 */
export let postSignup = async(req: Request,res: Response,next: NextFunction) => {
  req.assert("email", "Email is not valid").isEmail();
  req
    .assert("password", "Password must be at least 10 characters long")
    .len({ min: 10 });
  req
    .assert("confirmPassword", "Passwords do not match")
    .equals(req.body.password);
  req.sanitize("email").normalizeEmail({ gmail_remove_dots: false });

  const errors = req.validationErrors();

  if (errors) {
    return res.status(403).json({ errors });
  }

  const user = new User({
    email: req.body.email,
    password: req.body.password
  });

  const foundUser = await User.findOne({ email: req.body.email });
  if (foundUser) {
    return res.status(403).json({ error: "Email is already in use" });
  }

  await user.save();

  const token = signToken(user);
  res.status(200).json({ token });
};


/**
 * POST /reset/:token
 * Process the reset password request.
 */
export let postReset = (req: Request, res: Response, next: NextFunction) => {
  req
    .assert("password", "Password must be at least 10 characters long.")
    .len({ min: 10 });
  req.assert("confirm", "Passwords must match.").equals(req.body.password);

  const errors = req.validationErrors();

  if (errors) {
    return res.status(403).json({ errors });
  }

  async.waterfall(
    [
      function resetPassword(done: Function) {
        User.findOne({ passwordResetToken: req.params.token })
          .where("passwordResetExpires")
          .gt(Date.now())
          .exec((err, user: any) => {
            if (err) {
              return res.status(403).json({ err });
            }
            if (!user) {
              return res.status(403).json({ "message": "User can not be found." });
            }
            user.password = req.body.password;
            user.passwordResetToken = undefined;
            user.passwordResetExpires = undefined;
            user.save((err: WriteError) => {
              if (err) {
                return res.status(403).json({ err });
              }
            });
          });
      },
      function sendResetPasswordEmail(user: UserModel, done: Function) {
        const transporter = nodemailer.createTransport({
          service: "SendGrid",
          auth: {
            user: process.env.SENDGRID_USER,
            pass: process.env.SENDGRID_PASSWORD
          }
        });
        const mailOptions = {
          to: user.email,
          from: "letsgiftme@gmail.com",
          subject: "Your password has been changed",
          text: `Hello,\n\nThis is a confirmation that the password for your account ${
            user.email
          } has just been changed.\n`
        };
        transporter.sendMail(mailOptions, err => {
          done(err);
        });
      }
    ],
    err => {
      if (err) {
        return res.status(403).json({ err });
      }
      res.status(200).json({ "message": "Password has been changed." });
    }
  );
};

/**
 * POST /forgot
 * Create a random token, then the send user an email with a reset link.
 */
export let postForgot = (req: Request, res: Response, next: NextFunction) => {
  req.assert("email", "Please enter a valid email address.").isEmail();
  req.sanitize("email").normalizeEmail({ gmail_remove_dots: false });

  const errors = req.validationErrors();

  if (errors) {
    return res.status(403).json({ errors });
  }

  async.waterfall(
    [
      function createRandomToken(done: Function) {
        crypto.randomBytes(16, (err, buf) => {
          const token = buf.toString("hex");
          done(err, token);
        });
      },
      function setRandomToken(token: AuthToken, done: Function) {
        User.findOne({ email: req.body.email }, (err, user: any) => {
          if (err) {
            return res.status(403).json({ err });
          }
          if (!user) {
            return res.status(403).json({ "message": "User can not be found." });
          }
          user.passwordResetToken = token;
          user.passwordResetExpires = Date.now() + 3600000; // 1 hour
          user.save((err: WriteError) => {
            done(err, token, user);
          });
        });
      },
      function sendForgotPasswordEmail(
        token: AuthToken,
        user: UserModel,
        done: Function
      ) {
        const transporter = nodemailer.createTransport({
          service: "SendGrid",
          auth: {
            user: process.env.SENDGRID_USER,
            pass: process.env.SENDGRID_PASSWORD
          }
        });
        const mailOptions = {
          to: user.email,
          from: "letsgiftme@gmail.com",
          subject: "Reset your password on Hackathon Starter",
          text: `You are receiving this email because you (or someone else) have requested the reset of the password for your account.\n\n
          Please click on the following link, or paste this into your browser to complete the process:\n\n
          http://${req.headers.host}/reset/${token}\n\n
          If you did not request this, please ignore this email and your password will remain unchanged.\n`
        };
        transporter.sendMail(mailOptions, err => {
          done(err);
        });
      }
    ],
    err => {
      if (err) {
        return res.status(403).json({ err });
      }
      return res.status(200).json({ "message": "E-mail with has been sent to the provided e-mail address." });
    }
  );
};




/**
 * POST /account/profile
 * Update profile information.
 */
export let postUpdateProfile = (req: Request,res: Response,next: NextFunction) => {

  User.findById(req.user.id, async(err, user: UserModel) => {
    if (err) {
      return next(err);
    }
    user.email = req.body.email || "";
    user.profile.name = req.body.name || "";
    user.profile.gender = req.body.gender || "";
    user.profile.location = req.body.location || "";
    user.profile.website = req.body.website || "";

    await user.save();

    const token = signToken(user);
    res.status(200).json({ token });

  });
};

/**
 * POST /account/password
 * Update current password.
 */
export let postUpdatePassword = (req: Request, res: Response, next: NextFunction) => {
  req
    .assert("password", "Password must be at least 4 characters long")
    .len({ min: 4 });
  req
    .assert("confirmPassword", "Passwords do not match")
    .equals(req.body.password);

  const errors = req.validationErrors();

  if (errors) {
    return res.status(403).json({ errors });
  }

  User.findById(req.user.id, (err, user: UserModel) => {
    if (err) {
      return res.status(403).json({ err });
    }
    user.password = req.body.password;
    user.save((err: WriteError) => {
      if (err) {
        return res.status(403).json({ errors });
      }
      const token = signToken(user);
      res.status(200).json({ token });
    });
  });
};

/**
 * POST /account/delete
 * Delete user account.
 */
export let postDeleteAccount = (req: Request, res: Response, next: NextFunction) => {
  User.remove({ _id: req.user.id }, err => {
    if (err) {
      return res.status(403).json({ err });
    }
    res.status(200).json({ "message" : "Account has been deleted." });
  });
};

/**
 * GET /account/unlink/:provider
 * Unlink OAuth provider.
 */
export let getOauthUnlink = (req: Request, res: Response, next: NextFunction) => {
  const provider = req.params.provider;
  User.findById(req.user.id, (err, user: any) => {
    if (err) {
      return res.status(403).json({ err });
    }
    user[provider] = undefined;
    user.tokens = user.tokens.filter(
      (token: AuthToken) => token.kind !== provider
    );
    user.save((err: WriteError) => {
      if (err) {
        return res.status(403).json({ err });
      }
      const token = signToken(user);
      res.status(200).json({ token });
    });
  });
};
