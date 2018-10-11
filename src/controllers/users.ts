import { mongoose } from "mongoose";
import passport from "passport";
import { default as User, UserModel, AuthToken } from "../models/User";
import { Response, Request, NextFunction } from "express";
import { IVerifyOptions } from "passport-local";
import { WriteError } from "mongodb";
import "../config/passport";
const request = require("express-validator");

/**
 * POST /api
 * List of API examples.
 */
export let signin = (req: Request, res: Response, next: NextFunction) => {
  let msg = {};

  req.assert("email", "Email is not valid").isEmail();
  req.assert("password", "Password cannot be blank").notEmpty();
  req.sanitize("email").normalizeEmail({ gmail_remove_dots: false });

  const errors = req.validationErrors();

  if (errors) {
    msg = { error: "Email or password not correct." };
    res.json(msg);
    return;
  }

  passport.authenticate(
    "local",
    (err: Error, user: UserModel, info: IVerifyOptions) => {
      if (err) {
        return next(err);
      }
      if (!user) {
        // req.flash("errors", info.message);
        msg = { error: "User nahi mila" };
        res.json(msg);
        return;
      }
      req.logIn(user, err => {
        msg = err ? { error: "Ghalat login" } : { error: "Mil gaya" };

        res.json(msg);
        return;
      });
    }
  )(req, res, next);
};
