import passport from "passport";
import { default as User, UserModel, AuthToken } from "../models/User";
import { Response, Request, NextFunction } from "express";
import { IVerifyOptions } from "passport-local";
// import { WriteError } from "mongodb";
import "../config/passport";
import { MappedError } from "express-validator/shared-typings";
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
    msg = { error: "Please enter a valid email and password." };
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
        msg = { error: "User with this email does not exist." };
        res.json(msg);
        return;
      }
      req.logIn(user, err => {
        if (err) {
          return res.json({
            error: "The email and password you entered is incorrect."
          });
        }

        res.json({ error: "Login success", token: "hello" });
        return;
      });
    }
  )(req, res, next);
};

// ########################################################################
export let signup = (req: Request, res: Response, next: NextFunction) => {
  let msg = {};
  req.assert("email", "Email is not valid").isEmail();
  req
    .assert("password", "Password must be at least 4 characters long")
    .len({ min: 4 });
  req.sanitize("email").normalizeEmail({ gmail_remove_dots: false });

  const errors = req.validationErrors();

  const err_msgs = [];
  if (errors) {
    errors.forEach(function (e) {
      err_msgs.push(e.msg);
    });
    return res.json({ error: err_msgs });
  }

  const user = new User({
    email: req.body.email,
    password: req.body.password
  });
  User.findOne({ email: req.body.email }, (err, existingUser) => {
    if (err) {
      return next(err);
    }
    if (existingUser) {
      msg = { error: true, message: "Account with that email address already exists." };
      return res.json(msg);
    }

    user.save(err => {
      if (err) {
        msg = { error: true, message: err };
        return res.json(msg);
      }

      msg = { error: false, message: "User created successfully." };
      return res.json(msg);
    });
  });
};
