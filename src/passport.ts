import passport from "passport";
const LocalStrategy = require("passport-local").Strategy;
import { default as User, UserModel, AuthToken } from "./models/User";

passport.use(new LocalStrategy({
  usernameField: "email",
  passwordField: "password"
}, function (email: string, password: string, cb: Function) {
  const user = new User({email, password});
  return (user as any)
    .findOne({email, password})
    .then((user: any) => {
      if (!user) {
        return cb(undefined, false, {message: "Incorrect email or password."});
      }
      return cb(undefined, user, {message: "Logged In Successfully"});
    })
    .catch((err: any) => cb(err));
}));
