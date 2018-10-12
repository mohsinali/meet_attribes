import passport from "passport";
const LocalStrategy = require("passport-local").Strategy;
import { default as User, UserModel, AuthToken } from "./models/User";

passport.use(
  new LocalStrategy(
    {
      usernameField: "email",
      passwordField: "password"
    },
    function(email: string, password: string, cb) {
      const user = new User({ email, password });
      return user
        .findOne({ email, password })
        .then(user => {
          if (!user) {
            return cb(null, false, { message: "Incorrect email or password." });
          }
          return cb(null, user, { message: "Logged In Successfully" });
        })
        .catch(err => cb(err));
    }
  )
);
