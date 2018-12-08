import * as express from "express";
import passport from "passport";

import * as userController from "../controllers/user";

class MainRoutes {
  public router: express.Router = express.Router();
  public passportJWT = passport.authenticate('jwt', { session: false });

  constructor() {
    this.main();
  }

  private main(): void {

    //Login, Signup, ForgotPass, ResetPass
    this.router.route("/login", )
        .post(userController.postLogin);

    this.router.route("/signup")
        .post(userController.postSignup);

    this.router.route("/forgot", )
        .post(userController.postForgot);

    this.router.route("/reset/:token")
        .post(userController.postReset);


    //Authenticated
    this.router.route("/account/profile")
        .post(this.passportJWT, userController.postUpdateProfile);
    
    this.router.route("/account/password")
        .post(this.passportJWT, userController.postUpdatePassword);

    this.router.route("/account/delete")
        .post(this.passportJWT, userController.postDeleteAccount);

    this.router.route("/account/unlink/:provider")
        .post(this.passportJWT, userController.getOauthUnlink);

    //OAuth authentication routes. (Sign in)
    this.router.route("/auth/facebook")
        .get(passport.authenticate("facebook", { scope: ["email", "public_profile"] }));

    this.router.route("/auth/facebook/callback")
        .get(passport.authenticate("facebook", { failureRedirect: "/login" }));

  }
}

export const mainRoutes = new MainRoutes().router;
