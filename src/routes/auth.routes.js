import { Router } from "express";
import { registerUser } from "../controllers/auth-controllers.js";
import {
  emailVerificationMailgenContent,
  forhotpasswordMailgenContent,
  sendEmail,
} from "../utils/mail.js";
;



const router = Router();


router.route("/register").post(registerUser)

export default router;