import express from "express";
import {
  loginUser,
  signupUser,
  logoutUser,
} from "../controllers/authController.js";
import { validateLogin, validateSignup } from "../middlewares/validateAuth.js";
import { protect } from "../middlewares/authMiddleware.js";

const router = express.Router();

router.post("/signup", validateSignup, signupUser);
router.post("/login", validateLogin, loginUser);
router.post("/logout", protect, logoutUser);
router.get("/validate", protect, (req, res) => {
  // Return user information based on the decoded token
  res.status(200).json({
    success: true,
    user: {
      id: req.user.id,
      role: req.user.role,
    },
  });
});

export default router;
