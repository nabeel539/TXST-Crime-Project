import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import User from "../models/userModel.js"; // Import User model

// Officer & Investigator Signup
export const signupUser = async (req, res) => {
  try {
    const { name, email, mobile, password, role } = req.body;

    // Check if role is valid (officer/investigator only)
    if (!["officer", "investigator"].includes(role)) {
      return res.status(403).json({ success: false, message: "Invalid role" });
    }

    // Check if User already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res
        .status(400)
        .json({ success: false, message: "User already exists" });
    }

    // Hash the password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create new Officer/Investigator User
    const newUser = new User({
      name,
      email,
      mobile,
      password: hashedPassword,
      role, // Either officer or investigator
    });

    // Save User to the database
    await newUser.save();

    // Create token
    const token = jwt.sign(
      { id: newUser._id, role: newUser.role },
      process.env.JWT_SECRET,
      {
        expiresIn: "30d",
      }
    );

    res.status(201).json({
      success: true,
      message: "Signup Successful",
      token,
      role: newUser.role,
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

// Officer & Investigator Login
export const loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check if the user exists
    const existingUser = await User.findOne({ email });

    if (!existingUser) {
      return res
        .status(404)
        .json({ success: false, message: "Invalid email or password" });
    }

    // Compare password with hashed password
    const isMatch = await bcrypt.compare(password, existingUser.password);
    if (!isMatch) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid email or password" });
    }

    // Generate JWT Token
    const token = jwt.sign(
      { id: existingUser._id, role: existingUser.role },
      process.env.JWT_SECRET,
      { expiresIn: "30d" }
    );

    // Send response
    res.status(200).json({
      success: true,
      message: "Login successful",
      token,
      role: existingUser.role,
      user: {
        id: existingUser._id,
        name: existingUser.name,
        email: existingUser.email,
        role: existingUser.role,
      },
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

// Logout User
export const logoutUser = async (req, res) => {
  try {
    // Since we're using JWT, we don't need to do anything server-side
    // The client should remove the token from storage
    res.status(200).json({
      success: true,
      message: "Logged out successfully",
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};
