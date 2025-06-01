import { generateToken } from "../lib/utils.js";
import User from "../models/user.model.js";
import bcrypt from "bcryptjs";
import validator from "validator";
import cloudinary from "../lib/cloudinary.js";

export const signup = async (req, res) => {
  const { fullName, email, password } = req.body;
  try {
    //* verify no field is empty
    if (!fullName || !email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    //* verify password length
    if (password.length < 6) {
      return res.status(400).json({ message: "Password must be 6 characters" });
    }

    //* Verify Email is valid
    if (!validator.isEmail(email))
      return res.status(400).json({ message: "Email is not Valid" });

    //* find if email already exists in DB
    const user = await User.findOne({ email });
    if (user) return res.status(400).json({ message: "Email already exists" });

    //* generate salt for hashing
    const salt = await bcrypt.genSalt(10);

    //* generate hashed password
    const hashedPassword = await bcrypt.hash(password, salt);

    //* create new user
    const newUser = new User({
      fullName,
      email,
      password: hashedPassword,
    });

    if (newUser) {
      //* generate JWT token
      generateToken(newUser._id, res);
      await newUser.save();

      res.status(201).json({
        _id: newUser._id,
        fullName: newUser.fullName,
        email: newUser.email,
        profilePic: newUser.profilePic,
      });
    } else {
      res.status(400).json({ message: "Invalid User data" });
    }
  } catch (error) {
    console.log("Error in signup controller: ", error.message);
    res.status(500).json({ message: "Internal Server Error!" });
  }
};

export const login = async (req, res) => {
  const { email, password } = req.body;

  try {
    //* verify user exist in DB
    const user = await User.findOne({ email });

    //* Send error if user not exist
    if (!user) {
      res.status(400).json({ message: "Invalid Credentials" });
    }

    //* verify password
    const isPasswordCorrect = await bcrypt.compare(password, user.password);

    //* Send error if password not correct
    if (!isPasswordCorrect) {
      res.status(400).json({ message: "Invalid Credentials" });
    }

    //* generate JWT token
    generateToken(user._id, res);

    res.status(200).json({
      _id: user._id,
      fullName: user.fullName,
      email: user.email,
      profilePic: user.profilePic,
    });
  } catch (error) {
    console.log("Error in signup controller: ", error.message);
    res.status(500).json({ message: "Internal Server Error!" });
  }
};

export const logout = (req, res) => {
  try {
    res.cookie("jwt", "", {
      maxage: 0,
    });
    res.status(200).json({ message: "Logged Out Successfully" });
  } catch (error) {
    console.log("Error in signup controller: ", error.message);
    res.status(500).json({ message: "Internal Server Error!" });
  }
};

export const updateProfile = async (req, res) => {
  try {
    const { profilePic } = req.body;
    const userId = req.user._id;

    if (!profilePic) {
      res.status(400).json({ message: "Profile Picture is required" });
    }

    const uploadResponse = await cloudinary.uploader.upload(profilePic);
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      {
        profilePic: uploadResponse.secure_url,
      },
      { new: true }
    );

    return res.status(200).json(updatedUser);
  } catch (error) {
    console.log("Error in update profile: ", error.message);
    res.status(500).json({ message: "Internal Server Error!" });
  }
};

export const checkAuth = (req, res) => {
  try {
    return res.status(200).json(req.user);
  } catch (error) {
    console.log("Error in check auth controller: ", error.message);
    res.status(500).json({ message: "Internal Server Error!" });
  }
};
