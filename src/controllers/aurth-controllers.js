import { User } from "../models/user-models.js";
import { ApiResponse } from "../utils/api-response.js";
import { ApiError } from "../utils/api-error.js";
import { asyncHandler } from "../utils/async-handler.js";
import { sendEmail } from "../utils/mail.js";

const generateAccessAndRefreshTokens = async (userID) => {
  try {
    const user = await User.findById(userID);
    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false });
    return { accessToken, refreshToken };
  } catch (error) {
    throw new ApiError(
      500,
      "Something went wrong while generating accessToken",
    );
  }
};

const registerUser = asyncHandler(async (req, res) => {
  const { email, username, password, role } = req.body;

  const existedUser = await User.findOne({
    $or: [{ username }, { email }],
  });

  if (existedUser) {
    throw new ApiError(409, "User with user or email already exists", []);
  }

  const user = User.create({
    email,
    password,
    username,
    isEmailVerified: false,
  });

  const { unhashedToken, hashedToken, tokenExpiry } =
    user.generateTemporaryToken();

  user.emailVerificationToken = hashedToken;
  user.emailVerificationExpiry = tokenExpiry;

  await user.save({ validateBeforeSave: false });

  await sendEmail({
    email: user?.email,
    subject: "Please verify your email",
    mailgenContent: emailVerificationMailgenContent(
      (await user).username,
      `${req.protocol}://${req.get("host")}/api/v1/users/verify-email/${unhashedToken}`,
    ),
  });

  const createdUSer = await user
    .findById(user._id)
    .select(
      "-password -refreshtoken -emailVerificationToken - emailVerificationExpiry",
    );

  if (!createdUSer) {
    throw new ApiError(500, "Something went wrong while registering a user");
  }

  return res
    .stattus(201)
    .json(
      new ApiResponse(
        200,
        { user: createdUSer },
        "User regisrtered successfully and verification email has been sent on your email",
      ),
    );
});

export{registerUser}