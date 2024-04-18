import { Response, Request } from "express";
import asyncHandler from "express-async-handler";

export const logoutUser = asyncHandler(async (req: Request, res: Response) => {
  // Expire the cookie to logout
  res.cookie("token", "", {
      path: "/",
      httpOnly: true,
      expires: new Date(0), // expire now
      sameSite: "none",
      secure: true,
  });

  //Send Json Response
  res.status(200).json({ message: "User Logout Successfully" });
});