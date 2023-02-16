const jwt = require("jsonwebtoken");
const userModel = require("./user.schema");

const validateToken = async (req, res, next) => {
  try {
    //lay token tu headers truyen vao tu dashboard
    const accessToken = req.headers.authorization.split(" ")[1];
    //validate accessToken neu het han nhay xuong dong catch
    const verifyToken = jwt.verify(
      accessToken,
      process.env.ACCESS_TOKEN_SECRET
    );
    // tim kiem user trong db xem co ko
    const user = await userModel.findOne(verifyToken.id); //co the dung verifyToken.id hoac username nhu da dang ky o jwt.sign
    if (!user) {
      res.status(400).send("No user found");
    }
    next();
  } catch (error) {
    console.log(error);
    //truong hop het han token se yeu cau FE bat status nay de gui them refreshToken
    res.status(401).send("accessToken expired");
  }
};
module.exports = validateToken;
