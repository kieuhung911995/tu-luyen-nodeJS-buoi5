const express = require("express");
const morgan = require("morgan");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");

const validateToken = require("./validateToken");

dotenv.config();
const userModel = require("./user.schema");

const app = express();
const port = 3000;

app.use(morgan("combined"));
app.use(express.json());
app.use(express.urlencoded());
app.use(cors());

app.get("/ping", async (req, res) => {
  try {
    res.status(200).send("Kiem tra trang thai");
  } catch (error) {}
});

app.post("/login", async (req, res) => {
  try {
    const findUser = userModel.findOne({ username: `${req.body.username}` });
    const doc = await findUser.exec();
    if (!doc) {
      res.status(400).send("ko ton tai user nay");
    } else {
      //so sanh pass da ma hoa
      bcrypt.compare(req.body.password, doc.password, function (err, result) {
        if (!result) {
          res.status(404).send("sai password");
        } else {
          //accessToken
          const accessToken = jwt.sign(
            { id: doc.id, username: doc.username },
            process.env.ACCESS_TOKEN_SECRET,
            { expiresIn: 5 }
          ); //token het han sau 5s
          //refreshToken
          const refreshToken = jwt.sign(
            { id: doc.id, username: doc.username }, // payload
            process.env.ACCESS_TOKEN_SECRET, // secret key để tạo token
            {
              expiresIn: 1000, //Exprire time of refresh token
            }
          );
          //luu token vao db
          doc.accessToken = accessToken;
          doc.refreshToken = refreshToken;
          doc.save();
          res.send({ accessToken: accessToken, refreshToken: refreshToken });
        }
      });
    }
  } catch (error) {
    console.log(error);
  }
});

app.post("/logout", async (req, res) => {
  const { accessToken, refreshToken } = req.body;
  const user = await userModel.findOne({ accessToken, refreshToken });
  if (user) {
    user.accessToken = "";
    user.refreshToken = "";
    user.save();
  }
  res.send("logout thanh cong");
});

app.post("/register", async (req, res) => {
  try {
    //ma hoa email
    const salt = await bcrypt.genSalt(10);
    const hashPass = await bcrypt.hash(req.body.password, salt);

    const user = await userModel.create({
      username: `${req.body.username}`,
      password: `${hashPass}`,
    });
    res.send(user);
    console.log(req.body);
  } catch (error) {
    console.log(error);
  }
});

app.get("/dashboard", validateToken, async (req, res) => {
  const user = await userModel.find();
  res.send(user);
});

app.post("/refreshToken", async (req, res) => {
  try {
    /// Lay access token va refresh token
    const { accessToken, refreshToken } = req.body;
    //validate refreshtoken neu het han nhay xuong dong catch
    const verifyToken = jwt.verify(
      refreshToken,
      process.env.ACCESS_TOKEN_SECRET
    );
    //tim user trong db
    const user = await userModel.findOne(verifyToken.id);
    if (!user) {
      res.status(400).send("Can not find user");
    }
    //neu co user
    const newAccessToken = jwt.sign(
      { id: user.id, username: user.username }, // payload
      process.env.ACCESS_TOKEN_SECRET, // secret key để tạo token
      {
        expiresIn: 5, //Exprire time of access token
      }
    );

    const newRefreshToken = jwt.sign(
      { id: user.id, username: user.username }, // payload
      process.env.ACCESS_TOKEN_SECRET, // secret key để tạo token
      {
        expiresIn: 1000, //Exprire time of refresh token
      }
    );

    // Save token -> dùng để refresh token
    user.accessToken = newAccessToken;
    user.refreshToken = newRefreshToken;
    user.save();
    res
      .status(200)
      .send({ accessToken: newAccessToken, refreshToken: newRefreshToken });
  } catch (error) {
    res.status(402).send("refreshToken expired");
  }
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
