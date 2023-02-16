const mongoose = require("mongoose");
const Schema = mongoose.Schema;

mongoose.connect("mongodb://127.0.0.1:27017/tuhocMongoose");
// Tao schema dk model (kieu du lieu chuan cua tung document trong colletion)
const userSchema = new Schema({
  username: Schema.Types.String,
  password: Schema.Types.String,
  accessToken: Schema.Types.String,
  refreshToken: Schema.Types.String,
});

//Tao model (User collection dc tao trong db tuhocMongoose)
const userModel = mongoose.model("users", userSchema);
module.exports = userModel;
