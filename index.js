import express from "express"; // call express
import path from "path"; // path is a core module, no need to install it
import mongoose from "mongoose"; // call mongoose
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

// create our app with express
const app = express();

mongoose
  .connect("mongodb://localhost:27017", {
    dbName: "notes-backend",
  })
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.log(err));

const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
});

const User = mongoose.model("User", userSchema);

const users = [];

// Middlewares
app.use(express.static(path.join(path.resolve(), "public")));
app.use(express.urlencoded({ extended: true })); // for parsing application/x-www-form-urlencoded
app.use(cookieParser()); // for parsing cookies

// set up ejs for templating, either set this to ejs or use .ejs after the file name when rendering.
app.set("view engine", "ejs");

const isAuth = async (req, res, next) => {
  const { token } = req.cookies;
  if (token) {
    const decodedToken = jwt.verify(token, "1dayumay");
    req.user = await User.findById(decodedToken._id);

    next();
  } else {
    res.redirect("/login");
  }
};

app.get("/", isAuth, (req, res) => {
  res.render("logout", { name: req.user.name });
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  let user = await User.findOne({ email });

  if (!user) return res.redirect("/register");

  const isMatch = await bcrypt.compare(password, user.password);

  if (!isMatch) return res.render("login", { email, message: "incorrect password" });

  const token = jwt.sign({ _id: user._id }, "1dayumay");

  res.cookie("token", token, {
    httpOnly: true,
    expires: new Date(Date.now() + 60 * 1000), // 1 minute
  });
  res.redirect("/");
});

app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  let user = await User.findOne({ email });
  if (user) {
    return res.redirect("/login");
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  user = await User.create({
    name,
    email,
    password: hashedPassword,
  });

  const token = jwt.sign({ _id: user._id }, "1dayumay");

  res.cookie("token", token, {
    httpOnly: true,
    expires: new Date(Date.now() + 60 * 1000), // 1 minute
  });
  res.redirect("/");
});

app.get("/logout", (req, res) => {
  res.cookie("token", null, {
    httpOnly: true,
    expires: new Date(Date.now()), // 1 minute
  });
  res.redirect("/");
});

// start the server
app.listen(3000, () => {
  console.log("Server is running on port: 3000");
});
