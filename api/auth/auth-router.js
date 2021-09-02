const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const jwt = require("jsonwebtoken")
const { JWT_SECRET } = require("../secrets"); // use this secret!
const model = require("../users/users-model")
const bcrypt = require("bcryptjs")

router.post("/register", validateRoleName, async (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }
    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
  try {
    const { username, password, role_name } = req.body
    const hashedPw = await bcrypt.hash(password, 4)
    console.log(role_name)
    const newUser = await model.add({
      username,
      password: hashedPw,
      role_name,
    })
    res.status(201).json({
      user_id: newUser.user_id,
      username: newUser.username,
      role_name: newUser.role_name
    })
  } catch (err) {
    next(err)
  }
});


router.post("/login", checkUsernameExists, async (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }
    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }
    The token must expire in one day, and must provide the following information
    in its payload:
    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
  try {
    const { username, password } = req.body
    const user = await model.findBy({ username })
    const passwordValid = await bcrypt.compare(password, user[0].password)
    if (!passwordValid) {
      return res.status(401).json({
        message: "Invalid Credentials"
      })
    }
    const token = jwt.sign({
      subject: user[0].user_id,
      username: user[0].username,
      role_name: user[0].role_name,
    }, JWT_SECRET, { expiresIn: "1d" });

    res.cookie = ("token", token)
    res.status(200).json({
      message: `${user[0].username} is back!`,
      token: token,
    })
  } catch (err) {
    next(err)
  }
});

module.exports = router;
