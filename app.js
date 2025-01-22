const express = require("express");
const app = express();
const userModal = require("./modals/userModal");
const postModal = require("./modals/post");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');

app.set("view engine", "ejs");
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname,"public")));
app.use(cookieParser());

// Declare `storage` before using it in `upload`
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, './public/images/uploads');
    },
    filename: function (req, file, cb) {
        crypto.randomBytes(12, (err, bytes) => {
            if (err) return cb(err);
            const uniqueFilename = bytes.toString("hex") + path.extname(file.originalname);
            cb(null, uniqueFilename);
        });
    }
});
const upload = multer({ storage: storage });



app.get("/", (req, res) => {
  res.render("index");
});
app.get("/profile/upload", (req, res) => {
    res.render("profileuploaded");
});

app.post('/upload', isLoggedIn, upload.single("image"), async (req, res) => {
    try {
        let user = await userModal.findOne({ email: req.user.email });
        user.profilepic = req.file.filename;
        await user.save();

        res.redirect('/profile');
    } catch (err) {
        console.error("Error uploading profile picture:", err);
        res.status(500).send("An error occurred while uploading the profile picture.");
    }
});

// const upload = multer({ storage: storage });

// app.get("/test", (req, res) => {
//     res.render("test");
// });

// app.post('/upload', upload.single("image"), (req, res) => {
//     console.log(req.file); // Access uploaded file info here
//     res.send("File uploaded successfully!");
// });
  

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/profile", isLoggedIn, async (req, res) => {
  try {
    let user = await userModal
      .findOne({ email: req.user.email })
      .populate("posts");
    console.log(user.posts);
    if (!user) {
      return res.status(404).send("User not found");
    }

    res.render("profile", { user });
  } catch (err) {
    console.error("Error fetching user:", err);
    res.status(500).send("An error occurred while fetching user data");
  }
});
app.get("/like/:id", isLoggedIn, async (req, res) => {
  try {
    let post = await postModal.findOne({ _id: req.params.id }).populate("user");
    if (!post) {
      return res.status(404).send("Post not found");
    }

    const likeIndex = post.likes.indexOf(req.user.userId);
    if (likeIndex === -1) {
      post.likes.push(req.user.userId);
    } else {
      post.likes.splice(likeIndex, 1);
    }

    await post.save();

    res.redirect("/profile");
  } catch (err) {
    console.error("Error:", err);
    res.status(500).send("An error occurred while processing the like.");
  }
});
app.get('/edit/:id', isLoggedIn, async (req, res)=>{
    let post = await postModal.findOne({_id: req.params.id}).populate("user");
    res.render('edit', {post})
})
app.post('/update/:id', isLoggedIn, async (req, res)=>{
    let post = await postModal.findOneAndUpdate({_id: req.params.id}, {content: req.body.content})
    res.redirect('/profile');
})

app.post("/post", isLoggedIn, async (req, res) => {
  try {
    let user = await userModal.findOne({ email: req.user.email });
    let content = req.body.content;
    if (!content) return res.status(400).send("Content is required");

    let post = await postModal.create({
      user: user._id,
      content,
    });

    user.posts.push(post._id);
    await user.save();

    res.redirect("/profile");
  } catch (err) {
    console.error("Error creating post:", err);
    res.status(500).send("An error occurred while creating the post");
  }
});

app.post("/register", async (req, res) => {
  let { email, password, username, name, age } = req.body;
  let user = await userModal.findOne({ email });
  if (user) return res.status(500).send("User already registered");

  bcrypt.genSalt(10, (err, salt) => {
    bcrypt.hash(password, salt, async (err, hash) => {
      let user = await userModal.create({
        username,
        email,
        age,
        name,
        password: hash,
      });
      let token = jwt.sign({ email: email, userId: user._id }, "shhhh");
      res.cookie("token", token);
      res.send("Registered");
    });
  });
});

app.post("/login", async (req, res) => {
  let { email, password } = req.body;
  let user = await userModal.findOne({ email });
  if (!user) return res.status(500).send("User not found");

  bcrypt.compare(password, user.password, (err, result) => {
    if (result) {
      let token = jwt.sign({ email: email, userId: user._id }, "shhhh");
      res.cookie("token", token);
      res.status(200).redirect("/profile");
    } else {
      res.redirect("/login");
    }
  });
});

app.get("/logout", (req, res) => {
  res.cookie("token", "", { maxAge: 0 });
  res.redirect("/login");
});

function isLoggedIn(req, res, next) {
  if (!req.cookies.token) {
    return res.redirect("/login");
  }

  try {
    let data = jwt.verify(req.cookies.token, "shhhh");
    req.user = data;
    next();
  } catch (err) {
    res.cookie("token", "", { maxAge: 0 });
    return res.redirect("/login");
  }
}

app.listen(3000, () => console.log("Server running on http://localhost:3000"));
