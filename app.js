"use-strict";

//////Dependencies//////
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const methodOverride = require("method-override");
// const User = require("./models/users.js")

//Passport Dependencies
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(
  bodyParser.urlencoded({
    extended: true,
  })
);
app.use(methodOverride("_method"));

app.use(
  session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

//DB Connection
mongoose.connect(
  process.env.MONGOCONNECTION,
  { useNewUrlParser: true, useUnifiedTopology: true }
);
mongoose.set("useCreateIndex", true);
mongoose.set("useFindAndModify", false);

//Schemas
//Secret Schemas
const secretSchema = new mongoose.Schema(
  {
    secretBody: String,
  },
  { timestamps: true }
);

//Secret Model
const Secret = new mongoose.model("Secret", secretSchema);

//User Schemas
const userSchema = new mongoose.Schema(
  {
    email: String,
    password: String,
    googleId: String,
    secret: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: "Secret"
    }],
  },
  { timestamps: true }
);

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//User Model - need to come after the passport plugin
const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "https://konfessions.herokuapp.com/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    function (accessToken, refreshToken, profile, cb) {
      console.log(profile);
      User.findOrCreate({username: profile.emails[0].value, googleId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

app.get("/", function (req, res) {
  res.render("home");
});

app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  }
);

app.get("/login", function (req, res) {
  res.render("login");
});

app.get("/register", function (req, res) {
  res.render("register");
});

app.get("/secrets", function (req, res) {
  Secret.find({}, function (err, foundSecrets) {
    if (err) {
      console.log(err);
    } else {
      if (foundSecrets) {
        sortedSecrets = foundSecrets.sort(function(x, y) {
          return y.updatedAt - x.updatedAt;
        });
        res.render("secrets", { allSecrets: sortedSecrets }); //foundUsers returns all user objects that have secrets
      }
    }
  });
});

app.get("/mysecrets", function (req, res) {
  User.findById(req.user.id).populate("secret").exec(function (err, foundUser) {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        res.render("mysecrets", { specificUser: foundUser });
        // console.log(req.user.id)
      }
    }
  })
});

//Submitting New Secret
app.get("/submit", function (req, res) {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", function (req, res) {
  const submittedSecretField = new Secret({
    secretBody: req.body.secret,
  });
  submittedSecretField.save();

  User.findById(req.user.id, function (err, foundUser) {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        foundUser.secret.push(submittedSecretField._id);
        foundUser.save(function () {
          res.redirect("/secrets");
        });
      }
    }
  });
});

app.get("/logout", function (req, res) {
  req.logout();
  res.redirect("/");
});

app.post("/register", function (req, res) {
  User.register(
    { username: req.body.username },
    req.body.password,
    function (err, user) {
      if (err) {
        console.log(err);
        res.redirect("/register");
      } else {
        passport.authenticate("local")(req, res, function () {
          res.redirect("/secrets");
        });
      }
    }
  );
});

app.post("/login", function (req, res) {
  const user = new User({
    username: req.body.username,
    password: req.body.password,
  });

  req.login(user, function (err) {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      });
    }
  });
});

///////Editing individual secret////////
app.get("/mysecrets/:id/edit", function (req, res) {
  // console.log(req.params.id);
  Secret.findById(req.params.id, function (err, foundSecret) {
    res.render("edit", { secret: foundSecret });
  });
});

app.put("/mysecrets/:id", function (req, res) {
  // console.log(req.body.changedSecret)
  const secretIdToUpdate = req.params.id;

  // Updating the secret within the secrets database
  Secret.findById(
    secretIdToUpdate, 
    function (err, foundSecret) {
      console.log(foundSecret);
      if (err) {
        console.log(err);
      } else {
        foundSecret.secretBody = req.body.changedSecret;
        foundSecret.save(); //saved updated seceret - tested and secret updated in the secrets database
        res.redirect("/mysecrets");
      }
    }
  );


});

///////Deleting individual secret///////

app.delete("/mysecrets", function (req, res) {
  const secretIdToDelete = req.body.deleteSecret; //returns body of the secret to delete - best to use ID but can't seem to register the ID at "**"
  console.log(secretIdToDelete);
  
  //Delete from secretsDB
  Secret.findByIdAndRemove(secretIdToDelete, function(err) {
    if (err) {
      console.log(err);
    } 
  });

  //Delete from userDB
  User.findByIdAndUpdate(req.user.id, {$pull: {secret: secretIdToDelete}}, function(err) {
    if (err) {
      console.log(err);
    } else {
      res.redirect("/mysecrets")
    }
  });
  // User.findById(req.user.id, function (err, foundUser) {
  //   console.log(foundUser.secret)
  //   if (err) {
  //     console.log(err);
  //   } else {
  //     const secretToDeletePosition = foundUser.secret.findIndex(
  //       (secret) => {//"**"
  //       console.log(secret);
  //       console.log(secret._id);
  //       return secret._id.toString() === secretIdToDelete} 
  //     );
  //     console.log(secretToDeletePosition)
  //     foundUser.secret.splice(secretToDeletePosition, 1);
  //     foundUser.save(function () {
  //       res.redirect("/mysecrets");
  //     });
  //   }
  // });

});

let port = process.env.PORT;
if (port == null || port == "") {
  port = 3000;
}

app.listen(port, function (req, res) {
  console.log("Server is up and running");
});
