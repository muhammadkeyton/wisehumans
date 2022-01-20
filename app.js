require('dotenv').config()
const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const findOrCreate = require('mongoose-findorcreate');
const flash = require('connect-flash');



const app = express();

//serving static files
app.use(express.static(__dirname+'/public'));

//using ejs
app.set('view engine', 'ejs');

//using bodyparser
app.use(bodyParser.urlencoded({ extended: true }));

//setting up session
app.use(session({
  secret:process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}))

//initializing passport
app.use(passport.initialize());
app.use(passport.session());

//using flash to display error messages and more
app.use(flash());

//connecting to mongodb database
mongoose.connect(process.env.DATABASE_URI,{ useNewUrlParser: true });


//database schema
const wiseHumansSchema = new mongoose.Schema({
  username:String,
  password:String,
  posts:[{title:String,content:String,currentUser:String}],
  googleId:String,
  name:String,
  facebookId:String,
  displayName:String,
});

//setting up passport local passportLocalMongoose
wiseHumansSchema.plugin(passportLocalMongoose);
wiseHumansSchema.plugin(findOrCreate);


//data model
const wiseHumans = mongoose.model("User",wiseHumansSchema);

passport.use(wiseHumans.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  wiseHumans.findById(id, function(err, user) {
    done(err, user);
  });
});

//using google to authenticate
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret:process.env.CLIENT_SECRET,
    callbackURL: "https://wisehumans.herokuapp.com/auth/google/all-quotes"
  },
  function(accessToken, refreshToken, profile, cb) {
    wiseHumans.findOrCreate({ googleId: profile.id,name:profile.name.givenName }, function (err, user) {
      return cb(err, user);
    });
  }
));


//using facebook to authenticate
passport.use(new FacebookStrategy({
    clientID:process.env.FACEBOOK_APPID,
    clientSecret:process.env.FACEBOOK_APPSECRET,
    callbackURL: "https://wisehumans.herokuapp.com/auth/facebook/all-quotes"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    wiseHumans.findOrCreate({ facebookId: profile.id,displayName:profile.displayName }, function (err, user) {
      return cb(err, user);
    });
  }
));


app.get("/",(req,res)=>{
  res.render("home",{message:"no"});
});

//google oauth
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] })
);

app.get('/auth/google/all-quotes',
  passport.authenticate('google', { failureRedirect: '/sign-up' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/all-quotes');
});

//facebook aauth
app.get('/auth/facebook',
  passport.authenticate('facebook')
);

app.get('/auth/facebook/all-quotes',
  passport.authenticate('facebook', { failureRedirect: '/sign-up' }),
  function(req, res) {
    // Successful authentication, redirect all-quotes.
    res.redirect('/all-quotes');
});

app.get("/sign-in",(req,res)=>{
  res.render("sign-in-up",{method:"Sign in",route:"sign-in",message:"no"})
});
app.get("/sign-up",(req,res)=>{
  res.render("sign-in-up",{method:"Sign up",route:"sign-up",message:"no"})
});

app.get("/all-quotes",(req,res)=>{
  if(req.isAuthenticated()){
    wiseHumans.find({"posts":{$ne:null}},(err,foundUsers)=>{
      if(err){
        console.log(err);
      }else{
        if(foundUsers){
          res.render("quotes",{wiseUsers:foundUsers})
        }

      }

    });

  }else{
    res.redirect("/");
  }


});


app.get("/submit",(req,res)=>{
  if(req.isAuthenticated()){
    res.render("post");
  }else{
    res.redirect("/sign-in")
  }

});

app.get("/log-out",(req,res)=>{
  req.logout();
  res.redirect('/');
});




app.post('/', function(req, res, next) {
  const wiseHuman = new wiseHumans({
    username:req.body.username,
    password:req.body.password
  });

  wiseHumans.findOne({username:req.body.username },function (err,foundUser){

    if(err){
      console.log(err);
    }else{

      //checking if user exists and if passwords match and then using flash to show errors
      if(foundUser){

        foundUser.authenticate(req.body.password, function(err,model,passwordError){
            if(passwordError){
              req.flash("info","incorrect password! please check and try again.")
              res.render("home",{message:req.flash('info')[0]})
            } else{
              req.login(wiseHuman, function(err) {
                if(err){
                  console.log(err);
                  res.redirect("/")
                }else{
                  passport.authenticate("local")(req,res,function(){
                    res.redirect("/all-quotes")});
                }

            });

            }
        });

      }else{
        if(req.body.username && req.body.password){
          req.flash("info",`${req.body.username} was not found in our database! please sign up instead.`)
          res.render("sign-in-up",{method:"Sign up",route:"sign-up",message:req.flash('info')[0]})
        }else{
            req.flash("info","you can't login without entering your credentials.")
            res.render("home",{message:req.flash('info')[0]})
        }

      }

    }

  });

});



//signing in existing users and doing some validation
app.post("/sign-in",(req,res)=>{
  const wiseHuman = new wiseHumans({
    username:req.body.username,
    password:req.body.password
  });
  wiseHumans.findOne({username:req.body.username },function (err,foundUser){

    if(err){
      console.log(err);
    }else{

      //checking if user exists and if passwords match and then using flash to show errors
      if(foundUser){

        foundUser.authenticate(req.body.password, function(err,model,passwordError){
            if(passwordError){
              req.flash("info","incorrect password! please check and try again.")
              res.render("sign-in-up",{method:"Sign in",route:"sign-in",message:req.flash('info')[0]})
            } else{
              req.login(wiseHuman, function(err) {
                if(err){
                  console.log(err);
                  res.redirect("/")
                }else{
                  passport.authenticate("local")(req,res,function(){
                    res.redirect("/all-quotes")});
                }

            });

            }
        });

      }else{
        //
        if(req.body.username && req.body.password){
          req.flash("info",`${req.body.username} was not found in our database! please sign up instead.`)
          res.render("sign-in-up",{method:"Sign up",route:"sign-up",message:req.flash('info')[0]})
        }else{
            req.flash("info","you can't login without entering your credentials.")
            res.render("sign-in-up",{method:"Sign in",route:"sign-in",message:req.flash('info')[0]})
        }

      }

    }

  });



});


//signing up new users if they don't exist in the database
app.post("/sign-up",(req,res)=>{

  wiseHumans.findOne({username:req.body.username}, function (err,foundUser){

    if(err){
      console.log(err);
    }else{
      if(foundUser){
        req.flash("info",` an account for ${req.body.username} already exists! please sign in instead.`)
        res.render("home",{message:req.flash('info')[0]})
      }else{
        if(req.body.username && req.body.password){
          wiseHumans.register({username:req.body.username},req.body.password,function(err,user){
            if(err){
              console.log(err);
              res.redirect("sign-up")
            }else{
              passport.authenticate("local")(req,res,function(){
                res.redirect("/all-quotes")
              });
            }

          });

        }else{
          req.flash("info","you need to provide data for both fields.")
          res.render("sign-in-up",{method:"Sign up",route:"sign-up",message:req.flash('info')[0]})
        }



      }
    }

  });





});

app.post("/submit",(req,res)=>{

  //checking if user is authenticated and submitting the user's details together with the quote
  const currentUser = req.user

  if(req.isAuthenticated()){

    if(req.body.title && req.body.content){

      //checking what method the user signed or upwith and then getting their posts together with the current authenticated user
      if(currentUser.username){
        currentUser.posts.push({title:req.body.title,content:req.body.content,currentUser:currentUser.username});
      }else if(currentUser.name){
        currentUser.posts.push({title:req.body.title,content:req.body.content,currentUser:currentUser.name});

      }else{
        currentUser.posts.push({title:req.body.title,content:req.body.content,currentUser:currentUser.displayName});
      }

      // currentUser.posts.push({title:req.body.title,content:req.body.content,currentUser:req.user});
      currentUser.save((err)=>{
        if(err){
          console.log(err);
        }else{
          console.log("successfully added post for the current user");
        }

      })
      res.redirect("/all-quotes")

    }else{
      res.redirect("/submit")
    }


  }else{
    res.redirect("/sign-in")
  }


});


let port = process.env.PORT;
if (port == null || port == "") {
  port = 3000;
}

app.listen(port,(req,res)=>{
  console.log(`server running on port ${port}`);
});
