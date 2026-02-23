const express               =  require('express'),
      expSession            =  require("express-session"),
      app                   =  express(),
      mongoose              =  require("mongoose"),
      passport              =  require("passport"),
      bodyParser            =  require("body-parser"),
      LocalStrategy         =  require("passport-local"),
      passportLocalMongoose =  require("passport-local-mongoose"),
      User                  =  require("./models/user"),
      mongoSanitize         =  require('express-mongo-sanitize'),
      rateLimit             =  require('express-rate-limit'),
      xss                   =  require('xss-clean'),
      helmet                =  require('helmet')

//Connecting database
mongoose.connect("mongodb://localhost/auth_demo");

app.use(expSession({
    secret:"mysecret",       //decode or encode session
    resave: false,          
    saveUninitialized: true,
    cookie: {
        httpOnly: true,
        secure: true,
        maxAge: 1 * 60 * 1000 // 10 minutes
    }
}))

passport.serializeUser(User.serializeUser());       //session encoding
passport.deserializeUser(User.deserializeUser());   //session decoding
passport.use(new LocalStrategy(User.authenticate()));
app.set("view engine","ejs");
app.use(bodyParser.urlencoded(
      { extended:true }
))
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static("public"));


//=======================
//      O W A S P
//=======================

// Data Sanitization against NoSQL Injection Attacks
app.use(mongoSanitize());

// Preventing Brute Force & DOS Attacks - Rate Limiting
const limit = rateLimit({
    max: 100,               // max requests
    windowMs: 60 * 60 * 1000, // 1 Hour of 'ban' / lockout
    message: 'Too many requests' // message to send
});
app.use('/login', limit);   // Setting limiter on specific route
app.use('/register', limit);

// Preventing DOS Attacks - Body Parser
app.use(express.json({ limit: '10kb' })); // Body limit is 10kb

// Data Sanitization against XSS attacks
app.use(xss());

// Helmet to secure connection and data
app.use(helmet());


//=======================
//      R O U T E S
//=======================
app.get("/", (req,res) =>{
    res.render("home");
})
app.get("/userprofile" ,(req,res) =>{
    res.render("userprofile");
})
//Auth Routes
app.get("/login",(req,res)=>{
    res.render("login");
});
app.post("/login",passport.authenticate("local",{
    successRedirect:"/userprofile",
    failureRedirect:"/login"
}),function (req, res){
});
app.get("/register",(req,res)=>{
    res.render("register", { errors: [] });
});

app.post("/register",(req,res)=>{
    const { username, password, email, phone } = req.body;
    const errors = [];

    // Username validation: min 4 chars, alphanumeric + underscore only
    if (!username || username.trim().length < 4) {
        errors.push("Username must be at least 4 characters long.");
    }
    if (username && !/^[a-zA-Z0-9_]+$/.test(username)) {
        errors.push("Username can only contain letters, numbers, and underscores.");
    }

    // Password validation: min 8 chars, uppercase, number, special char
    if (!password || password.length < 8) {
        errors.push("Password must be at least 8 characters long.");
    }
    if (password && !/[A-Z]/.test(password)) {
        errors.push("Password must contain at least one uppercase letter.");
    }
    if (password && !/[0-9]/.test(password)) {
        errors.push("Password must contain at least one number.");
    }
    if (password && !/[!@#$%^&*]/.test(password)) {
        errors.push("Password must contain at least one special character (!@#$%^&*).");
    }

    if (errors.length > 0) {
        return res.render("register", { errors });
    }
    
    User.register(new User({username: req.body.username, email: req.body.email, phone: req.body.phone}), req.body.password, function(err, user){
        if(err){
            console.log(err);
            return res.render("register", { errors: [err.message] });
        }
        passport.authenticate("local")(req,res,function(){
            res.redirect("/login");
        })    
    })
})
app.get("/logout",(req,res)=>{
    req.logout();
    res.redirect("/");
});
function isLoggedIn(req,res,next) {
    if(req.isAuthenticated()){
        return next();
    }
    res.redirect("/login");
}

//Listen On Server
app.listen(process.env.PORT || 3000,function (err) {
    if(err){
        console.log(err);
    }else {
        console.log("Server Started At Port 3000");  
    }
});
