const express = require("express")
const router = express.Router()
const bcrypt = require('bcryptjs')


// User model
const User = require('../models/User');
const passport = require('passport');

// Login Route
router.get("/login",(req,res) => {
    res.render("login")
})

// Register Route
router.get("/register",(req,res) => {
    res.render("register")
})

router.post("/register",(req,res) => {
    
    const {name,email,password1,password2} = req.body;
    let errors = [];

    // Check Required fields
    if(!name || !email || !password1 || !password2){
        errors.push({msg:"Please fill in all fields"})
    }

    // Check Passwords match

    if(password1 !== password2){
        errors.push({msg:"Password do not match"})
    }

    // Check password length
    if(password1.length < 6){
        errors.push({msg:"Password should be atleast 6 characters"})
    }

    if(errors.length > 0){
        res.render("register",{errors,name,email,password1,password2})
    }else{
        // Validation Passed
        User.findOne({email:email}).then((user) => {
            if(user) {
                // User Exists
                errors.push({msg:"Email is already Exists"})
                res.render("register",{
                    errors,
                    name,
                    email,
                    password1,
                    password2
                })
            }else{
                const newUser = new User({
                    name:name,
                    email:email,
                    password:password1
                })

                // Hash Password
                bcrypt.genSalt(10,(err,salt) => bcrypt.hash(newUser.password,salt,(err,hash) => {
                    if(err) throw err;
                     
                    // Set Password to hashed
                    newUser.password = hash;

                    // Save user
                    newUser.save()
                    .then((user) => {
                        req.flash("success_msg","You are now registered and can log in")
                        res.redirect("/users/login")
                    })
                    .catch((err) => console.log(err ))
                }))
            }
        })
        
        
    }

})


// Login Route
router.post("/login",(req,res,next) => {
    passport.authenticate("local",{
        successRedirect:"/dashboard",
        failureRedirect:"/users/login",
        failureFlash:true
    })(req,res,next);
})

// Logout Route
router.get("/logout",(req,res) => {
    req.logout()
    req.flash("success_msg","You are Logged out");
    res.redirect("/users/login")
})

module.exports = router