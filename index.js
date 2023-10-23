import express from "express";
import path from "path";
import mongoose from "mongoose";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken" 
import bcrypt from "bcrypt"


const app = express();

//connection of db
mongoose
  .connect("mongodb://127.0.0.1:27017", {
    dbName: "backend",
  })
  .then(() => console.log("database connected"))
  .catch((e) => console.log(e));

//we cannot use middle ware directly
//we have to use app.use()
app.use(express.static(path.join(path.resolve(), "public")));

//setting up view engine
app.set("view engine", "ejs");

const isAuthenticated = async(req, res, next) => {
  const { token } = req.cookies;

  //  check token exit or not
  if (token) {
    const decoded =  jwt.verify(token, "biruly")
    // res.render("logout");

    //find user in db
    req.user = await User.findById(decoded._id)
    next()
  } else {
    res.redirect("/login") 
  }
};
    
//middleware for url encoded
app.use(express.urlencoded({ extended: true }));

//for accessing cookies in server side
app.use(cookieParser());


// userSchema
const userSchema = new mongoose.Schema({
  name:{
    type:String
  },

  email:{
    type:String
  },

  password:{
    type:String
  }
})

const User = mongoose.model("users", userSchema)



//create route
app.get("/", isAuthenticated,  (req, res) => {
   res.render("logout", {name: req.user.name});
   //res.render("index")
});

//get login page

app.get("/login",  (req, res) => {
   res.render("login");
  //res.render("index")
});

//get register page
app.get("/register",  (req, res) => {
  res.render("register");
 //res.render("index")
});

//get method for logout
app.get("/logout", (req, res) => {
 
  res.cookie("token", null, {
    expires: new Date(Date.now()),
  });
  res.redirect("/");
}); 




//post method for register
app.post("/register",async(req, res) => {

   const {name, email} = req.body 
   
    
  //user is exist or not
  const isUserExist = await User.findOne({email })
  if(isUserExist){
    return res.redirect("/login");
  } 

  //hash password
  const hashPassword = await bcrypt.hash(req.body.password, 10)

  //create entry on db

  const user = await User.create({
    name, email, password: hashPassword
  })

  console.log(user)

  // create sign in with jwt 
  const token = jwt.sign({_id: user._id},"biruly")
 
  //store data in cookie
  res.cookie("token", token, {
    httpOnly: true,
    expires: new Date(Date.now() + 60 * 1000),
  });

  res.redirect("/");
});


//post method for login
app.post("/login", async(req, res)=>{
   const {email, password} = req.body

   //find user in db
   let user = await User.findOne({email})
   if(!user) return res.redirect("/register ")

   const isMatch  = await bcrypt.compare(password, user.password)
   if(!isMatch){
    return res.render("login", {email, message:"incorrect password"})
   }

    // create sign in with jwt 
  const token = jwt.sign({_id: user._id},"biruly")
 
  //store data in cookie
  res.cookie("token", token, {
    httpOnly: true,
    expires: new Date(Date.now() + 60 * 1000),
  });

  res.redirect("/");
})



app.listen(5000, () => {
  console.log("Server is working");
});
