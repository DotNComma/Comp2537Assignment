require("./utils.js");
require("dotenv").config();

const express = require("express");
const session = require("express-session");

const MongoStore = require("connect-mongo")

const bcrypt = require("bcrypt");
const saltRounds = 12;

const Joi = require("joi");

const port = process.env.PORT || 3000;
const app = express();

const expireTime = 1 * 60 * 60 * 1000;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;

app.use(express.urlencoded({extended: false}));

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database}`,
    crypto: {
        secret: mongodb_session_secret
    }
})

app.use(session({
    secret: node_session_secret,
        store: mongoStore,
        saveUninitialized: false,
        resave: true
}));

app.get("/", async (req, res) => {
    if(req.session.authenticated)
    {
        const result = await userCollection.find({email: req.session.email}).project({name: 1, id: 1}).toArray();
        const name = result[0].name;

        var html = `
        Hello ${name}!
        <form action='/members' method='get'>
            <button id='members' name='members'>Go to Members Area</button>
        </form>
        <form action='/signOut' method='get'>
            <button id='signout' name='signout'>Sign Out</button>
        </form>    
        `;
    }
    else 
    {
        var html = `
        <form action='/change' method='post'>
            <button id='signup' name='signup' value='1'>Sign up</button>
            <button id='login' name='login' value='1'>Log in</button>
        </form>
        `;
    }
    res.send(html);
});

app.post("/change", (req, res) => {
    if(req.body.signup == 1)
    {
        res.redirect("/signup");
        return; 
    }
    else if(req.body.login == 1)
    {
        res.redirect("/login");
        return;
    } 
});

app.get("/signup", (req, res) => {
    var html = `
    Create User
    <form action='/signupUser' method='post'>
        <input id='name' name='name' type='text' placeholder='name'></input>
        <input id='email' name='email' type='text' placeholder='email'></input>
        <input id='password' name='password' type='password' placeholder='password'></input>
        <button id='submitSignUp' name='submitSignUp'>Submit</button>  
    </form>
    `
    res.send(html);
})

app.post("/signupUser", async (req, res) => {
    var name = req.body.name;
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object(
        {
            name: Joi.string().alphanum().max(20).required(),
            email: Joi.string().max(20).required(),
            password: Joi.string().max(20).required()
        }
    )
    const validationResult = schema.validate({name, email, password});
    if(validationResult.error != null)
    {
        console.log("Validation Error Message: " + validationResult.error)
        res.redirect("/signup");
        return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({
        name: name,
        email: email,
        password: hashedPassword
    });
    console.log("User Inserted");

    res.redirect("/");
});

app.get("/login", (req, res) => {
    var html = `
    Log in
    <form action='/loginUser' method='post'>
        <input id='email' name='email' type='text' placeholder='email'></input>
        <input id='password' name='password' type='password' placeholder='password'></input>
        <button id='submitSignUp' name='submitSignUp'>Submit</button>  
    </form>
    `
    res.send(html);
})

app.post("/loginUser", async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object(
        {
            email: Joi.string().max(20).required(),
            password: Joi.string().max(20).required()
        }
    )
    const validationResult = schema.validate({email, password});
    if(validationResult.error != null)
    {
        console.log("Validation Error Message: " + validationResult.error);
        res.redirect("/login");
        return;
    }

    const result = await userCollection.find({email: email}).project({email: 1, password: 1, id: 1}).toArray();
    if(result.length != 1)
    {
        console.log("User not found");
        res.redirect("/login");
        return;
    }

    if(await bcrypt.compare(password, result[0].password)) 
    {
        req.session.authenticated = true;
        req.session.email = email;
        req.session.cookie.maxAge = expireTime;

        res.redirect("/members");
        return;
    }
    else
    {
        console.log("Incorrect Password");
        res.redirect("login");
        return;
    }
});

app.get("/members", async (req, res) => {
    if(!req.session.authenticated)
    {
        res.redirect("/login");
        return;
    }
    
    const result = await userCollection.find({email: req.session.email}).project({name: 1, id: 1}).toArray();
    const name = result[0].name;

    var html = `
    Welcome ${name}
    <form action="/signOut" method="get">
        <button id="signout" name="signout">Sign Out</button>
    </form>
    `;
    res.send(html);
});

app.get("/signOut", (req, res) => {
    req.session.destroy();
    res.redirect("/");
});

app.get("*", (req, res) => {
    res.status(404);
    res.send("Page not found - 404");
});  

app.listen(port, () => {
    console.log("Node application listening to port " + port);
})