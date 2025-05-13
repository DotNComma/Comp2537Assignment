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

app.set('view engine', 'ejs');
app.use(express.urlencoded({extended: false}));
app.use(express.static('public'));

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

const navLinks = [
    {
        text: "Home",
        redirect: "/"
    },
    {
        text: "Sign Up",
        redirect: "/signup"
    },
    {
        text: "Log In",
        redirect: "/login"
    },
    {
        text: "Members",
        redirect: "/members"
    },
    {
        text: "Admin",
        redirect: "/admin"
    }
];

function isValidSession(req)
{
    if(req.session.authenticated)
    {
        return true;
    }
    return false;
}

function sessionValidation(req, res, next)
{
    if(isValidSession(req))
    {
        next();
    }
    else
    {
        res.redirect('/login');
    }
}

function isAdmin(req)
{
    if(req.session.role == 'admin')
    {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next)
{
    if(isAdmin(req))
    {
        next();
    }
    else
    {
        res.status(403);
        res.render("error", {message: "Not authorized", redirect: "/members", navLinks: navLinks});
    }
}

app.get("/", async (req, res) => {
    if(req.session.authenticated)
    {
        res.render("indexSession", {name: req.session.name, navLinks: navLinks});
        return;
    }
    else 
    {
        res.render("index", {navLinks: navLinks});
        return;
    }
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

app.post("/changeRole", async (req, res) => {
    const email = req.body.roleChange;
    const result = await userCollection.find({email: email}).project({name: 1, role: 1, id: 1}).toArray();
    const role = result[0].role;
    
    if(role == 'user')
    {
        userCollection.updateOne({email: email}, {$set: {role: 'admin'}});
    }
    else if(role == 'admin')
    {
        userCollection.updateOne({email: email}, {$set: {role: 'user'}});
    }

    res.redirect("/admin");
})

app.get("/signup", (req, res) => {
    res.render("signup", {navLinks: navLinks});
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
        password: hashedPassword,
        role: "user"
    });
    
    res.redirect("/");
});

app.get("/login", (req, res) => {
    res.render("login", {navLinks: navLinks});
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

    const result = await userCollection.find({email: email}).project({email: 1, name: 1, password: 1, role: 1, id: 1}).toArray();
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
        req.session.name = result[0].name;
        req.session.role = result[0].role;
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

app.get("/members", sessionValidation, async (req, res) => {
    res.render("members", {name: req.session.name, navLinks: navLinks});
});

app.get("/admin", sessionValidation, adminAuthorization, async (req, res) => {
    const result = await userCollection.find().project({email: 1, name: 1, role: 1, id: 1}).toArray();
    res.render("admin", {users: result, navLinks: navLinks});
});

app.get("/signOut", (req, res) => {
    req.session.destroy();
    res.redirect("/");
});

app.get("*", (req, res) => {
    res.status(404);
    res.render("error", {message: "Page not found - 404", redirect: "/", navLinks: navLinks});
});  

app.listen(port, () => {
    console.log("Node application listening to port " + port);
})