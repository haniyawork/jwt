require("dotenv").config();
const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const {verify} = require('jsonwebtoken');
const {hash, compare} = require('bcryptjs');
const {fakeDB} = require('./fakeDB.js');
const server = express();
const { createAccessToken, createRefreshToken, sendAccessToken, sendRefreshToken } = require('./tokens.js');
const {isAuth} = require('./isAuth.js')
server.use(cookieParser());

server.use(
    cors({
        orgin: 'http://localhost:3000',
        credentials: true
    })
);

server.use(express.json());

server.use(express.urlencoded({ extended: true }));


//Register a user
 server.post('/register', async (req,res) => {
    const {email, password} = req.body;
    try{
        //1. check if user exist
        const user = fakeDB.find(user => user.email === email)
        if(user) throw new Error('user already exist');
        //2. if not user exist, hash the password
        const hashedPassword = await hash(password, 10);
        //3. insert the user in database
        fakeDB.push({
            id: fakeDB.length,
            email,
            password: hashedPassword
        });
        res.send({ message: 'User created'});
        console.log(fakeDB);
    }catch (err){
        res.send({
            error: `${err.message}`,
        })
    }
 });

 //2. login a user
server.post('/login', async(req, res) => {
    const {email,password} = req.body;
    try{
        const user = fakeDB.find(user => user.email === email);
        if (!user) throw new Error("User does not exist");
        //2. compare crypted password and see if it checks out. send error if not
        const valid = await compare(password, user.password);
        if(!valid) throw new Error("password not correct");
        //3. create refresh and accestoken
        const accesstoken =createAccessToken(user.id);
        const refreshtoken = createRefreshToken(user.id);
        // 4. put the refresh token in database
        user.refreshtoken = refreshtoken;
        console.log(fakeDB);
        //5. send token. refresh token as a cookie and accesstoken as a regular response
        sendRefreshToken(res, refreshtoken);
        sendAccessToken(res, req, accesstoken);
    }
    catch(err) {
        res.send({ 
            error: `${err.message}`,
        });
    }
})

//3. logout user
server.post('/logout', (_req, res) => {
    res.clearCookie('refreshtoken');
    return res.send({
        message: 'Logged out',
    })
})

//4. protected route
server.post('/protected', async (req, res) => {
    try{
        const userId = isAuth(req)
        if(userId !== null){
            res.send({ 
                data: 'this is protected data'
            });
        }
    }catch (err) {
        res.send({
            error: `${err.message}`,
        });
    }
});

server.listen(process.env.PORT, () =>
console.log(`Server listening on port ${process.env.PORT}`),
);

//https://www.youtube.com/watch?v=x5gLL8-M9Fo