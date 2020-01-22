//Criação do server
const express = require('express')
const app = express()
const cors = require('cors')
require('dotenv').config()

//Validator
const Validator = require('fastest-validator')
const valid = new Validator()

//Email Validator
const nodemailer = require('nodemailer')

const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: false,
    requireTLS: true,
    auth:{
        user: process.env.EMAIL,
        pass: process.env.PASS
    }
})

//Segurança
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken')
const api_secret = process.env.API_SECRET

//Banco
const mongoose = require('mongoose')
mongoose.connect(process.env.MONGOOSE_CONNECTION , {useNewUrlParser: true, useUnifiedTopology: true})

const userSchema = mongoose.Schema({
    email: String,
    password: String,
    confirmed: Boolean
})

const Users = mongoose.model('User', userSchema)

//utils
async function findInDb(data){
    const find = await Users.findOne(data)
    return find
}

async function existInDb(data){
    if (await findInDb(data)){
        return true
    }else{
        return false
    }
}

async function hashingpassword(data){
    data['password'] = await bcrypt.hash(data.password, 10);
    return data
}

async function comparingpassword(password, hash){
    return await bcrypt.compare(password, hash);
}

async function sendConfirmEmail(email, token){
    let mailOptions = {
        from: 'gustavoferri13@gmail.com',
        to: email,
        subject: 'Confirmation',
        html: `<h1> <a href="http://localhost:3001/validation/${token}" > Para confirmar o seu email clique aqui </a> </h1>`
    };    
    return await transporter.sendMail(mailOptions)
}

function returnData(req){
    var auth = req.headers.authorization.split(' ')

    const dados = new Buffer.from(auth[1] , 'base64').toString().split(':')

    return {email: dados[0], password: dados[1]}
}


//AppUSe
app.use(express.json())
app.use(cors('*'))

//Rotas
app.get('/', (req, res)=>{
    res.send('OLA')
    res.end()
})

app.get('/validation/:token', async (req, res)=>{
    const verify = jwt.verify(req.params.token, api_secret)
    await Users.updateOne({email: verify.email}, {$set: {confirmed: true}})
    res.send('Já pode logar no site :D')
    res.end()
})

app.post('/auth', async (req, res)=>{

    const {email, password} = returnData(req)

    await existInDb({ email }) ? await (async()=>{
        const find = await findInDb({ email })
        const { confirmed } = find
        if ( confirmed ){
            const passwordCorrect = await comparingpassword(password, find.password)
            resposta = passwordCorrect ? jwt.sign({ email }, api_secret) : 401
            res.send(resposta)
        }else{
            res.sendStatus(403)
        }
    })() : res.sendStatus(404)
    res.end()
})

app.post('/create', async (req, res)=>{

    const {email, password} = returnData(req)

    const schema = {
        email: {max: 255, min: 1, type: "string"},
        password: {max: 255, min: 8, type: "string"}
    }

    const isValid = valid.validate({email, password}, schema) 
    
    if(isValid === true){

        let problem = false

        await existInDb({ email }) ? res.sendStatus(409) : (async ()=>{
            var new_body = await hashingpassword({email, password})
            new_body.confirmed = false
            let token = jwt.sign({ email }, api_secret)
            try{
                await sendConfirmEmail(new_body.email, token) 
                await Users.create(new_body)
            }catch(error){
                console.log(error)
                problem = 502
            }
        })().then(problem ? res.sendStatus(502) : res.sendStatus(200) )
         
    }else{
        res.sendStatus(401)
    }

    res.end()

})

app.post('/', (req, res)=>{
    console.log(req.body)
    res.send('OLA')
    res.end()
})

app.listen( process.env.PORT || 8080) 