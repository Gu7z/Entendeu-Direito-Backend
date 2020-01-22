//Criação do server
const express = require('express')
const app = express()
require('dotenv').config()

//Validator
const Validator = require('fastest-validator')
const valid = new Validator()

//Segurança
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken')
const api_secret = process.env.API_SECRET

//Banco
const mongoose = require('mongoose')
mongoose.connect(process.env.MONGOOSE_CONNECTION , {useNewUrlParser: true, useUnifiedTopology: true})

const userSchema = mongoose.Schema({
    name: String,
    email: String,
    pssw: String
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

async function hashingPssw(data){
    data['pssw'] = await bcrypt.hash(data.pssw, 10);
    return data
}

async function comparingPssw(pssw, hash){
    return await bcrypt.compare(pssw, hash);
}

//AppUSe
app.use(express.json())

//Rotas
app.get('/', (req, res)=>{
    res.send('OLA')
})

app.post('/create', async (req, res)=>{

    const { body } = req

    const schema = {
        name: {max: 60, min: 1, type: "string"},
        email: {max: 255, min: 1, type: "string"},
        pssw: {max: 255, min: 8, type: "string"}
    }

    const isValid = valid.validate(body, schema) 
    
    if(isValid === true){

        await existInDb(body) ? res.send('Usuario ja existe') : (async ()=>{
            var new_body = await hashingPssw(body)
            console.log(new_body)
            const create = await Users.create(new_body)
            res.send(create)
        })()
         
    }else{

        res.send(`Dados Invalidos`)

    }

})

app.post('/auth', async (req, res)=>{
    const { body } = req
    const exist = await existInDb({email: body.email}) ? await (async()=>{
        const find = await findInDb({email: body.email})
        const psswCorrect = await comparingPssw(body.pssw, find.pssw)
        resposta = psswCorrect ? jwt.sign({ email: body.email }, api_secret) : false
        return resposta
    })() : false
    res.send(exist)
})

app.post('/', (req, res)=>{
    console.log(req.body)
    res.send('OLA')
})

app.listen( process.env.PORT, ()=>{console.log('Server rodando na porta', process.env.PORT)}) 