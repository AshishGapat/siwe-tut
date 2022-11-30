import cors from 'cors'
import express from 'express'
import Session from 'express-session'
import { generateNonce, SiweMessage } from 'siwe'

const app = express()
app.use(express.json())
app.use(cors({
    origin: 'http://localhost:8080',
    credentials: true,
}))

app.use(Session({
    name: 'siwe-quests',
    secret: "siwe-quests-secret",
    resave: true,
    saveUninitialized: true,
    cookie: { secure: false, sameSite: true }
}));

app.get('/nonce', (req, res) => {
    req.session.nonce = generateNonce()
    res.setHeader('Content-Type', 'text/plain')
    res.status(200).send(req.session.nonce)
})

app.post('/verify', async function(req,res) {
    try {
        if(!req.body.message) {
            res.status(422).json({message: "Expected prepareMessage as body"})
            return
        }

        let message = new SiweMessage(req.body.message)
        const fields = await message.validate(req.body.signature)
        if(fields.nonce != req.session.nonce) {
            console.log(req.session)
            res.status(422).json({
                message: `Invalid nonce`
            })
            return
        }
        req.session.siwe = fields
        req.session.cookie.expires = new Date(fields.expirationTime)
        req.session.save(() => res.status(200).end())
    }
    catch(e) {
        req.session.siwe = null
        req.session.nonce = null
        console.error(e)
    
    }
})

app.get('/edit_profile', function(req, res) {
    if(!req.session.siwe) {
        res.status(401).json({message: 'You have to first sign in'})
        return
    }
    console.log("User is authenticated")
    res.setHeader('Content-Type', 'text/plain')
    res.send(`You are authenticated and your address is: ${req.session.siwe.address}`)
})

app.listen(3000)