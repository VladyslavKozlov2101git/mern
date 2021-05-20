const {Router} = require('express')
const bcrypt = require('bcryptjs')
const {check, validationResult} = require('express-validator')
const User = require('../models/User')
const router = Router()
const jwt = require('jsonwebtoken')
const config = require('config')

// api/auth/register

router.post('/register',
    [
        check('email', 'The email is wrong').isEmail(), // Робимо валідацію для даних через  express-validator
        check('password', 'The minimal password\' lenght is 6 symbols')
            .isLength({min:6})
    ],
    async(req, res)=>{
    try {
        const errors = validationResult(req)

        if(!errors.isEmpty){
            return res.status(400).json({
                errors: errors.array(),
                message: 'Некоректные даные при регистрации'
            })
        }

        const {email, password} = req.body

        const candidate = await User.findOne({email:email})

        if (candidate){
           return  res.status(400).json({message:'Такой пользователь уже существует'})
        }

        const hashedPassword = await bcrypt.hash(password, 12) // хешируем пароль 12бит
        const user = new User ({email:email, password:hashedPassword})

        await user.save()  // очыкуэмо поки юзер збережеться

        res.status(201).json({message:'Юзер успешно создан'})


        
    } catch (error) {
        res.status(500).json({message:'Что-то пошло не так. Попробуйте снова'})
    }
})


// api/auth/login

router.post('/login', [
    check('email', 'Введите коректный емейл').normalizeEmail().isEmail(),
    check('password', 'The minimal password\' lenght is 6 symbols').exists()
    ],
    async(req, res)=>{
    try {
        const errors = validationResult(req)

        if(!errors.isEmpty){
            return res.status(400).json({
                errors: errors.array(),
                message: 'Некоректные даные при входе в систему'
            })
        }

        const {email, password} = req.body()

        const user = await User.findOne({email:email})

        if (!user){
            return res.status(400).json({message:'Пользователь не найден'})
        }

        const isMath = await bcrypt.compare(password, user.password) // порівнює введений пароль із паролем в БД

        if (!isMath){
            return res.status(400).json({message:'Пользователь не найден'})
        }

        const token = jwt.sign(
            {userID:user.id},
            config.get('jwtSecret'),
            {"expiresIn":"1h"} // время существования токена

        )  // create web token

        res.json({
            token, userId:user.id
        })

    
    } catch (error) {
        res.status(400).json({message:'Неверный пароль, попробуйте снова'})
    }


})




module.exports = router