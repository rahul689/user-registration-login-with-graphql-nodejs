const { User } = require('../models')
const bcrypt = require('bcryptjs')
const { UserInputError, AuthenticationError } = require('apollo-server')
const jwt = require('jsonwebtoken')
const { JWT_SECRET } = require('../config/env.json')
const { Op } = require('sequelize')

module.exports={
    Query: {
        getUsers: async (_, __, context) =>{
            let user = {}
            if(context.req && context.req.headers.authorization)
            {
                const token= context.req.headers.authorization.split('Bearer ')[1]
                jwt.verify(token, JWT_SECRET, (err, decodedToken)=>{
                    if(err){
                        throw new AuthenticationError("Unathenticated")
                    }
                    
                    user = decodedToken
                    console.log(user)
                })
            }
            try{
                const users = await User.findAll({
                    where:{ username: {[Op.ne]: user.username}}
                })
                return users
            }catch(err){
                console.log(err)
                throw err
            }
        },
        login: async(_, args) => {
            let { username, password } = args
            let errors ={}

            try{
                if(username.trim() === '') errors.username = 'Username must not be empty.'
                if(password === '') errors.password = 'Password must not be empty.'

                if(Object.keys(errors).length > 0)
                {
                    throw new UserInputError('Bad input', { errors })
                }
                const user = await User.findOne({
                    where: { username }
                })        

                if (!user){
                    errors.username ='User not found.'
                    throw new UserInputError('User Not found', { errors })

                }


                const correctPassword = await bcrypt.compare(password, user.password)
                
                if (!correctPassword){
                    errors.password ='Incorrect password.'
                    throw new AuthenticationError('Password is incorrect.', { errors })
                }

                token =  jwt.sign({username}, JWT_SECRET, {expiresIn: '1h'})
                user.token =  token
                return {
                    ...user.toJSON(),
                    createdAt: user.createdAt.toISOString(),
                    token
                }

            }catch(err){
                console.log(err)
                throw err
            }
        }
    },
    Mutation: {
        register: async (_, args) => {
            let { username, email, password, confirmPassword } = args
            let errors = {}
            try{
                // TODO validate input data
                if(email.trim() == '') errors.email = 'Email must not be empty'
                if(username.trim() == '') errors.username = 'Username must not be empty'
                if(password.trim() == '') errors.password = 'Password must not be empty'
                if(confirmPassword.trim() == '') errors.confirmPassword = 'ConfirmPassword must not be empty'
                if(password !== confirmPassword) errors.confirmPassword = 'password must match'
                // TODO  check if username / email exists
                // const userByUsername = await User.findOne({ where: { username }})
                // const userByEmail = await User.findOne({ where: { email }})

                // if(userByUsername) errors.username = 'Username is taken'
                // if(userByEmail) errors.email = 'Email is taken'

                if(Object.keys(errors).length > 0)
                {
                    throw errors
                }
                //TODO hash password
                password = await bcrypt.hash(password, 6)
                // TODO Create user
                const user = await User.create({
                    username, email, password
                })
                // TODO return user
                return user
            } catch(err){
                console.log(err)
                if(err.name === 'SequelizeUniqueConstraintError')
                {
                    err.errors.forEach(e => (
                        errors[e.path] = `${e.path} is already taken.`
                    ));
                } else if(err.name === 'SequelizeValidationError')
                {                    
                    err.errors.forEach(e => (
                        errors[e.path] = `${e.message}`
                    ));
                }
                throw new UserInputError(' Bad input', errors)
            }

        }
    }
}
