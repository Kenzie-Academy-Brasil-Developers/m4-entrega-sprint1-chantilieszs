import express, { request, response } from "express";
import users from "./database";
import { v4 as uuidv4} from 'uuid'
import { hash, compare } from 'bcryptjs'
import jwt from 'jsonwebtoken'
import e from "express";

const app = express()
app.use(express.json());

const ensureAuthMiddleware = (request, response, next) => {
    let authorization = request.headers.authorization
    if (!authorization) {
        return response.status(401).json({
            message: 'Missing authorization headers'
        })
    }

    authorization = authorization.split(' ')[1]

    return jwt.verify(authorization, "SECRET_KEY", (error, decoded) => {
        if (error){
            return response.status(401).json({
                message: 'Invalid Token'
            })
        }

        request.user = {
            id: decoded.sub,
            isAdmn: decoded.isAdmn

        }

        return next()
    })
}

const ensureUserIsAdm = (request, response, next) => {
    const user = request.user
    console.log(user);
    if(user.isAdmn) {
        return next()
    }
    return response.status(403).json({
        message: "missing admin permissions"
    })
}

const createUserService = async (userData) => {
    
    const user = { 
        uuid: uuidv4(),
        ...userData,
        password: await hash(userData.password, 10),
        createdOn: new Date(),
        updatedOn: new Date()
    }
    const filteredUser = users.find(ele => ele.email === userData.email)
    if(filteredUser) {
        return [409, {
            message: 'E-mail already registered'
        }]
    }
    users.push(user)
    return [201, user]
}
const createUserController = async (request, response) => {
    const [status, data ] = await createUserService(request.body)
    return response.status(status).json(data);
}

const createSessionService = async ({email, password}) => {
    const user = users.find(ele => ele.email === email)

    if (!user) {
        return [401, {
            message: 'Wrong email or password'
        }]
    }
    const passordMatch = await compare(password, user.password)

    if(!passordMatch) {
        return [401, {
            message: 'Wrong email or password'
        }]
    }
    const token = jwt.sign(
        {
            isAdmn: user.isAdmn
        },
        "SECRET_KEY",
        {
            expiresIn: "24h",
            subject: user.uuid
        }
    )
    return [200, {token}]
}
const createSessionController = async (request, response) => {
    const [status, data] = await createSessionService(request.body)
    return response.status(status).json(data)
}

const listUsersService = (name) => {
    
        if(name) {
            const filteredUser = users.filter(ele => ele.name === name)
            return [200, filteredUser]
        }
        return [200, users]
    
}
const listUsersController = (request, response ) => {
    const [status, userData] =  listUsersService(request.query.name);

    return response.status(status).json(userData)
}

const retriveUserService = (id) => {
    
    const user = users.find(ele => ele.uuid === id)

    if(!user) {
    return [404, {
        message: 'User not found'
     }]
    }
    return [200, user]
}
const retriveUserController = (request, response) => {
    const id = request.params.id
    const [status, data] = retriveUserService(id)

    return response.status(status).json(data)
}

const userProfileService = (request) => {
    
    const user = users.find(ele => ele.uuid === request.user.id)
    delete user.password
    
    return [200, user]
}
const userProfileController = (request, response) => {
    const [status, data] = userProfileService(request)

    return response.status(status).json(data)
}
const updateUserService = async (uuid, request) => {
    const user = users.find(ele => ele.uuid === uuid)
    const {id, name, email, password, isAdmn, createdOn, updatedOn} = user
    if(user.isAdm  || user.uuid === uuid) {
        const userUpdated = {
            uuid: id,
            name: request.name ? request.name : name,
            email: request.email ? request.email : email,
            password: request.password ? await hash(request.password, 8) : password,
            isAdmn: isAdmn,
            createdOn: createdOn,
            updatedOn: new Date()
        }
    
        return [200, userUpdated]
    }
    return [403, {
        message: "missing admin permissions"
    }]

}

const updateUserController = async (request, response) => {
    const uuid = request.params.uuid
    const [status, data] = await updateUserService(uuid, request.body)

    return response.status(status).json(data)

}
const deleteUserService = (uuid, request) => {
    const user = users.find(ele => ele.uuid === uuid);
    if(!user) {
        return [404, {
            message: 'User not found'
        }]
    }
    if(user.isAdmn === true || request.user.id === uuid) {
        const index = users.findIndex(ele => ele.uuid === uuid)
        users.splice(index, 1)

        return [204, {}]
    }
    return [403, {
        message: "missing admin permissions"
    }]
}
const deleteUserController = ( request, response) => {
    const uuid = request.params.uuid
    const [status, data] = deleteUserService(uuid, request)

    return response.status(status).json(data)

}

app.post('/users', createUserController)
app.get('/users', ensureAuthMiddleware, ensureUserIsAdm, listUsersController)
app.get('/user/:id', ensureAuthMiddleware, retriveUserController)
app.post('/login', createSessionController)
app.get('/users/profile', ensureAuthMiddleware, userProfileController)
app.patch('/users/:uuid', ensureAuthMiddleware, updateUserController)
app.delete('/users/:uuid', ensureAuthMiddleware, deleteUserController)


app.listen(3000, () => {
    console.log('server running in port 3000');
})



export default app;