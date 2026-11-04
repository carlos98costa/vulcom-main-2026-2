import prisma from '../database/client.js'
import jwt from 'jsonwebtoken'
import { hashPassword, verifyPassword } from '../lib/passwords.js'

const controller = {}     // Objeto vazio

controller.create = async function(req, res) {
  try {
    if(typeof req.body?.password !== 'string') {
      return res.status(400).end()
    }

    await prisma.user.create({
      data: {
        ...req.body,
        password: await hashPassword(req.body.password)
      }
    })

    // HTTP 201: Created
    res.status(201).end()
  }
  catch(error) {
    console.error(error)

    // HTTP 500: Internal Server Error
    res.status(500).end()
  }
}

controller.retrieveAll = async function(req, res) {
  try {
    const result = await prisma.user.findMany({
      select: {
        id: true,
        fullname: true,
        username: true,
        email: true,
        is_admin: true
      }
    })

    // HTTP 200: OK (implícito)
    res.send(result)
  }
  catch(error) {
    console.error(error)

    // HTTP 500: Internal Server Error
    res.status(500).end()
  }
}

controller.retrieveOne = async function(req, res) {
  try {
    const result = await prisma.user.findUnique({
      where: { id: Number(req.params.id) },
      select: {
        id: true,
        fullname: true,
        username: true,
        email: true,
        is_admin: true
      }
    })

    // Encontrou ~> retorna HTTP 200: OK (implícito)
    if(result) res.send(result)
    // Não encontrou ~> retorna HTTP 404: Not Found
    else res.status(404).end()
  }
  catch(error) {
    console.error(error)

    // HTTP 500: Internal Server Error
    res.status(500).end()
  }
}

controller.update = async function(req, res) {
  try {
    const data = { ...req.body }
    if(data.password !== undefined) {
      if(typeof data.password !== 'string') return res.status(400).end()
      data.password = await hashPassword(data.password)
    }

    const result = await prisma.user.update({
      where: { id: Number(req.params.id) },
      data
    })

    // Encontrou e atualizou ~> HTTP 204: No Content
    if(result) res.status(204).end()
    // Não encontrou (e não atualizou) ~> HTTP 404: Not Found
    else res.status(404).end()
  }
  catch(error) {
    console.error(error)

    // HTTP 500: Internal Server Error
    res.status(500).end()
  }
}

controller.delete = async function(req, res) {
  try {
    await prisma.user.delete({
      where: { id: Number(req.params.id) }
    })

    // Encontrou e excluiu ~> HTTP 204: No Content
    res.status(204).end()
  }
  catch(error) {
    if(error?.code === 'P2025') {
      // Não encontrou e não excluiu ~> HTTP 404: Not Found
      res.status(404).end()
    }
    else {
      // Outros tipos de erro
      console.error(error)

      // HTTP 500: Internal Server Error
      res.status(500).end()
    }
  }
}

controller.login = async function(req, res) {
  try {

      // Busca o usuário no BD usando o valor dos campos
      // "username" OU "email"
      const user = await prisma.user.findFirst({
        where: {
          OR: [
            { username: req.body?.username },
            { email: req.body?.email }
          ]
        }
      })

      // Se o usuário não for encontrado, retorna
      // HTTP 401: Unauthorized
      if(! user) return res.status(401).end()

      const passwordIsValid = await verifyPassword(req.body?.password, user.password)

      // Se a senha estiver errada, retorna
      // HTTP 401: Unauthorized
      if(! passwordIsValid) return res.status(401).end()

      const publicUser = {
        id: user.id,
        fullname: user.fullname,
        username: user.username,
        email: user.email,
        is_admin: user.is_admin
      }
      const token = jwt.sign(
        publicUser,                 // Dados do usuário, sem a senha ou seu hash
        process.env.TOKEN_SECRET,   // Senha para criptografar o token
        { expiresIn: '24h' }        // Prazo de validade do token
      )

      // Formamos o cookie para enviar ao front-end
      res.cookie(process.env.AUTH_COOKIE_NAME, token, {
        httpOnly: true, // O cookie ficará inacessível para o JS no front-end
        secure: true,   // O cookie será criptografado em conexões https
        sameSite: 'None',
        path: '/',
        maxAge: 24 * 60 * 60 * 100  // 24h
      })

      res.send({token, user: publicUser})

  }
  catch(error) {
    console.error(error)

    // HTTP 500: Internal Server Error
    res.status(500).end()
  }
}

controller.me = function(req, res) {
  // Retorna as informações do usuário autenticado
  // HTTP 200: OK (implícito)
  res.send(req?.authUser)
}

export default controller