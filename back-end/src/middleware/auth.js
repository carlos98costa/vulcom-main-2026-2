import jwt from 'jsonwebtoken'

/*
 * Este middleware verifica se a requisição recebeu um token de autorização.
 * As rotas listadas em bypassRoutes podem ser acessadas sem esse token.
 */
const bypassRoutes = [
  { url: '/users/login', method: 'POST' },
  // Caso o cadastro de novos usuários seja público:
  // { url: '/users', method: 'POST' },
]

export default function(req, res, next) {
  // Rotas liberadas seguem para o próximo middleware sem validar o token.
  for(const route of bypassRoutes) {
    if(route.url === req.path && route.method === req.method) {
      return next()
    }
  }

  // O cabeçalho deve conter um token no formato "Bearer <token>".
  const authHeader = req.headers.authorization
  if(!authHeader) {
    console.error('ERRO DE AUTORIZAÇÃO: falta de cabeçalho')
    return res.status(403).end()
  }

  const tokenMatch = authHeader.match(/^Bearer\s+(\S+)$/i)
  if(!tokenMatch) {
    console.error('ERRO DE AUTORIZAÇÃO: token inválido ou expirado')
    return res.status(403).end()
  }

  const secret = process.env.TOKEN_SECRET
  if(!secret) {
    console.error('TOKEN_SECRET is not configured')
    return res.status(500).end()
  }

  try {
    const authUser = jwt.verify(tokenMatch[1], secret)
    if(!authUser || typeof authUser !== 'object') {
      console.error('ERRO DE AUTORIZAÇÃO: token inválido ou expirado')
      return res.status(403).end()
    }

    // Disponibiliza os dados autenticados para os próximos middlewares e rotas.
    req.authUser = authUser
    next()
  }
  catch(error) {
    if(error instanceof jwt.JsonWebTokenError || error instanceof jwt.TokenExpiredError) {
      console.error('ERRO DE AUTORIZAÇÃO: token inválido ou expirado')
      return res.status(403).end()
    }

    console.error(error)
    res.status(500).end()
  }
}
