import prisma from '../database/client.js'
import DOMPurify from 'isomorphic-dompurify'

const controller = {}

controller.retrieveComments = async function(req, res) {
  try {
    const comments = await prisma.xssComment.findMany({
      orderBy: { id: 'asc' }
    })

    res.send(comments)
  }
  catch(error) {
    console.error(error)
    res.status(500).end()
  }
}

controller.createComment = async function(req, res) {
  try {
    const rawContent = req.body?.content ?? ''
    const cleanContent = DOMPurify.sanitize(rawContent, { ALLOWED_TAGS: [], ALLOWED_ATTR: [] })
    await prisma.xssComment.create({
      data: { content: cleanContent }
    })

    res.status(201).end()
  }
  catch(error) {
    console.error(error)
    res.status(500).end()
  }
}

export default controller
