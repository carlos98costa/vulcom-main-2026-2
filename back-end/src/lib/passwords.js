import argon2 from 'argon2'

export async function hashPassword(password) {
  if(typeof password !== 'string') {
    throw new TypeError('A senha deve ser uma string.')
  }

  return argon2.hash(password, { type: argon2.argon2id })
}

export async function verifyPassword(password, encodedHash) {
  if(typeof password !== 'string' || typeof encodedHash !== 'string') return false
  if(!encodedHash.startsWith('$argon2id$')) return false

  return argon2.verify(encodedHash, password)
}
