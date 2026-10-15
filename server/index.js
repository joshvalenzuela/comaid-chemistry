import express from 'express'
import cors from 'cors'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import 'dotenv/config'
import { pool } from './db.js'

const app = express()
const port = process.env.PORT || 3001
const jwtSecret = process.env.JWT_SECRET || 'development-secret-change-me'

app.use(cors())
app.use(express.json())

const makeToken = (user) => jwt.sign({ sub: user.id, email: user.email }, jwtSecret, { expiresIn: '7d' })
const publicUser = (user) => ({ id: user.id, name: user.name, email: user.email, xp: user.xp, streak: user.streak })

const requireAuth = (request, response, next) => {
  const token = request.headers.authorization?.replace('Bearer ', '')
  if (!token) return response.status(401).json({ error: 'Authentication required' })
  try { request.userId = jwt.verify(token, jwtSecret).sub; next() } catch { response.status(401).json({ error: 'Invalid or expired token' }) }
}

app.get('/api/health', (_request, response) => response.json({ status: 'ok' }))

app.get('/api/leaderboard', async (_request, response) => {
  try {
    const result = await pool.query('SELECT name, email, xp AS points FROM users ORDER BY xp DESC, created_at ASC LIMIT 20')
    response.json({ leaderboard: result.rows.map((user, index) => ({ rank: index + 1, name: user.name, email: user.email, initials: user.name.split(/\s+/).map((part) => part[0]).join('').slice(0, 2).toUpperCase(), points: user.points, color: ['yellow', 'blue', 'teal', 'violet'][index % 4] })) })
  } catch { response.status(500).json({ error: 'Could not load leaderboard' }) }
})

app.post('/api/auth/register', async (request, response) => {
  const { name, email, password } = request.body
  if (!name || !email || !password || password.length < 6) return response.status(400).json({ error: 'Name, email, and a 6-character password are required' })
  try {
    const passwordHash = await bcrypt.hash(password, 12)
    const result = await pool.query('INSERT INTO users (name, email, password_hash) VALUES ($1, LOWER($2), $3) RETURNING id, name, email, xp, streak', [name, email, passwordHash])
    const user = result.rows[0]
    response.status(201).json({ user: publicUser(user), token: makeToken(user) })
  } catch (error) {
    response.status(error.code === '23505' ? 409 : 500).json({ error: error.code === '23505' ? 'Email is already registered' : 'Could not create account' })
  }
})

app.post('/api/auth/login', async (request, response) => {
  const { email, password } = request.body
  try {
    const result = await pool.query('SELECT id, name, email, password_hash, xp, streak FROM users WHERE email = LOWER($1)', [email])
    const user = result.rows[0]
    if (!user || !(await bcrypt.compare(password, user.password_hash))) return response.status(401).json({ error: 'Email or password is incorrect' })
    response.json({ user: publicUser(user), token: makeToken(user) })
  } catch { response.status(500).json({ error: 'Could not sign in' }) }
})

app.get('/api/me', requireAuth, async (request, response) => {
  const result = await pool.query('SELECT id, name, email, xp, streak FROM users WHERE id = $1', [request.userId])
  if (!result.rows[0]) return response.status(404).json({ error: 'User not found' })
  response.json({ user: publicUser(result.rows[0]) })
})

app.post('/api/progress/xp', requireAuth, async (request, response) => {
  const { amount, lessonId, quizId, score } = request.body
  const xp = Math.max(0, Math.min(Number(amount) || 0, 100))
  const client = await pool.connect()
  try {
    await client.query('BEGIN')
    await client.query('UPDATE users SET xp = xp + $1 WHERE id = $2', [xp, request.userId])
    if (lessonId) await client.query('INSERT INTO lesson_progress (user_id, lesson_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [request.userId, lessonId])
    if (quizId) await client.query('INSERT INTO quiz_attempts (user_id, quiz_id, score, xp_earned) VALUES ($1, $2, $3, $4)', [request.userId, quizId, score || 0, xp])
    await client.query('COMMIT')
    const result = await pool.query('SELECT id, name, email, xp, streak FROM users WHERE id = $1', [request.userId])
    response.json({ user: publicUser(result.rows[0]) })
  } catch (error) { await client.query('ROLLBACK'); response.status(500).json({ error: 'Could not save progress' }) } finally { client.release() }
})

app.listen(port, () => console.log(`Valengog API listening on http://localhost:${port}`))
