/*KEY TAKEAWAYS:
*In bcrypt.compare(para1,para2)-->para1 is user input
and para2 is the password from database
*In bcrypt.hash(password, SaltRound)-->The number of rounds
 determines how long the hashing process will take. A higher
number makes the hash more secure but slower to compute. A common
value is 10.
*Don't forget to use app.use(express.json())
*If username is not in database then the queryResponse itself is
undefined i.e. queryResponse=undefined && queryResponse.username=undefined
*/

const express = require('express')
const path = require('path')
const bcrypt = require('bcrypt')

const {open} = require('sqlite')
const sqlite3 = require('sqlite3')
const app = express()

const dbPath = path.join(__dirname, 'userData.db')
let db = null
const initializeDbAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    })
    app.listen(3000, () => {
      console.log('Server is running')
    })
  } catch (e) {
    console.log('Error occured')
    process.exit(1)
  }
}
initializeDbAndServer()
//API 1
app.use(express.json())
app.post('/register', async (request, response) => {
  const {username, name, password, gender, location} = request.body
  const query = `SELECT * FROM user WHERE username=?;`
  const queryResponse = await db.get(query, [username])
  if (queryResponse !== undefined && queryResponse.username !== undefined) {
    response.status(400)
    response.send('User already exists')
  } else if (password.length < 5) {
    response.status(400)
    response.send('Password is too short')
  } else {
    const encryptedPassword = await bcrypt.hash(password, 10)
    const insertQuery = `INSERT INTO user(username,name,password,gender,location) values(?,?,?,?,?);`
    const toRun = await db.run(insertQuery, [
      username,
      name,
      encryptedPassword,
      gender,
      location,
    ])
    console.log(encryptedPassword, username, name)
    response.status(200)
    response.send('User created successfully')
  }
})
//API 2
app.post('/login', async (request, response) => {
  const {username, password} = request.body
  const query = `select * from user where username=?;`
  const queryResponse = await db.get(query, [username])
  if (queryResponse === undefined) {
    response.status(400)
    response.send('Invalid user')
  } else {
    const isPasswordMatch = await bcrypt.compare(
      password,
      queryResponse.password,
    )
    if (isPasswordMatch === true) {
      response.status(200)
      response.send('Login success!')
    } else {
      response.status(400)
      response.send('Invalid password')
    }
  }
})
//API3
app.put('/change-password', async (request, response) => {
  const {username, oldPassword, newPassword} = request.body
  const query = `select * from user where username=?;`
  const queryResponse = await db.get(query, [username])
  const isPasswordMatch = await bcrypt.compare(
    oldPassword,
    queryResponse.password,
  )
  console.log(isPasswordMatch)
  if (isPasswordMatch === false) {
    response.status(400)
    response.send('Invalid current password')
  } else {
    if (newPassword.length < 5) {
      response.status(400)
      response.send('Password is too short')
    } else {
      const encryptedPassword = await bcrypt.hash(newPassword, 10)
      const updateQuery = `update user set password=? where username=?;`
      const toRun = await db.run(updateQuery, [encryptedPassword, username])
      response.status(200)
      response.send('Password updated')
    }
  }
})
module.exports = app
