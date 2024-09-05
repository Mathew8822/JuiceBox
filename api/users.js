const express = require('express');
const usersRouter = express.Router();
require('dotenv').config();
const bcrypt = require('bcrypt');


const { 
  createUser,
  getAllUsers,
  getUserByUsername,
} = require('../db');

const jwt = require('jsonwebtoken');
//get all works
usersRouter.get('/', async (req, res, next) => {
  try {
    const users = await getAllUsers();
  
    res.send({
      users
    });
  } catch ({ name, message }) {
    next({ name, message });
  }
});

usersRouter.post('/login', async (req, res, next) => {
  const { username, password } = req.body;

  // request must have both
  if (!username || !password) {
    return next({
      name: "MissingCredentialsError",
      message: "Please supply both a username and password"
    });
  }

  try {
    const user = await getUserByUsername(username);

    if (user) {
      const passwordValid = await bcrypt.compare(password, user.password);

      if (passwordValid) {
        const token = jwt.sign({ 
          id: user.id, 
          username: user.username
        }, process.env.ACCESS_TOKEN_SECRET, {
          expiresIn: '1w'
        });

        return res.json({ 
          message: "you're logged in!",
          token 
        });
      }
    }

    return res.status(401).json({ 
      name: 'IncorrectCredentialsError', 
      message: 'Username or password is incorrect'
    });

  } catch(error) {
    console.error(error);
    next(error);
  }
});

usersRouter.post('/register', async (req, res, next) => {
  const { username, password, name, location } = req.body;

  try {
    const _user = await getUserByUsername(username);
  
    if (_user) {
      next({
        name: 'UserExistsError',
        message: 'A user by that username already exists'
      });
    }

    const user = await createUser({
      username,
      password,
      name,
      location,
    });

    const token = jwt.sign({ 
      id: user.id, 
      username
    }, process.env.ACCESS_TOKEN_SECRET, {
      expiresIn: '1w'
    });

    res.send({ 
      message: "thank you for signing up",
      token 
    });
  } catch ({ name, message }) {
    next({ name, message });
  } 
});

module.exports = usersRouter;