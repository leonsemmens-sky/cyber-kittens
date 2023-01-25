const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const app = express();
const { User, Kitten } = require("./db");

const SALT_COUNT = 10;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get("/", async (req, res, next) => {
	try {
		res.send(`
      <h1>Welcome to Cyber Kittens!</h1>
      <p>Cats are available at <a href="/kittens/1">/kittens/:id</a></p>
      <p>Create a new cat at <b><code>POST /kittens</code></b> and delete one at <b><code>DELETE /kittens/:id</code></b></p>
      <p>Log in via POST /login or register via POST /register</p>
    `);
	} catch (error) {
		console.error(error);
		next(error);
	}
});

// Verifies token with jwt.verify and sets req.user
// TODO - Create authentication middleware
const auth = async (req, res, next) => {
	const header = req.header("Authorization");
	if (header) {
		const [_, token] = header.split(" ");
		const payload = jwt.verify(token, process.env.JWT_SECRET);
		req.user = payload;
	}
	next();
};

// POST /register
// OPTIONAL - takes req.body of {username, password} and creates a new user with the hashed password
app.post("/register", async (req, res) => {
	const { username, password } = req.body;

	const hash = await bcrypt.hash(password, SALT_COUNT);
	const user = await User.create({
		username,
		password: hash,
	});
	const token = jwt.sign(user.toJSON(), process.env.JWT_SECRET);

	res.send({
		token: token,
		message: "success",
	});
});

// POST /login
// OPTIONAL - takes req.body of {username, password}, finds user by username, and compares the password with the hashed version from the DB
app.post("/login", async (req, res) => {
	const { username, password } = req.body;

	const user = await User.findOne({
		where: { username },
	});
	if (!user) {
		return res.sendStatus(401);
	}

	const match = await bcrypt.compare(password, user.password);
	if (!match) {
		return res.sendStatus(401);
	}

	const token = jwt.sign(user.toJSON(), process.env.JWT_SECRET);
	res.send({
		token: token,
		message: "success",
	});
});

// GET /kittens/:id
// TODO - takes an id and returns the cat with that id
app.get("/kittens/:id", auth, async (req, res) => {
	if (!req.user) {
		return res.sendStatus(401);
	}

	const kitten = await Kitten.findByPk(req.params.id);
	if (!kitten || kitten.getDataValue("ownerId") !== req.user.id) {
		return res.sendStatus(401);
	}

	const { name, age, color } = kitten.toJSON();
	res.send({ name, age, color });
});

// POST /kittens
// TODO - takes req.body of {name, age, color} and creates a new cat with the given name, age, and color
app.post("/kittens", auth, async (req, res) => {
	if (!req.user) {
		return res.sendStatus(401);
	}

	const { name, age, color } = req.body;
	await Kitten.create({
		name,
		age,
		color,
		ownerId: req.user.id,
	});

	res.status(201).send({ name, age, color });
});

// DELETE /kittens/:id
// TODO - takes an id and deletes the cat with that id
app.delete("/kittens/:id", auth, async (req, res) => {
	if (!req.user) {
		return res.sendStatus(401);
	}

	const kitten = await Kitten.findByPk(req.params.id);
	if (!kitten || kitten.getDataValue("ownerId") !== req.user.id) {
		return res.sendStatus(401);
	}

	await kitten.destroy();
	res.sendStatus(204);
});

// error handling middleware, so failed tests receive them
app.use((error, req, res, next) => {
	console.error("SERVER ERROR: ", error);
	if (res.statusCode < 400) res.status(500);
	res.send({
		error: error.message,
		name: error.name,
		message: error.message,
	});
});

// we export the app, not listening in here, so that we can run tests
module.exports = app;
