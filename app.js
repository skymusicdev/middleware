const express = require("express");
const fileUpload = require("express-fileupload");
const { exec } = require("child_process");
const app = express();
const port = 3000;
const path = require("path");
const bcrypt = require("bcrypt");
const fs = require("fs");
const axios = require("axios");

const FormData = require("form-data");

app.use(
	fileUpload({
		useTempFiles: true,
		tempFileDir: "/tmp/",
	})
);

app.use(function (req, res, next) {
	const allowedOrigins = ["Application url", "Development url"];
	const origin = req.headers.origin;

	if (allowedOrigins.includes(origin)) {
		res.header("Access-Control-Allow-Origin", origin);
	}

	res.header(
		"Access-Control-Allow-Headers",
		"Origin, X-Requested-With, Content-Type, Accept, Authorization"
	);
	next();
});

app.use(express.json());

app.use("/output", express.static(path.join(__dirname, "output")));

const checkBearerToken = (req, res, next) => {
	const authHeader = req.headers["authorization"];
	const token = authHeader && authHeader.split(" ")[1];

	if (token == null) return res.sendStatus(401);

	if (token !== "API auth token") {
		return res.sendStatus(403);
	}

	next();
};

app.post("/convert", checkBearerToken, (req, res) => {
	// Convert music to opus
	if (!req.files || !req.files.music) {
		return res.status(400).send("No file was uploaded.");
	}

	const musicFile = req.files.music;
	const musicFileNameWithoutExt = path.basename(
		musicFile.name,
		path.extname(musicFile.name)
	);
	const qualities = [320, 160, 80, 40];
	let conversionCount = 0;

	qualities.forEach((quality) => {
		const outputPath = `./output/${musicFileNameWithoutExt}-${quality}.opus`;
		exec(
			`opusenc --bitrate ${quality} "${musicFile.tempFilePath}" "${outputPath}"`,
			(error) => {
				conversionCount++;
				if (error) {
					return res.status(500).send("Error during the conversion process.");
				}

				if (conversionCount === qualities.length) {
					res.send("Conversion completed.");
				}
			}
		);
	});
});

app.post("/upload", checkBearerToken, async (req, res) => {
	// Uploading music to S5
	const apiUrl = "S5URL/upload";

	try {
		if (!req.body) {
			throw new Error("No file uploaded");
		}
		const fileName = req.body.fileName;

		const filePath = path.join(__dirname, "output", fileName);

		if (!fs.existsSync(filePath)) {
			return res.status(404).send("File not found");
		}

		const formData = new FormData();

		const file = fs.createReadStream(filePath);
		formData.append("file", file);

		const response = await axios.post(apiUrl, formData, {
			headers: {
				...formData.getHeaders(),
				Authorization: "S5 auth token",
			},
		});

		if (response.status !== 200)
			throw new Error(`Error: ${response.statusText}`);

		const data = await response.data;

		res.json(data);
	} catch (error) {
		res.status(500).json({ error: error.message });
	}
});

app.post("/register", checkBearerToken, async (req, res) => {
	// Registering user
	const headers = {
		Authorization: "S5 admin auth token",
		"Content-Type": "application/json",
	};
	try {
		const { seed } = req.body;

		const hashedSeed = await bcrypt.hash(seed, 10);

		const encodedHashedSeed = encodeURIComponent(hashedSeed);

		const url = `S5URL/admin/accounts?email=${encodedHashedSeed}`;

		const response = await fetch(url, {
			method: "POST",
			headers: {
				...headers,
			},
			body: JSON.stringify({}),
		});

		if (!response.ok) {
			throw new Error("API call failed");
		}

		const data = await response.json();
		const userId = data.id;

		try {
			const url = `S5URL/admin/accounts/new_auth_token?id=${userId}`;

			const response = await fetch(url, {
				method: "POST",
				headers: {
					...headers,
				},
				body: JSON.stringify({}),
			});

			if (!response.ok) {
				throw new Error("API call failed");
			}

			const data = await response.json();

			res.status(201).send({ data });
		} catch (err) {
			console.error(err);
			res.status(500).json({ error: error.message });
		}
	} catch (err) {
		console.error(err);
		res.status(500).json({ error: error.message });
	}
});

app.post("/login", checkBearerToken, async (req, res) => {
	// Get all accounts data
	const url = "S5URL/admin/accounts/full";

	const headers = {
		Authorization: "S5 admin auth token",
		"Content-Type": "application/json",
	};
	try {
		const response = await fetch(url, {
			method: "GET",
			headers: {
				...headers,
			},
		});

		if (!response.ok) {
			throw new Error(`API call failed: ${response.statusText}`);
		}

		const data = await response.json();
		console.log(data);

		// Searching user
		try {
			const { seed } = req.body;

			let foundAccountID = null;

			for (const account of data.accounts) {
				if (account.email !== null && account.email !== "") {
					const isValidPassword = bcrypt.compareSync(seed, account.email);
					if (isValidPassword) {
						foundAccountID = account.id;
					}
				}
			}

			if (foundAccountID !== null) {
				try {
					const url = `S5URL/admin/accounts/new_auth_token?id=${foundAccountID}`;

					const response = await fetch(url, {
						method: "POST",
						headers: {
							...headers,
						},
						body: JSON.stringify({}),
					});

					if (!response.ok) {
						throw new Error("API call failed");
					}

					const data = await response.json();

					res.status(201).send({ data });
				} catch (err) {
					console.error(err);
					res.status(500).json({ error: error.message });
				}
			} else {
				res.status(401).send("Login failed. " + seed);
			}
		} catch (err) {
			console.error(err);
			res.status(500).send("Server error." + err);
		}
	} catch (error) {
		console.error("Error fetching account data:", error);
	}
});

app.listen(port, () => {
	console.log(`Server running at http://localhost:${port}`);
});
