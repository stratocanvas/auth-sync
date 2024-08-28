import { MongoClient } from "mongodb";
import { createDecipheriv } from "node:crypto";

// Environment variables
const MONGODB_URI = process.env.MONGODB_URI;
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;
const DB_NAME = process.env.DB_NAME;
const COLLECTION_NAME = process.env.COLLECTION_NAME;

if (!MONGODB_URI || !ENCRYPTION_KEY) {
	throw new Error("Missing required environment variables");
}

const ENCRYPTION_KEY_BUFFER = Buffer.from(ENCRYPTION_KEY, "hex");

// Database connection
let cachedClient = null;

async function connectToDatabase() {
	if (cachedClient) {
		return cachedClient;
	}

	const client = new MongoClient(MONGODB_URI);
	await client.connect();
	cachedClient = client;
	return client;
}

// Decryption
function decryptMessage(encryptedMessage) {
	const { encryptedData, iv } = encryptedMessage;
	const ivBuffer = Buffer.from(iv, "base64");
	const encryptedBuffer = Buffer.from(encryptedData, "base64");
	const authTagLength = 16;
	const ciphertext = encryptedBuffer.slice(0, -authTagLength);
	const authTag = encryptedBuffer.slice(-authTagLength);

	const decipher = createDecipheriv(
		"aes-256-gcm",
		ENCRYPTION_KEY_BUFFER,
		ivBuffer,
	);
	decipher.setAuthTag(authTag);

	const decrypted = Buffer.concat([
		decipher.update(ciphertext),
		decipher.final(),
	]);

	return JSON.parse(decrypted.toString("utf8"));
}

// Logging
const logger = {
	info: (message) => console.log(`ℹ️ ${message}`),
	success: (message) => console.log(`✅ ${message}`),
	warning: (message) => console.log(`⚠️ ${message}`),
	error: (message, error) =>
		console.error(`❌ ${message}\n${error.stack || error}`),
};

// Database operations
async function performMongoOperation(collection, action, userId) {
	switch (action) {
		case "create": {
			const createResult = await collection.insertOne({ uid: userId });
			logger.success(`Created user ${userId}`);
			return {
				acknowledged: createResult.acknowledged,
				insertedId: createResult.insertedId.toString(),
			};
		}
		case "delete": {
			const deleteResult = await collection.deleteOne({ uid: userId });
			logger.success(`Deleted user ${userId}`);
			return {
				acknowledged: deleteResult.acknowledged,
				deletedCount: deleteResult.deletedCount,
			};
		}
		default:
			throw new Error(`Unsupported action: ${action}`);
	}
}

// Main processing function
async function processRecord(record) {
	try {
		const message = JSON.parse(record.body);
		const decryptedMessage = decryptMessage(message);
		logger.success("Decryption complete");

		const client = await connectToDatabase();
		const collection = client.db(DB_NAME).collection(COLLECTION_NAME);
		const result = await performMongoOperation(
			collection,
			decryptedMessage.action,
			decryptedMessage.userId,
		);

		return {
			statusCode: 200,
			body: JSON.stringify({
				message: `Successfully performed ${decryptedMessage.action} operation`,
				result,
			}),
		};
	} catch (error) {
		logger.error("Error processing record:", error);
		return {
			statusCode: 500,
			body: JSON.stringify({
				error: "Failed to process record",
				details: error.message,
			}),
		};
	}
}

// Lambda handler
export const handler = async (event) => {
	logger.info("Processing...");
	try {
		const results = await Promise.all(event.Records.map(processRecord));
		logger.success("Completed");
		return results;
	} catch (error) {
		logger.error("Fatal error:", error);
		return [
			{
				statusCode: 500,
				body: JSON.stringify({
					error: "Fatal error occurred",
					details: error.message,
				}),
			},
		];
	}
};
