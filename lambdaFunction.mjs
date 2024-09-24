/* global fetch */
import { createDecipheriv } from "node:crypto";

// Environment variables
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;
const ENCRYPTION_KEY_BUFFER = Buffer.from(ENCRYPTION_KEY, "hex");

// Logging
const logger = {
	info: (message) => console.log(`ℹ️ ${message}`),
	success: (message) => console.log(`✅ ${message}`),
	warning: (message) => console.log(`⚠️ ${message}`),
	error: (message, error) =>
		console.error(`❌ ${message}\n${error.stack || error}`),
};

// Decryption
function decryptMessage(encryptedMessage) {
	const parsedMessage = JSON.parse(encryptedMessage);
  const { encryptedData, iv } = parsedMessage;
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

// Database operations
async function sendToDB(query) {
	const response = await fetch(`${process.env.SUPABASE_URL}/rest/v1/rpc/${process.env.API_NAME_USRC}`, {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			"apikey": process.env.SUPABASE_KEY,
			"Authorization": `Bearer ${process.env.SUPABASE_KEY}`
		},
		body:JSON.stringify(query)
	});
	return response.json();
}

// Main processing function
async function processRecord(record) {
	try {
		const message = JSON.parse(record.body);
		const decryptedMessage = decryptMessage(message);
		logger.success("Decryption complete");
		const result = await sendToDB(decryptedMessage);
		logger.info("Result: ", JSON.stringify(result));
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
