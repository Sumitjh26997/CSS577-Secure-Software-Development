import * as crypto from "crypto";
import * as fs from "fs";

/**
 * helper function to create a key using PBKDF2
 * @param password - password for generating the keys
 * @param salt - salt for generating the keys
 * @param iterations - iterations to run the key derivation function
 * @param hashingAlgorithm - algorithm to use for hashing the password (sha256, sha512)
 * @returns key generated using PBKDF2
 */
const createKey = (password: string | Buffer, salt: string | Buffer, iterations: number, hashingAlgorithm: string): any => {
	return crypto.pbkdf2Sync(password, salt, iterations, 32, hashingAlgorithm);
}

/**
 * function to generate master, encryption and hmac keys
 * @param password - password for generating the keys
 * @param salt - random salt of 16 bytes
 * @param iterations - no. of iterations to run the key derivation function
 * @param hashingAlgorithm - algorithm to use for hashing the password (sha256, sha512)
 * @returns - master, encryption and hmac keys
 */
export const generateKeys = (password: string, salt: Buffer, iterations: number, hashingAlgorithm: string): any => {
	console.time("Key Generation");
	const Km: Buffer = createKey(password, salt, iterations, hashingAlgorithm);
	const Ke: Buffer = createKey(Km, "EncryptionKey", 1, hashingAlgorithm);
	const Kh: Buffer = createKey(Km, "HMACKey", 1, hashingAlgorithm);
	console.timeEnd("Key Generation");

	return { Km, Ke, Kh };
}

/**
 * function to parse command line arguments
 * @param args - command line arguments
 * @param callback - callback function to be called with the parsed arguments
 */
export const parseArgs = (args: string[], callback: Function): Record<string, string> => {
	const options: Record<string, string> = {};
	for (let i = 2; i < args.length; i += 2) {
			const key = args[i].replace('--', '');
			options[key] = args[i + 1];
	}
	callback(options);
	return options;
}