import * as crypto from "crypto";
import * as fs from "fs";

const createKey = (password: string | Buffer, salt: string | Buffer, iterations: number, hashingAlgorithm: string): any => {
	return crypto.pbkdf2Sync(password, salt, iterations, 32, hashingAlgorithm);
}

export const generateKeys = (password: string, salt: Buffer, iterations: number, hashingAlgorithm: string): any => {
	const Km: Buffer = createKey(password, salt, iterations, hashingAlgorithm);
	const Ke: Buffer = createKey(Km, "EncryptionKey", 1, hashingAlgorithm);
	const Kh: Buffer = createKey(Km, "HMACKey", 1, hashingAlgorithm);

	return { Km, Ke, Kh };
}