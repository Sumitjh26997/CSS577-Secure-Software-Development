import * as crypto from 'crypto';
import * as fs from 'fs';
import { Metadata, EncryptedFile } from './Types';
import { generateKeys, parseArgs } from './utils';

/**
 * function to encrypt given file
 * @param filePath - path to the file to be encrypted
 * @param password - password to encrypt the file with
 * @param iterations - no. of iterations to run the key derivation function
 * @param encryptionAlgorithm - algorithm to use for encryption(aes-128-cbc, des-ede3-cbc, aes-256-cbc)
 * @param hashingAlgorithm - algorithm to use for hashing the password (sha256, sha512)
 */
export const encryptFile = (filePath: string, password: string, iterations: number, encryptionAlgorithm: string, hashingAlgorithm: string): void => {
	console.time("Encryption Time");
	// generate a random salt of 16 bytes
	const salt: Buffer = crypto.randomBytes(16);

	// generate master, encryption and hmac keys
	const { Km, Ke, Kh } = generateKeys(password, salt, iterations, hashingAlgorithm);
	
	// create metadata object to be written to the file
	const metadata: Metadata = {
		hashingAlgorithm,
		encryptionAlgorithm,
		iterations,
		salt: salt.toString('hex')
	};

	
	let iv: Buffer;
	let cipher: crypto.Cipher;

	// create an initialization vector and cipher object based on the block size of the encryption algorithm used
	if(encryptionAlgorithm === 'aes-128-cbc') { 
		iv = crypto.randomBytes(16);
		// use only the first 16 bytes of the encryption key for AES-128
		cipher = crypto.createCipheriv(encryptionAlgorithm, Ke.slice(0, 16), iv); 
	} else if (encryptionAlgorithm === 'des-ede3-cbc') {
		iv = crypto.randomBytes(8);
		// use only the first 24 bytes of the encryption key for 3DES
		cipher = crypto.createCipheriv(encryptionAlgorithm, Ke.slice(0, 24), iv);
	} else {
		iv = crypto.randomBytes(16);
		// use the full 32 byte encryption key for AES-256
		cipher = crypto.createCipheriv(encryptionAlgorithm, Ke, iv);
	}

	// pads the data to the correct block size
	cipher.setAutoPadding(true);

	// read the file to be encrypted
	const data = fs.readFileSync(filePath);
	// encrypt the file data
	let cipherText = cipher.update(data);
	cipherText = Buffer.concat([cipherText, cipher.final()]);

	// create a HMAC of the salt, iterations, hashing algorithm, encryption algorithm, iv and cipher text
	const hmac = crypto.createHmac(hashingAlgorithm, Kh);
	hmac.update(metadata.salt).update(metadata.iterations.toString()).update(metadata.hashingAlgorithm).update(metadata.encryptionAlgorithm);
	hmac.update(iv).update(cipherText);

	// write the encrypted file data to a file
	const fileData: EncryptedFile = {
		metadata,
		hmac: hmac.digest('hex'),
		iv: iv.toString('hex'),
		encryptedData: cipherText.toString('hex')
	};

	filePath = filePath.substring(filePath.lastIndexOf('/')+1);
	const writeStream = fs.createWriteStream(`${filePath}.enc.json`);
	writeStream.write(JSON.stringify(fileData));
	console.timeEnd("Encryption Time");
}

/**
 * function to validate if the parameters passed are valid and complete
 * @param options - options object containing all the arguments required for encryption
 */
const validateOptions = (options: Record<string, string>): void => {
	const requiredOptions = ['encryptionAlgorithm', 'hashingAlgorithm', 'iterations', 'password', 'filePath'];
	
	requiredOptions.forEach((option) => {
		if (!options[option]) {
			throw new Error(`Missing required option: ${option}`);
		}
	});

	if (!['aes-128-cbc', 'des-ede3-cbc', 'aes-256-cbc'].includes(options.encryptionAlgorithm)) {
		throw new Error(`Invalid encryption algorithm: ${options.encryptionAlgorithm}, must be one of aes-128-cbc, des-ede3-cbc, aes-256-cbc`);
	}

	if (!['sha256', 'sha512'].includes(options.hashingAlgorithm)) {
		throw new Error(`Invalid hashing algorithm: ${options.hashingAlgorithm}, must be one of sha256, sha512`);
	}

	if (isNaN(parseInt(options.iterations))) {
		throw new Error(`Invalid number of iterations: ${options.iterations}, must be a number`);
	}

	if (!fs.existsSync(options.filePath)) {
		throw new Error(`File does not exist: ${options.filePath}`);
	}
}


const args = parseArgs(process.argv, validateOptions);
// destructure the arguments
const { encryptionAlgorithm, hashingAlgorithm, iterations, password, filePath} = args;

encryptFile(filePath, password, parseInt(iterations), encryptionAlgorithm, hashingAlgorithm);
