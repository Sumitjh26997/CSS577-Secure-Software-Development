import * as crypto from 'crypto';
import * as fs from 'fs';
import { EncryptedFile } from './Types';
import { generateKeys, parseArgs } from './utils';

/**
 * function to decrypt given file - file must be in the format of an EncryptedFile
 * @param filePath - path to the encrypted file to be decrypted
 * @param password - password to decrypt the file with
 */
const decryptFile = (filePath: string, password: string): void => {
	// read the encrypted file data
	const fileData: EncryptedFile = JSON.parse(fs.readFileSync(filePath).toString());
	// destructure the file data into metadata, hmac, iv and encryptedData
	const { metadata, hmac, iv, encryptedData } = fileData;

	// generate master, encryption and hmac keys
	const { Km, Ke, Kh } = generateKeys(password, Buffer.from(metadata.salt, 'hex'), metadata.iterations, metadata.hashingAlgorithm);

	// create a HMAC of the salt, iterations, hashing algorithm, encryption algorithm, iv and cipher text
	const hmacCheck = crypto.createHmac(metadata.hashingAlgorithm, Kh);
	hmacCheck.update(metadata.salt).update(metadata.iterations.toString()).update(metadata.hashingAlgorithm).update(metadata.encryptionAlgorithm);
	hmacCheck.update(Buffer.from(iv, 'hex')).update(Buffer.from(encryptedData, 'hex'));


	// check if the HMAC of the file data matches the HMAC in the file
	// used timingSafeEqual to prevent timing attacks
	if(crypto.timingSafeEqual(hmacCheck.digest(), Buffer.from(hmac, 'hex'))) {
		console.log("HMAC check successful");
	} else {
		throw new Error("HMAC check failed, file may have been tampered with");
	}

	// create a decipher object based on the block size of the encryption algorithm used
	let decipher: crypto.Decipher;
	if(metadata.encryptionAlgorithm === 'aes-128-cbc') { 
		decipher = crypto.createDecipheriv(metadata.encryptionAlgorithm, Ke.slice(0, 16), Buffer.from(iv, 'hex')); 
	} else if (metadata.encryptionAlgorithm === 'des-ede3-cbc') {
		decipher = crypto.createDecipheriv(metadata.encryptionAlgorithm, Ke.slice(0, 24), Buffer.from(iv, 'hex'));
	} else {
		decipher = crypto.createDecipheriv(metadata.encryptionAlgorithm, Ke, Buffer.from(iv, 'hex'));
	}

	// pads the data to the correct block size
	decipher.setAutoPadding(true);

	// decrypt the file data
	let decryptedData = decipher.update(Buffer.from(encryptedData, 'hex'));
	decryptedData = Buffer.concat([decryptedData, decipher.final()]);

	// write the decrypted data to a file
	const fileName = filePath.substring(filePath.lastIndexOf('/')+1);
	fs.writeFileSync(`./${fileName.replace('.enc.json', '')}`, decryptedData);
}

/**
 * function to validate if the parameters passed are valid and complete
 * @param options - options object containing all the arguments required for encryption
 */
const validateOptions = (options: Record<string, string>): void => {
	const requiredOptions = ['password', 'filePath'];
	
	requiredOptions.forEach((option) => {
		if (!options[option]) {
			throw new Error(`Missing required option: ${option}`);
		}
	});

	if (!fs.existsSync(options.filePath)) {
		throw new Error(`File does not exist: ${options.filePath}`);
	}
}



	// Parse command line arguments
const args = parseArgs(process.argv, validateOptions);
const { password, filePath} = args;

decryptFile(filePath, password);
