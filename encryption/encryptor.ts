import * as crypto from 'crypto';
import * as fs from 'fs';
import { Metadata, EncryptedFile } from './Types';
import { generateKeys } from './utils';


export const encryptFile = (filePath: string, password: string, iterations: number, encryptionAlgorithm: string, hashingAlgorithm: string): void => {
	const salt: Buffer = crypto.randomBytes(16);
	const { Km, Ke, Kh } = generateKeys(password, salt, iterations, hashingAlgorithm);

	console.log("master key:", Km.toString("hex"));
	console.log("encryption key:", Ke.toString("hex"));
	console.log("hmac key:", Kh.toString("hex"));
	
	const metadata: Metadata = {
		hashingAlgorithm,
		encryptionAlgorithm,
		iterations,
		salt: salt.toString('hex')
	};

	console.log({metadata});

	let iv: Buffer;
	let cipher: crypto.Cipher;

	if(encryptionAlgorithm === 'aes-128-cbc') { 
		iv = crypto.randomBytes(16);
		cipher = crypto.createCipheriv(encryptionAlgorithm, Ke.slice(0, 16), iv); 
	} else if (encryptionAlgorithm === 'des-ede3-cbc') {
		iv = crypto.randomBytes(8);
		cipher = crypto.createCipheriv(encryptionAlgorithm, Ke.slice(0, 24), iv);
	} else {
		iv = crypto.randomBytes(16);
		cipher = crypto.createCipheriv(encryptionAlgorithm, Ke, iv);
	}

	const data = fs.readFileSync(filePath);
	console.log(data.toString('utf-8'));
	let cipherText = cipher.update(data);
	cipherText = Buffer.concat([cipherText, cipher.final()]);

	const hmac = crypto.createHmac(hashingAlgorithm, Kh);
	// hmac.update(metadata.salt).update(metadata.iterations.toString()).update(metadata.hashingAlgorithm).update(metadata.encryptionAlgorithm);
	hmac.update(iv).update(cipherText);

	const fileData: EncryptedFile = {
		metadata,
		hmac: hmac.digest('hex'),
		iv: iv.toString('hex'),
		encryptedData: cipherText.toString('hex')
	};

	console.log({fileData})
	console.log(filePath.split('.'));
	const fileName = filePath.substring(filePath.lastIndexOf('/')+1, filePath.lastIndexOf('.'));

	const writeStream = fs.createWriteStream(`${fileName}_enc.json`);
	writeStream.write(JSON.stringify(fileData));
}


const validateOptions = (options: Record<string, string>): void => {
	const requiredOptions = ['encryptionAlgorithm', 'hashingAlgorithm', 'iterations', 'password', 'filePath'];
	
	requiredOptions.forEach((option) => {
		if (!options[option]) {
			throw new Error(`Missing required option: ${option}`);
		}
	});

	if (!['aes-128-cbc', 'des-ede3-cbc', 'aes-256-cbc'].includes(options.encryptionAlgorithm)) {
		throw new Error(`Invalid encryption algorithm: ${options.encryptionAlgorithm}`);
	}

	if (!['sha256', 'sha512'].includes(options.hashingAlgorithm)) {
		throw new Error(`Invalid hashing algorithm: ${options.hashingAlgorithm}`);
	}

	if (isNaN(parseInt(options.iterations))) {
		throw new Error(`Invalid number of iterations: ${options.iterations}`);
	}

	if (!fs.existsSync(options.filePath)) {
		throw new Error(`File does not exist: ${options.filePath}`);
	}
}

const parseArgs = (args: string[]): Record<string, string> => {
	const options: Record<string, string> = {};
	for (let i = 2; i < args.length; i += 2) {
			const key = args[i].replace('--', '');
			options[key] = args[i + 1];
	}
	validateOptions(options);
	return options;
}


// Parse command line arguments
const args = parseArgs(process.argv);
console.log(args);
const { encryptionAlgorithm, hashingAlgorithm, iterations, password, filePath} = args;

encryptFile(filePath, password, parseInt(iterations), encryptionAlgorithm, hashingAlgorithm);
