import * as crypto from 'crypto';
import * as fs from 'fs';
import { EncryptedFile } from './Types';
import { generateKeys } from './utils';

const decryptFile = (filePath: string, password: string): void => {
		const fileData: EncryptedFile = JSON.parse(fs.readFileSync(filePath).toString());
		const { metadata, hmac, iv, encryptedData } = fileData;
	
		const { Km, Ke, Kh } = generateKeys(password, Buffer.from(metadata.salt, 'hex'), metadata.iterations, metadata.hashingAlgorithm);

		const hmacCheck = crypto.createHmac(metadata.hashingAlgorithm, Kh);
		// hmacCheck.update(Buffer.from(metadata.salt, 'hex')).update(metadata.iterations.toString()).update(metadata.hashingAlgorithm).update(metadata.encryptionAlgorithm);
		hmacCheck.update(Buffer.from(iv, 'hex')).update(Buffer.from(encryptedData, 'hex'));


		if(crypto.timingSafeEqual(hmacCheck.digest(), Buffer.from(hmac, 'hex'))) {
			console.log("HMAC check successful");
		} else {
			throw new Error("HMAC check failed, file may have been tampered with");
		}

		let decipher: crypto.Decipher;
		if(metadata.encryptionAlgorithm === 'aes-128-cbc') { 
			decipher = crypto.createDecipheriv(metadata.encryptionAlgorithm, Ke.slice(0, 16), Buffer.from(iv, 'hex')); 
		} else if (metadata.encryptionAlgorithm === 'des-ede3-cbc') {
			decipher = crypto.createDecipheriv(metadata.encryptionAlgorithm, Ke.slice(0, 24), Buffer.from(iv, 'hex'));
		} else {
			decipher = crypto.createDecipheriv(metadata.encryptionAlgorithm, Ke, Buffer.from(iv, 'hex'));
		}

		let decryptedData = decipher.update(Buffer.from(encryptedData, 'hex'));
		decryptedData = Buffer.concat([decryptedData, decipher.final()]);
		console.log(decryptedData.toString());

		const fileName = filePath.substring(filePath.lastIndexOf('/')+1);

		fs.writeFileSync(`./${fileName.replace('.enc.json', '')}`, decryptedData);

	}


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
const { password, filePath} = args;

decryptFile(filePath, password);
