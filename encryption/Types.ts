export type Metadata = {
	hashingAlgorithm: string;
	encryptionAlgorithm: string;
	iterations: number;
	salt: string;
};

export type EncryptedFile = {
	metadata: Metadata;
	hmac: string;
	iv: string;
	encryptedData: string;
};