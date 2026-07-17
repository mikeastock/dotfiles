declare module "@20minutes/s3rver" {
	interface S3rverBucketConfig {
		name: string;
		configs?: Array<string | Buffer>;
	}

	interface S3rverOptions {
		address?: string;
		port?: number;
		silent?: boolean;
		directory?: string;
		resetOnClose?: boolean;
		allowMismatchedSignatures?: boolean;
		configureBuckets?: S3rverBucketConfig[];
	}

	export default class S3rver {
		constructor(options?: S3rverOptions);
		run(): Promise<{ address: string; port: number }>;
		close(): Promise<void>;
	}
}
