export class JwtError extends Error {
	public constructor(message: string) {
		super(message);
		this.name = 'JwtError';
		Error.captureStackTrace(this, this.constructor);
	}
}
