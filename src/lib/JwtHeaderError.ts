import {JwtError} from './JwtError';

export class JwtHeaderError extends JwtError {
	public constructor(message: string) {
		super(message);
		this.name = 'JwtHeaderError';
		Error.captureStackTrace(this, this.constructor);
	}
}
