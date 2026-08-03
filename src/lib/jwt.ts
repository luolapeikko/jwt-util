import {type JwtPayload, type VerifyErrors, verify} from 'jsonwebtoken';

type JwtVerifyPromiseFunc<T = Record<string, unknown>> = (...params: Parameters<typeof verify>) => Promise<(JwtPayload & T) | undefined>;
export const jwtVerifyPromise: JwtVerifyPromiseFunc = (token, secretOrPublicKey, options) => {
	return new Promise<JwtPayload | undefined>((resolve, reject) => {
		// biome-ignore lint/suspicious/noExplicitAny: temporary workaround for type mismatch
		verify(token, secretOrPublicKey, options as any, (err: VerifyErrors | null, decoded: object | undefined) => {
			if (err) {
				reject(err);
			} else {
				resolve(decoded);
			}
		});
	});
};
