import * as jwt from 'jsonwebtoken';
import {pki} from 'node-forge';
import {beforeAll, describe, expect, it} from 'vitest';
import {IssuerManager} from '../src/IssuerManager';
import {JwtAsymmetricTokenIssuer} from '../src/issuers/JwtAsymmetricTokenIssuer';
import {JwtManager} from '../src/JwtManager';
import {JwtBodyError} from '../src/lib/JwtBodyError';
import {JwtHeaderError} from '../src/lib/JwtHeaderError';

const keys = pki.rsa.generateKeyPair(2048);
const privateKeyBuffer = Buffer.from(pki.privateKeyToPem(keys.privateKey));
const issuerUrl = 'http://localhost';
const localPki = new JwtAsymmetricTokenIssuer([issuerUrl]);
localPki.add(issuerUrl, '01', privateKeyBuffer);

let jwtManager: JwtManager;

describe('JwtError tests', () => {
	beforeAll(() => {
		jwtManager = new JwtManager(new IssuerManager([localPki]));
	});

	describe('JwtBodyError', () => {
		it('should create error with message', async () => {
			const token = jwt.sign({}, privateKeyBuffer, {keyid: '1', algorithm: 'RS256'});
			await expect(jwtManager.verify(token)).rejects.toThrow(JwtBodyError);
		});
	});

	describe('JwtHeaderError', () => {
		it('should create error with message', async () => {
			const token = jwt.sign({}, privateKeyBuffer, {issuer: issuerUrl, algorithm: 'RS256'});
			await expect(jwtManager.verify(token)).rejects.toThrow(JwtHeaderError);
		});
	});
});
