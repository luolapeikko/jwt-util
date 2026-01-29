import * as dotenv from 'dotenv';
import * as jwt from 'jsonwebtoken';
import {pki} from 'node-forge';
import {beforeAll, describe, expect, it} from 'vitest';
import {z} from 'zod';
import {IssuerManager, JwtAsymmetricDiscoveryTokenIssuer, JwtAsymmetricTokenIssuer, JwtAzureMultiTenantTokenIssuer, JwtManager} from '../src';
import {getAzureAccessToken, haveAzureEnvVariables} from './lib/azure';
import {getGoogleIdToken, haveGoogleEnvVariables} from './lib/google';

dotenv.config({quiet: true});

const googleIdTokenSchema = z.object({
	aud: z.string(),
	azp: z.string(),
	email: z.string(),
	email_verified: z.boolean(),
	exp: z.number(),
	iat: z.number(),
	iss: z.string(),
	sub: z.string(),
});

const keys = pki.rsa.generateKeyPair(2048);
const privateKeyBuffer = Buffer.from(pki.privateKeyToPem(keys.privateKey));
const issuerUrl = 'http://localhost';
const localPki = new JwtAsymmetricTokenIssuer([issuerUrl]);
localPki.add(issuerUrl, '01', privateKeyBuffer);

let jwtManager: JwtManager;

describe('JwtManager', () => {
	beforeAll(() => {
		jwtManager = new JwtManager(
			new IssuerManager([
				new JwtAsymmetricDiscoveryTokenIssuer(['https://accounts.google.com']),
				new JwtAzureMultiTenantTokenIssuer({allowedIssuers: [`https://sts.windows.net/${String(process.env.AZ_TENANT_ID)}/`]}),
				localPki,
			]),
		);;
	});
	it('should validate google id token', {skip: !haveGoogleEnvVariables()}, async () => {
		const {isCached, body} = await jwtManager.verify(await getGoogleIdToken(), undefined, (body) => googleIdTokenSchema.strict().parse(body));
		expect(body).to.have.all.keys(['aud', 'azp', 'email', 'email_verified', 'exp', 'iat', 'iss', 'sub']);
		expect(isCached).to.be.eq(false);
	});
	it('should validate azure token', {skip: !haveAzureEnvVariables()}, async () => {
		const token = await getAzureAccessToken();
		const {isCached, body} = await jwtManager.verify(token);
		expect(body).to.have.all.keys(['aud', 'iss', 'iat', 'nbf', 'exp', 'aio', 'appid', 'appidacr', 'idp', 'oid', 'rh', 'sub', 'tid', 'uti', 'ver', 'xms_ftd']);
		expect(isCached).to.be.eq(false);
	});
	it('should sign and verify jwt', async () => {
		const payload = {foo: 'bar'};
		const token = jwt.sign(payload, privateKeyBuffer, {algorithm: 'RS256', issuer: issuerUrl, keyid: '01', expiresIn: '1h'});
		const {body} = await jwtManager.verify(token);
		expect(body).to.include(payload);
	});
});
