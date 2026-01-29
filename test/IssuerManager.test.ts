import * as dotenv from 'dotenv';
import {describe, expect, it, vi} from 'vitest';
import {IssuerManager, JwtAsymmetricDiscoveryTokenIssuer, JwtAsymmetricTokenIssuer, JwtSymmetricTokenIssuer} from '../src';

dotenv.config({quiet: true});

const issuerUrl = 'http://localhost';

describe('IssuerManager', () => {
	it('should store and get symmetric key', async () => {
		const issuer = new JwtSymmetricTokenIssuer([issuerUrl]);
		issuer.add(issuerUrl, '01', 'secret');
		const issuerManager = new IssuerManager();
		issuerManager.add(issuer);
		expect(issuerManager.issuerSolverCount(issuerUrl)).to.be.eq(1);
		expect(issuerManager.issuerSolverCount('http://localhost2')).to.be.eq(0);
		expect(await issuerManager.get(issuerUrl, '01')).to.be.eq('secret');
		expect(await issuerManager.get(issuerUrl, '02')).to.be.eq(undefined);
	});
	it('should store and get asymmetric key', async () => {
		const issuer = new JwtAsymmetricTokenIssuer([issuerUrl]);
		issuer.add(issuerUrl, '01', Buffer.from('secret'));
		const issuerManager = new IssuerManager();
		issuerManager.add(issuer);
		expect(issuerManager.issuerSolverCount(issuerUrl)).to.be.eq(1);
		expect(issuerManager.issuerSolverCount('http://localhost2')).to.be.eq(0);
		expect((await issuerManager.get(issuerUrl, '01'))?.toString()).to.be.eq('secret');
		expect(await issuerManager.get(issuerUrl, '02')).to.be.eq(undefined);
	});
	it('should store and get issuer asymmetric key', async () => {
		const issuer = new JwtAsymmetricDiscoveryTokenIssuer(['https://accounts.google.com']);
		const issuerManager = new IssuerManager();
		issuerManager.add(issuer);
		expect(issuerManager.issuerSolverCount('https://accounts.google.com')).to.be.eq(1);
		expect(issuerManager.issuerSolverCount('http://localhost2')).to.be.eq(0);
		await issuer.load('https://accounts.google.com');
		const keyIds = await issuer.listKeyIds('https://accounts.google.com');
		expect(keyIds.length).to.be.greaterThan(0);
		const buffer = await issuerManager.get('https://accounts.google.com', keyIds[0]);
		expect(buffer).to.be.instanceOf(Buffer);
	});

	describe('constructor', () => {
		it('should accept array of issuers', () => {
			const issuer1 = new JwtSymmetricTokenIssuer([issuerUrl]);
			const issuer2 = new JwtSymmetricTokenIssuer(['http://other']);
			const issuerManager = new IssuerManager([issuer1, issuer2]);
			expect(issuerManager.issuerSolverCount(issuerUrl)).to.be.eq(1);
			expect(issuerManager.issuerSolverCount('http://other')).to.be.eq(1);
		});

		it('should accept Set of issuers', () => {
			const issuer1 = new JwtSymmetricTokenIssuer([issuerUrl]);
			const issuer2 = new JwtSymmetricTokenIssuer(['http://other']);
			const issuerManager = new IssuerManager(new Set([issuer1, issuer2]));
			expect(issuerManager.issuerSolverCount(issuerUrl)).to.be.eq(1);
			expect(issuerManager.issuerSolverCount('http://other')).to.be.eq(1);
		});

		it('should accept logger option', () => {
			const logger = {debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn()};
			const issuerManager = new IssuerManager([], {logger});
			const issuer = new JwtSymmetricTokenIssuer([issuerUrl]);
			issuerManager.add(issuer);
			expect(logger.debug).toHaveBeenCalledWith('Adding issuer: symmetric');
		});
	});

	describe('add', () => {
		it('should add array of issuers', () => {
			const issuer1 = new JwtSymmetricTokenIssuer([issuerUrl]);
			const issuer2 = new JwtSymmetricTokenIssuer(['http://other']);
			const issuerManager = new IssuerManager();
			issuerManager.add([issuer1, issuer2]);
			expect(issuerManager.issuerSolverCount(issuerUrl)).to.be.eq(1);
			expect(issuerManager.issuerSolverCount('http://other')).to.be.eq(1);
		});
	});

	describe('delete', () => {
		it('should delete an issuer and return true', () => {
			const issuer = new JwtSymmetricTokenIssuer([issuerUrl]);
			const issuerManager = new IssuerManager([issuer]);
			expect(issuerManager.issuerSolverCount(issuerUrl)).to.be.eq(1);
			const deleted = issuerManager.delete(issuer);
			expect(deleted).to.be.eq(true);
			expect(issuerManager.issuerSolverCount(issuerUrl)).to.be.eq(0);
		});

		it('should return false when deleting non-existent issuer', () => {
			const issuer = new JwtSymmetricTokenIssuer([issuerUrl]);
			const issuerManager = new IssuerManager();
			const deleted = issuerManager.delete(issuer);
			expect(deleted).to.be.eq(false);
		});

		it('should log when deleting with logger', () => {
			const logger = {debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn()};
			const issuer = new JwtSymmetricTokenIssuer([issuerUrl]);
			const issuerManager = new IssuerManager([issuer], {logger});
			issuerManager.delete(issuer);
			expect(logger.debug).toHaveBeenCalledWith('Deleting issuer: symmetric');
		});
	});

	describe('get', () => {
		it('should return undefined for unknown issuer URL', async () => {
			const issuerManager = new IssuerManager();
			const result = await issuerManager.get('http://unknown', 'key1');
			expect(result).to.be.eq(undefined);
		});

		it('should log when getting with logger', async () => {
			const logger = {debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn()};
			const issuerManager = new IssuerManager([], {logger});
			await issuerManager.get('http://unknown', 'key1');
			expect(logger.debug).toHaveBeenCalledWith("Getting issuer: http://unknown 'key1' size: 0");
			expect(logger.debug).toHaveBeenCalledWith('Issuer not found: http://unknown');
		});
	});
});
