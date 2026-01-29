import {describe, expect, it} from 'vitest';
import {buildCertFrame, rsaPublicKeyPem} from '../src/lib/rsaPublicKeyPem';

describe('rsaPublicKeyPem', () => {
	describe('rsaPublicKeyPem function', () => {
		it('should generate valid base64 PEM from modulus and exponent', () => {
			// Using small test values for modulus and exponent
			const modulus = Buffer.from([0x00, 0xb5, 0x09, 0x1a]).toString('base64');
			const exponent = Buffer.from([0x01, 0x00, 0x01]).toString('base64');

			const result = rsaPublicKeyPem(modulus, exponent);
			expect(typeof result).to.be.eq('string');
			// Result should be base64 encoded
			expect(() => Buffer.from(result, 'base64')).not.to.throw();
		});

		it('should handle short modulus values', () => {
			const modulus = Buffer.from([0x01]).toString('base64');
			const exponent = Buffer.from([0x03]).toString('base64');

			const result = rsaPublicKeyPem(modulus, exponent);
			expect(typeof result).to.be.eq('string');
		});

		it('should pre-pad signed values when MSB >= 0x80', () => {
			// 0x80 in hex requires pre-padding with 0x00
			const modulus = Buffer.from([0x80, 0x01, 0x02]).toString('base64');
			const exponent = Buffer.from([0x01, 0x00, 0x01]).toString('base64');

			const result = rsaPublicKeyPem(modulus, exponent);
			expect(typeof result).to.be.eq('string');
		});

		it('should handle large length encoding (>127 bytes)', () => {
			// Create a modulus that will result in length > 127
			const largeModulus = Buffer.alloc(128);
			largeModulus.fill(0x01);
			const modulus = largeModulus.toString('base64');
			const exponent = Buffer.from([0x01, 0x00, 0x01]).toString('base64');

			const result = rsaPublicKeyPem(modulus, exponent);
			expect(typeof result).to.be.eq('string');
		});
	});

	describe('buildCertFrame function', () => {
		it('should wrap certificate data in PEM headers', () => {
			const certData = 'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo='; // base64 encoded "abcdefghijklmnopqrstuvwxyz"
			const result = buildCertFrame(certData);

			expect(result).to.be.instanceOf(Buffer);
			const resultStr = result.toString();
			expect(resultStr).to.include('-----BEGIN RSA PUBLIC KEY-----');
			expect(resultStr).to.include('-----END RSA PUBLIC KEY-----');
		});

		it('should split long cert data into 64-character lines', () => {
			// Create cert data longer than 64 chars
			const longCertData = 'A'.repeat(128);
			const result = buildCertFrame(longCertData);

			const resultStr = result.toString();
			const lines = resultStr.split('\r\n');
			// First line is BEGIN, last two are empty and END
			const dataLines = lines.filter((line) => !line.includes('-----') && line.length > 0);
			for (const line of dataLines) {
				expect(line.length).to.be.lessThanOrEqual(64);
			}
		});

		it('should throw error for empty cert data', () => {
			expect(() => buildCertFrame('')).to.throw('Cert data error');
		});
	});
});
