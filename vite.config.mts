/// <reference types="vitest" />

import {defineConfig} from 'vitest/config';

export default defineConfig({
	test: {
		reporters: ['verbose', 'github-actions', 'junit'],
		outputFile: {
			junit: './test-results.xml',
		},
		coverage: {
			provider: 'v8',
			include: ['src/**/*.ts'],
			reporter: ['text', 'lcov'],
		},
		include: ['test/**/*.test.ts'],
	},
});
