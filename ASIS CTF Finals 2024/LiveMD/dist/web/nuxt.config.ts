// https://nuxt.com/docs/api/configuration/nuxt-config
export default defineNuxtConfig({
	compatibilityDate: '2024-11-01',
	devtools: { enabled: false },
	modules: ['nuxt-security'],
	nitro: {
		esbuild: {
			options: {
				target: 'esnext'
			}
		}
	},
	vite: {
		build: {
			target: 'esnext'
		}
	},
	security: {
		headers: {
			contentSecurityPolicy: {
				'script-src': ["'nonce-{{nonce}}'", "'strict-dynamic'"],
				'upgrade-insecure-requests': false // allow HTTP access
			}
		},
		rateLimiter: false // disable this to prevent bot from being rate limited
	}
})
