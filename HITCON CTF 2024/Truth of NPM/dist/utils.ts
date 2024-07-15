import { createMiddleware } from 'hono/factory'

export const rateLimiter = (limit: number) => {
	let count = 0
	return createMiddleware(async (c, next) => {
		if (count >= limit) {
			return c.json({ error: 'Rate limit exceeded' }, 429)
		}
		count++
		const res = await next()
		count--
		return res
	})
}

export async function asyncMapToArray<T, U>(asyncIterable: AsyncIterable<T>, callback: (val: T, idx: number) => U) {
	const arr: U[] = []
	let i = 0
	for await (const val of asyncIterable) arr.push(callback(val, i++))
	return arr
}
