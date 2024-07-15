import { Hono, Context } from 'hono'
import { rateLimiter } from './utils.ts'

const app = new Hono()

app.use(rateLimiter(1))
app.use(async (c: Context) => {
	const page = c.req.path.slice(1) || 'index'
	try {
		const { handler } = await import(`./pages/${page}.tsx`)
		return handler(c)
	} catch {
		return c.html('404 Not Found', 404)
	}
})

export default app
