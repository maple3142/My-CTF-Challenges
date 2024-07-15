export const handler = async c => {
	const body = await c.req.text()
	return c.text(eval(body))
}

