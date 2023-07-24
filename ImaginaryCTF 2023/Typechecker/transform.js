const ts = require('typescript')

function randstr(n) {
	const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
	let res = ''
	for (let i = 0; i < n; i++) {
		res += chars[Math.floor(Math.random() * chars.length)]
	}
	return res
}

const filePath = './source.ts'
const program = ts.createProgram([filePath], {})
const checker = program.getTypeChecker()
const source = program.getSourceFile(filePath)
const printer = ts.createPrinter()

// construct a type replacement map from top-level type aliases
const typeReplacement = new Map()
ts.forEachChild(source, node => {
	if (ts.isTypeAliasDeclaration(node)) {
		const idnode = node.getChildAt(1)
		const id = idnode.getText()
		if (!typeReplacement.has(id)) {
			typeReplacement.set(id, randstr(16))
		}
	}
})

const { transformed } = ts.transform(source, [
	context => {
		return node => {
			const visitWithCtx = myctx => node => {
				if (ts.isIdentifier(node)) {
					const id = node.getText()
					if (typeReplacement.has(id)) {
						return ts.factory.createIdentifier(typeReplacement.get(id))
					}
					if (myctx && myctx.has(id)) {
						return ts.factory.createIdentifier(myctx.get(id))
					}
				}
				if (ts.isTypeAliasDeclaration(node)) {
					const typeParameterReplacement = new Map()
					ts.forEachChild(node, child => {
						if (ts.isTypeParameterDeclaration(child)) {
							typeParameterReplacement.set(child.getChildAt(0).getText(), randstr(16))
						}
					})
					return ts.visitEachChild(node, visitWithCtx(typeParameterReplacement), context)
				}
				return ts.visitEachChild(node, visitWithCtx(myctx), context)
			}
			return ts.visitNode(node, visitWithCtx(null))
		}
	}
])
const out = printer.printFile(transformed[0])
process.stdout.write(out)
