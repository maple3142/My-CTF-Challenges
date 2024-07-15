export const Page = (props: { title: string; children: unknown }) => (
	<html>
		<head>
			<title>{props.title}</title>
			<link
				href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css"
				rel="stylesheet"
				integrity="sha384-EVSTQN3/azprG1Anm3QDgpJLIm9Nao0Yz1ztcQTwFspd3yD65VohhpuuCOmLASjC"
				crossorigin="anonymous"
			></link>
		</head>
		<body>{props.children}</body>
	</html>
)
