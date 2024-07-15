import { Context } from 'hono'
import { Page } from './page.tsx'
import { cache } from './query.tsx'

export const handler = (c: Context) => {
	return c.html(
		<Page title="Home">
			<div class="container">
				<div class="p-5 mb-4 bg-light rounded-3">
					<div class="container-fluid py-5">
						<h1 class="display-5 fw-bold">The truth of NPM</h1>
						<p class="col-md-8 fs-4">
							Do you ever wonder how much weight does adding a NPM package to your project add?
						</p>
						<a href="#query">
							<button class="btn btn-primary btn-lg" type="button">
								Learn more
							</button>
						</a>
					</div>
				</div>
				<div id="query" class="row justify-content-lg-center">
					<div class="col-lg-6">
						<h2>Package size query</h2>
						<form action="/query">
							<div class="mb-3">
								<label for="packageName" class="form-label">
									Package Name
								</label>
								<input class="form-control" id="packageName" name="package" />
								<div class="form-text">
									Enter your favorite NPM package name here, and find out how much weight it adds to
									your project. E.g. <code>react</code>, <code>express</code>, <code>lodash</code>
								</div>
							</div>
							<button type="submit" class="btn btn-primary">
								Submit
							</button>
						</form>
					</div>
				</div>
				<div class="row justify-content-lg-center">
					<div class="col-lg-6">
						<h2>Popular packages</h2>
						{cache.size > 0 ? (
							<ul>
								{Array.from(cache.keys()).map(packageName => (
									<li>
										<a href={`/query?package=${packageName}`}>{packageName}</a>
									</li>
								))}
							</ul>
						) : (
							<p>No package queried yet</p>
						)}
					</div>
				</div>
			</div>
		</Page>
	)
}
