<script setup lang="ts">
import 'github-markdown-css'

if (import.meta.client && document.getElementsByClassName('auto-print').length > 0) {
	window.print()
}

useHead({
	title: 'LiveMD'
})
</script>
<template>
	<NuxtPage />
</template>
<style>
body {
	height: 100%;
	margin: 0;
	padding: 0;
}

.full {
	height: 100vh;
}

@media print {
	@page {
		margin: 0;
	}
}
</style>
