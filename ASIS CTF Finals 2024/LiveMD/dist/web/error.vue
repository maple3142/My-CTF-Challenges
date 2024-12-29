<script setup lang="ts">
import type { NuxtError } from '#app'

const props = defineProps<{
	error: NuxtError
}>()
</script>

<template>
	<div>
		<h2>{{ props.error.statusCode }} {{ props.error.message }}</h2>
	</div>
</template>
