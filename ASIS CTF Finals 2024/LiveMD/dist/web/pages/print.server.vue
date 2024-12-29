<script setup lang="ts">
const cookie = useCookie('markdown')
const markdown = computed(() => String(cookie.value || ''))
</script>
<template>
    <Markdown :markdown="markdown" class="auto-print full" />
</template>
