<script setup lang="ts">
import { marked } from 'marked'
import { sanitize } from '../purify'

const props = defineProps<{
    markdown: string
}>()
const html = computed(() => marked(props.markdown, { async: false }))
const sanitizedHtml = computed(() => sanitize(html.value))
</script>
<template>
    <div class="markdown-body" v-html="sanitizedHtml"></div>
</template>
<style scoped>
.markdown-body {
    box-sizing: border-box;
    margin: 0 auto;
    padding: 45px;
}

@media (max-width: 767px) {
    .markdown-body {
        padding: 15px;
    }
}
</style>
