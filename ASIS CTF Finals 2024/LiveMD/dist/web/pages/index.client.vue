<script setup lang="ts">
const cookie = useCookie('markdown')
const markdown = ref(String(cookie.value || ''))
watch(() => markdown.value, (value) => cookie.value = value)

const route = useRoute()
if (route.query.markdown) {
    markdown.value = String(route.query.markdown)
}

const print = () => {
    window.open('/print', 'print', 'width=800,height=600')
}
const share = async () => {
    const url = new URL(location.href)
    url.searchParams.set('markdown', markdown.value)
    if (navigator.clipboard) await navigator.clipboard.writeText(url.href)
    else {
        const ta = document.createElement('textarea')
        ta.value = url.href
        ta.style.position = 'absolute'
        ta.style.left = '-9999px'
        document.body.appendChild(ta)
        ta.select()
        document.execCommand('copy')
        document.body.removeChild(ta)
    }
    alert('URL copied to clipboard!')
}
</script>
<template>
    <div class="container full">
        <div class="half editor">
            <textarea v-model="markdown" class="editor-ta" autofocus placeholder="Enter markdown here..."></textarea>
            <div>
                <button @click="print">Print</button>
                <button @click="share">Share</button>
            </div>
        </div>
        <Markdown :markdown="markdown" class="half" />
    </div>
</template>
<style scoped>
.container {
    display: flex;
    justify-content: space-between;
}

.half {
    width: 50%;
    height: 100%;
}

.editor {
    display: flex;
    flex-direction: column;
    justify-content: space-between;

}

.editor button {
    padding: 0.5em 1em;
    margin: 0.5em;
    border: none;
    border-radius: 0.25em;
    background-color: #007bff;
    color: white;
    cursor: pointer;
}

.editor-ta {
    height: 100%;
    width: 100%;
    box-sizing: border-box;
    padding: 45px;
    font-size: 16px;
    resize: none;
    border: none;
    outline: none;
}

@media (prefers-color-scheme: dark) {
    .container {
        background-color: #333;
        color: #fff;
    }

    .editor-ta {
        background-color: #333;
        color: #fff;
    }
}
</style>
