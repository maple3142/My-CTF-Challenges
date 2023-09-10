# Project Structure

* `client`: Client source code (This is the main part of the challenge, focus on this)
* `server`: Server source code (No intended vulnerability here, you can ignore this)
* `bot`: The container for the bot (This shows how the bot will interact with the server, and you need to get RCE in this)
* `spawner`: A simple instancer for spawning bots (You can ignore this)

# Run this challenge locally

## Requirements

* Node.js 18
* Yarn 1
* Docker

## Commands

```sh
(
    cd client; yarn && yarn build
)
cp -r client/release/0.0.0/linux-unpacked bot
(
    cd bot; musl-gcc readflag.c -o readflag -static -Os -s -DFLAG='"flag{asd}"'
)
./spawner/update.sh
docker compose up --build
```
