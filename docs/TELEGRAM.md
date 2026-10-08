# Telegram setup and operation

WANCompass uses a Telegram bot you create and own. Each installation owner should create a dedicated bot through the official `@BotFather`; do not use a shared project bot, another person's token, or a token copied from an example. A bot token grants control of that bot, and polling updates should have one active consumer.

Telegram is optional. WANCompass works without it. Keep `[telegram].enabled = false` if you do not need bot commands or notifications.

## Create and connect your bot

1. In Telegram, open `@BotFather` and send `/newbot`.
2. Choose a display name and a unique bot username ending in `bot`.
3. Copy the token BotFather returns. Treat it like a password. Never put it in a command argument, public issue, screenshot, repository file, or AI prompt.
4. On the WANCompass host, from the checkout, run:

   ```sh
   sudo python3 tools/telegram_setup.py
   ```

5. Paste the token only at the helper's hidden prompt. It validates the token and reports the bot username, not the token.
6. Open your bot's private chat, tap **Start** or send it a message, and leave the chat open. The helper waits up to five minutes.
7. Check the identity it detected and confirm that it is you. If it is not, decline; the helper does not change the config.
8. The helper stores the token and your private chat ID in `/etc/netpulse/config.toml`, sends a test message, and restarts the `netpulse` service. Confirm the service is active and you receive the test message.

The setup helper removes any webhook and consumes earlier pending updates to establish a clean polling offset. This is appropriate for a newly created bot. Do not use a bot already connected to another application: setup can remove that webhook and consume its updates.

## Settings and privacy

- Keep `/etc/netpulse/config.toml` root-owned and readable only by the service group (normally mode `0640`).
- The chat ID belongs to your account/chat. There is intentionally no public sample chat ID; never copy another deployment's value.
- The helper asks you to confirm the first private chat before saving. Decline any identity you do not recognize.
- Daily digests, weekly reports, and device activity notifications are opt-in. Routine device notices default to off. Important WAN/system/control alerts follow the service policy.
- Messages can include router and device state. Use a private chat you control and protect notification previews on your devices.
- Telegram accepting a send request does not prove it was displayed or read.

For actual setting names and defaults, see [Configuration](CONFIGURATION.md).

## Add another account

The `--add` flow adds another private account to an existing installation. Use it only when the bot and WANCompass owner authorizes that person. The helper pauses the service during pairing, waits for a new private chat, shows its identity for confirmation, saves the additional chat ID, sends a message, and restarts the service. Added accounts can use bot commands and receive alerts, so keep the audience small and trusted.

```sh
sudo python3 tools/telegram_setup.py --add
```

## Troubleshooting

- **Token rejected:** create or copy the token again from your BotFather conversation and enter it only at the hidden prompt. Check outbound HTTPS connectivity.
- **No message arrives:** start the bot's private chat before the five-minute wait ends and use the account you intend to authorize.
- **Bot does not respond:** check `[telegram].enabled`, service status, and that the private chat ID belongs to the owner. Inspect service logs without printing config contents.
- **Multiple polling consumers:** do not run the same token in another service or development process. Use a dedicated bot for this installation.
- **Lost or exposed token:** revoke it with BotFather, then rerun setup with the replacement token. Treat logs, backups, and terminal transcripts as sensitive.

See [Troubleshooting](TROUBLESHOOTING.md) for service and network diagnostics.
