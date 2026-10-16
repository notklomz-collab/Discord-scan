# Discord Scan (Demo)

A Discord slash-command bot that reuploads a user-provided attachment alongside a clearly labeled **mock** result embed. It does not scan files and must not be represented as a real malware verdict.

## Files
- `main.py` — `/scan` command and attachment reupload
- `requirements.txt` — Python dependency

## Run
1. Use Python 3.10+.
2. Install dependencies: `pip install -r requirements.txt`
3. Set the environment variable `DISCORD_TOKEN` to your bot token in your hosting provider's **Secrets / Environment Variables** page. Never commit the token to GitHub or share it in chat.
4. Invite the bot with the `bot` and `applications.commands` scopes, and allow it to send messages and attach files.
5. Start the app with `python main.py`.
6. In Discord, use `/scan` and attach a file.

The response says **Demo only — file not actually scanned**. Files are subject to Discord upload limits. Keep the bot running for commands to work.
