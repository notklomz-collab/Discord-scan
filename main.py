import os
import discord
from discord import app_commands

TOKEN = os.getenv("DISCORD_TOKEN")

intents = discord.Intents.default()
client = discord.Client(intents=intents)
tree = app_commands.CommandTree(client)


@tree.command(name="scan", description="Show a demo file result and reupload the file")
@app_commands.describe(file="File to include in the demo result")
async def scan(interaction: discord.Interaction, file: discord.Attachment):
    # This is a mock/demo only. It does not inspect the file for malware.
    await interaction.response.defer(thinking=True)
    try:
        upload = await file.to_file()
        embed = discord.Embed(
            title="🛡️ File Scan Result (Demo)",
            description=(
                "✅ **No Malware Detected — Trusted!**\n\n"
                "⚠️ **Demo only:** this file was not actually scanned. "
                "Do not use this message as a security verdict."
            ),
            color=discord.Color.green(),
        )
        embed.add_field(name="File", value=f"`{discord.utils.escape_markdown(file.filename)}`", inline=False)
        embed.set_footer(text="Demo Scanner • Not a security verdict")
        await interaction.followup.send(embed=embed, file=upload)
    except (discord.HTTPException, discord.NotFound):
        await interaction.followup.send(
            "I couldn't reupload that attachment. It may be too large or no longer available.",
            ephemeral=True,
        )


@client.event
async def on_ready():
    await tree.sync()
    print(f"Logged in as {client.user} (slash commands synced)")


if not TOKEN:
    raise RuntimeError("Set the DISCORD_TOKEN environment secret before starting the bot.")

client.run(TOKEN)
