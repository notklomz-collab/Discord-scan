import asyncio
import io
import os
import re
import zipfile

import discord
from discord import app_commands

TOKEN = os.getenv("DISCORD_TOKEN")
MAX_UPLOAD_BYTES = 20 * 1024 * 1024
MAX_TOTAL_UNCOMPRESSED = 60 * 1024 * 1024
MAX_ENTRIES = 1500
MAX_ENTRY_BYTES = 8 * 1024 * 1024

intents = discord.Intents.default()
client = discord.Client(intents=intents)
tree = app_commands.CommandTree(client)

# Static heuristics: indicators are evidence to review, not proof of malware.
RULES = [
    ("HIGH", "Minecraft account-file reference",
     r"(launcher_accounts\.json|launcher_profiles\.json|\.minecraft[/\\].*(?:accounts|profiles))",
     "References Minecraft launcher/account-related files."),
    ("HIGH", "Discord token or webhook-related string",
     r"(discord(?:app)?\.com/api/webhooks|mfa\.[A-Za-z0-9_-]{20,}|(?:discord|authorization)[ _-]?token|/api/v\d+/users/@me)",
     "Contains Discord token, account API, or webhook-related strings."),
    ("HIGH", "Network communication API",
     r"(HttpURLConnection|HttpsURLConnection|okhttp3?[/\.]|java/net/Socket|WebSocket|multipart/form-data)",
     "Contains networking code. Review alongside sensitive-file access."),
    ("HIGH", "Process or shell execution",
     r"(java/lang/Runtime|java/lang/ProcessBuilder|\.exec\s*\(|powershell(?:\.exe)?|cmd\.exe|/bin/(?:sh|bash))",
     "May launch external processes or commands."),
    ("MEDIUM", "Sensitive local-data reference",
     r"(user\.home|APPDATA|Local AppData|\.minecraft|login_data|Cookies|LevelDB)",
     "References user or application data locations."),
    ("MEDIUM", "Dynamic loading or reflection",
     r"(java/lang/reflect|ClassLoader|defineClass|MethodHandles|javax/script|URLClassLoader)",
     "Can load or invoke code dynamically, limiting static analysis."),
    ("LOW", "Encoding, encryption, or compression API",
     r"(java/util/Base64|javax/crypto|Cipher\.getInstance|InflaterInputStream|GZIPInputStream)",
     "These APIs can transform data but are also common in legitimate software."),
    ("MEDIUM", "Keyboard/input monitoring API",
     r"(java/awt/Robot|org/jnativehook|GlobalScreen|KeyListener)",
     "References input-monitoring APIs."),
]

TEXT_EXTENSIONS = (".json", ".mf", ".txt", ".properties", ".xml", ".yml", ".yaml", ".cfg", ".conf", ".html", ".js")
STRING_RE = re.compile(rb"[\x20-\x7e]{5,}")


def extract_strings(data):
    return "\n".join(s.decode("latin-1", errors="ignore") for s in STRING_RE.findall(data))


def scan_jar(data):
    findings, notes, parts = [], [], []
    if not zipfile.is_zipfile(io.BytesIO(data)):
        return "INVALID", findings, ["Not a readable ZIP/JAR archive."]
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ENTRIES:
                return "LIMIT EXCEEDED", findings, ["Archive contains too many entries for the safe scan limit."]
            total = 0
            has_class = False
            for info in infos:
                if info.is_dir():
                    continue
                total += info.file_size
                if total > MAX_TOTAL_UNCOMPRESSED:
                    return "LIMIT EXCEEDED", findings, ["Expanded archive exceeds the safe scan limit."]
                if info.file_size > MAX_ENTRY_BYTES:
                    notes.append("Skipped oversized entry: " + info.filename[:80])
                    continue
                name = info.filename.lower()
                if name.endswith(".class"):
                    has_class = True
                if not (name.endswith(".class") or name.endswith(TEXT_EXTENSIONS)):
                    continue
                try:
                    parts.append(extract_strings(archive.read(info)))
                except (OSError, RuntimeError, zipfile.BadZipFile):
                    notes.append("Could not read entry: " + info.filename[:80])
            if not has_class:
                notes.append("No Java class files found; this may not be a normal mod JAR.")
    except (OSError, zipfile.BadZipFile, RuntimeError, ValueError):
        return "INVALID", findings, ["Archive could not be safely read."]

    text = "\n".join(parts)
    for severity, title, pattern, explanation in RULES:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            evidence = match.group(0)[:80].replace("\n", " ")
            findings.append((severity, title, explanation + " Example string: " + repr(evidence)))

    high = sum(1 for sev, _, _ in findings if sev == "HIGH")
    medium = sum(1 for sev, _, _ in findings if sev == "MEDIUM")
    if high >= 2 or (high >= 1 and medium >= 1):
        verdict = "SUSPICIOUS"
    elif high == 1 or medium >= 2:
        verdict = "REVIEW"
    elif findings:
        verdict = "LOW SIGNALS"
    else:
        verdict = "NO MATCHES"
        notes.append("No configured indicators matched. This does NOT prove the JAR is safe.")
    return verdict, findings, notes


def make_embed(filename, size, verdict, findings, notes):
    colors = {
        "SUSPICIOUS": discord.Color.red(),
        "REVIEW": discord.Color.orange(),
        "LOW SIGNALS": discord.Color.gold(),
        "NO MATCHES": discord.Color.green(),
        "INVALID": discord.Color.dark_grey(),
        "LIMIT EXCEEDED": discord.Color.dark_grey(),
    }
    summaries = {
        "SUSPICIOUS": "Multiple high-risk indicators found. Do not run this JAR until investigated.",
        "REVIEW": "Potentially concerning indicators found. Review the evidence before running it.",
        "LOW SIGNALS": "Some indicators found, but they do not prove malicious behavior.",
        "NO MATCHES": "No configured indicators matched. This is not a clean bill of health.",
        "INVALID": "The attachment could not be analyzed as a JAR archive.",
        "LIMIT EXCEEDED": "The archive exceeded safety limits and was not fully analyzed.",
    }
    embed = discord.Embed(title="MINECRAFT JAR THREAT REPORT", description=summaries.get(verdict, "Analysis incomplete."), color=colors.get(verdict, discord.Color.blurple()))
    embed.add_field(name="FILE", value=discord.utils.escape_markdown(filename)[:200], inline=False)
    embed.add_field(name="VERDICT", value=verdict, inline=True)
    embed.add_field(name="SIZE", value=f"{size / 1024:.1f} KB", inline=True)

    if findings:
        high = sum(1 for sev, _, _ in findings if sev == "HIGH")
        if high >= 2:
            classification = "Potential credential stealer or loader; requires manual confirmation"
        elif any("Network communication" in title for _, title, _ in findings) and any("account-file" in title for _, title, _ in findings):
            classification = "Possible Minecraft account stealer behavior"
        elif any("Process or shell" in title for _, title, _ in findings):
            classification = "Possible process launcher or staged payload behavior"
        else:
            classification = "Suspicious behavior indicators; malware family not identified"
        embed.add_field(name="CLASSIFICATION", value=classification, inline=False)
        embed.add_field(name="EVIDENCE", value="\n\n".join(f"[{sev}] {title}\n{detail}" for sev, title, detail in findings[:5])[:1024], inline=False)
        if len(findings) > 5:
            embed.add_field(name="Additional matches", value=f"{len(findings) - 5} more indicators omitted.", inline=False)
    else:
        embed.add_field(name="CLASSIFICATION", value="No known indicators matched; threat status remains unverified.", inline=False)

    if notes:
        embed.add_field(name="ANALYSIS NOTES", value="\n".join("- " + n for n in notes)[:1024], inline=False)
    embed.add_field(name="LIMITATIONS", value="Static string heuristics only. Obfuscation, encrypted payloads, and runtime-fetched code can evade detection. No malware family name is assigned without evidence.", inline=False)
    embed.set_footer(text="Do not run suspicious JARs to test them")
    return embed


@tree.command(name="scan", description="Scan a Minecraft Java JAR for suspicious indicators")
@app_commands.describe(file="Minecraft mod/client JAR to inspect")
async def scan(interaction: discord.Interaction, file: discord.Attachment):
    if not file.filename.lower().endswith(".jar"):
        await interaction.response.send_message("Please upload a Minecraft Java .jar file.", ephemeral=True)
        return
    if file.size > MAX_UPLOAD_BYTES:
        await interaction.response.send_message("Maximum scan size is 20 MB.", ephemeral=True)
        return
    await interaction.response.defer(thinking=True)
    try:
        data = await file.read(use_cached=True)
        if len(data) > MAX_UPLOAD_BYTES:
            await interaction.followup.send("The file exceeded the 20 MB scan limit.", ephemeral=True)
            return
        verdict, findings, notes = await asyncio.to_thread(scan_jar, data)
        await interaction.followup.send(embed=make_embed(file.filename, len(data), verdict, findings, notes))
    except (discord.HTTPException, asyncio.TimeoutError, OSError) as exc:
        await interaction.followup.send(f"Scan failed ({type(exc).__name__}). Try a smaller JAR.", ephemeral=True)


@client.event
async def on_ready():
    await tree.sync()
    print(f"Logged in as {client.user} (slash commands synced)")


if not TOKEN:
    raise RuntimeError("Set the DISCORD_TOKEN environment secret before starting the bot.")

client.run(TOKEN)
