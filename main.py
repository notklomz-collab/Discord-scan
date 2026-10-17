import asyncio
import io
import os
import re
import time
import zipfile

import discord
import aiohttp
from discord import app_commands

TOKEN = os.getenv("DISCORD_TOKEN")
BUILD_ID = "expanded-static-analysis-2026-10-17-v1"
MAX_UPLOAD_BYTES = 20 * 1024 * 1024
MAX_TOTAL_UNCOMPRESSED = 60 * 1024 * 1024
MAX_ENTRIES = 1500
MAX_ENTRY_BYTES = 8 * 1024 * 1024

intents = discord.Intents.default()
intents.message_content = True
client = discord.Client(intents=intents)
tree = app_commands.CommandTree(client)

# Static analysis only. Findings are indicators, not proof of malware.
RULES = [
    ("HIGH", "Minecraft session/account access",
     r"(launcher_accounts\.json|launcher_profiles\.json|\.minecraft[/\\].*(?:accounts|profiles)|accessToken|refreshToken|minecraftServices|msa.*token)",
     "References Minecraft launcher/session credentials or account data. Confirm surrounding code before concluding theft."),
    ("HIGH", "Discord credential/API access",
     r"(discord(?:app)?\.com/api/webhooks|mfa\.[A-Za-z0-9_-]{20,}|discord[_ -]?token|authorization[_ -]?token|/api/v\d+/users/@me)",
     "Contains Discord token, account API, or webhook-related strings."),
    ("HIGH", "Credential-store or browser-data access",
     r"(Login Data|Local State|Cookies|Network/Cookies|key4\.db|logins\.json|CryptUnprotectData|os_crypt|DPAPI)",
     "References browser or operating-system credential stores. These strings need contextual review."),
    ("HIGH", "Command or process execution",
     r"(java/lang/Runtime|java/lang/ProcessBuilder|powershell(?:\.exe)?|cmd\.exe|/bin/(?:sh|bash)|Runtime\.getRuntime)",
     "May start an external process or shell command."),
    ("HIGH", "Remote payload or dynamic code loading",
     r"(URLClassLoader|defineClass|ClassLoader\.defineClass|Instrumentation\.appendToSystemClassLoaderSearch|ScriptEngineManager)",
     "May load code dynamically; this can hide behavior from static scanning."),
    ("MEDIUM", "Network communication API",
     r"(HttpURLConnection|HttpsURLConnection|okhttp3?[/\.]|java/net/Socket|WebSocket|multipart/form-data|java/net/http/HttpClient)",
     "Network APIs are common in legitimate mods too. Destination and nearby code matter."),
    ("MEDIUM", "Local sensitive-data paths",
     r"(user\.home|APPDATA|\.minecraft|\.config|Local AppData|LevelDB|login_data)",
     "References local user or application data."),
    ("MEDIUM", "Reflection or obfuscation-related API",
     r"(java/lang/reflect|MethodHandles|invokedynamic|Base64\.getDecoder|StringBuilder\.reverse)",
     "May support dynamic behavior or obfuscation, but these are also common in normal software."),
    ("MEDIUM", "Input monitoring API",
     r"(org/jnativehook|GlobalScreen|Robot\.getPixelColor|addKeyListener|Keyboard\.isKeyDown)",
     "References input or keyboard APIs; review context for keylogging versus normal game input."),
    ("MEDIUM", "Potential Minecraft cheat feature",
     r"(KillAura|AimAssist|AutoClicker|Velocity\s*(?:Module|Hack)?|Reach\s*(?:Module|Hack)?|Scaffold(?:Walk)?|TriggerBot|NoFall|AntiKnockback|ChestStealer|AutoTotem|Xray(?:Module)?|ESP(?:Module)?|FlyHack|SpeedHack)",
     "Contains a known cheat-feature name. Names alone do not prove the mod implements or enables cheating."),
    ("LOW", "Encryption, encoding, or compression",
     r"(javax/crypto|Cipher\.getInstance|java/util/Base64|InflaterInputStream|GZIPInputStream|DeflaterOutputStream)",
     "Common in legitimate software; suspicious only when combined with other evidence."),
]
TEXT_EXTENSIONS = (".json", ".mf", ".txt", ".properties", ".xml", ".yml", ".yaml", ".cfg", ".conf", ".html", ".js", ".toml")
STRING_RE = re.compile(rb"[\x20-\x7e]{5,}")
URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,}", re.IGNORECASE)
DOMAIN_RE = re.compile(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|gg|dev|app|xyz|ru|cn|info|co|uk|me|de|fr|jp|cloud|site|online)\b")
SPOTIFY_DOMAINS = {"api.spotify.com", "accounts.spotify.com", "open.spotify.com", "spclient.wg.spotify.com", "apresolve.spotify.com", "gew1-spclient.spotify.com", "spotify.com"}


def extract_strings(data):
    return "\n".join(s.decode("latin-1", errors="ignore") for s in STRING_RE.findall(data))


def scan_jar(data):
    findings, notes, parts, entry_names = [], [], [], []
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
                entry_names.append(info.filename)
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
        matches = list(re.finditer(pattern, text, re.IGNORECASE))
        if matches:
            examples = list(dict.fromkeys(m.group(0)[:65].replace("\n", " ") for m in matches[:3]))
            findings.append((severity, title, explanation + " Evidence: " + ", ".join(repr(x) for x in examples) + f" ({len(matches)} string match(es))."))

    # Identify endpoints mentioned in readable strings. This cannot prove they are contacted at runtime.
    domains = set()
    for raw_url in URL_RE.findall(text):
        try:
            host = re.sub(r"^https?://", "", raw_url, flags=re.IGNORECASE).split("/")[0].split(":")[0].lower()
            if host:
                domains.add(host)
        except Exception:
            pass
    for domain in DOMAIN_RE.findall(text):
        domains.add(domain.lower())
    spotify = sorted(d for d in domains if d == "spotify.com" or d.endswith(".spotify.com"))
    other_domains = sorted(d for d in domains if d not in spotify)
    if spotify:
        notes.append("Spotify-related endpoint strings found: " + ", ".join(spotify[:8]) + ". This is consistent with Spotify integration but does not prove a connection occurs or that the JAR is safe.")
    if other_domains:
        notes.append("Other domain strings found (not proof of live connections): " + ", ".join(other_domains[:12]))
        if len(other_domains) > 12:
            notes.append(f"{len(other_domains) - 12} additional domain(s) omitted.")
    if not domains:
        notes.append("No readable URL/domain strings found; encrypted, constructed, or runtime-fetched endpoints may not be visible.")

    names_lower = "\n".join(entry_names).lower()
    if "fabric.mod.json" in names_lower:
        notes.append("Fabric metadata file present.")
    if "META-INF/mods.toml" in names_lower or "mods.toml" in names_lower:
        notes.append("Forge/NeoForge-style mods.toml metadata file present.")
    if "meta-inf/manifest.mf" in names_lower:
        notes.append("JAR manifest present.")
    notes.append(f"Archive inventory: {len(entry_names)} file entries; Java classes: {sum(1 for n in entry_names if n.lower().endswith('.class'))}.")

    high = sum(1 for sev, _, _ in findings if sev == "HIGH")
    medium = sum(1 for sev, _, _ in findings if sev == "MEDIUM")
    cheat = any("cheat feature" in title.lower() for _, title, _ in findings)
    if high >= 2 or (high >= 1 and medium >= 1):
        verdict = "SUSPICIOUS"
    elif high == 1 or medium >= 2 or cheat:
        verdict = "REVIEW"
    elif findings:
        verdict = "LOW SIGNALS"
    else:
        if spotify:
            verdict = "INFO"
        else:
            verdict = "NO MATCHES"
        notes.append("No configured risk indicators matched. This does NOT prove the JAR is safe.")
    return verdict, findings, notes


def make_embed(filename, size, verdict, findings, notes):
    colors = {
        "SUSPICIOUS": discord.Color.red(),
        "REVIEW": discord.Color.orange(),
        "LOW SIGNALS": discord.Color.gold(),
        "NO MATCHES": discord.Color.green(),
        "INFO": discord.Color.blue(),
        "INVALID": discord.Color.dark_grey(),
        "LIMIT EXCEEDED": discord.Color.dark_grey(),
    }
    summaries = {
        "SUSPICIOUS": "Several high-risk indicators matched. Treat as unsafe until investigated.",
        "REVIEW": "Potentially concerning or cheat-related indicators found. Review the evidence.",
        "LOW SIGNALS": "A few indicators matched, but they do not establish malicious behavior.",
        "NO MATCHES": "No configured indicators matched. This is not a guarantee of safety.",
        "INFO": "Spotify-related strings were found and no configured risk indicators matched. This is context, not proof of safety.",
        "INVALID": "The attachment could not be analyzed as a readable JAR archive.",
        "LIMIT EXCEEDED": "The archive exceeded scan safety limits and was not fully analyzed.",
    }
    embed = discord.Embed(title="MINECRAFT JAR THREAT INTELLIGENCE REPORT", description=summaries.get(verdict, "Analysis incomplete."), color=colors.get(verdict, discord.Color.blurple()))
    embed.add_field(name="FILE", value=discord.utils.escape_markdown(filename)[:200], inline=False)
    embed.add_field(name="VERDICT", value=verdict, inline=True)
    embed.add_field(name="SIZE", value=f"{size / 1024:.1f} KB", inline=True)
    embed.add_field(name="SCAN TYPE", value="Static inspection; file was not executed", inline=True)

    titles = [title.lower() for _, title, _ in findings]
    if any("minecraft session" in t or "credential-store" in t or "discord credential" in t for t in titles):
        classification = "Credential-access indicators present; theft is not confirmed from strings alone"
    elif any("cheat feature" in t for t in titles):
        classification = "Minecraft cheat-feature strings detected; functionality requires code-level confirmation"
    elif any("remote payload" in t or "process execution" in t for t in titles):
        classification = "Possible loader or process-launch behavior; inspect code paths"
    elif findings:
        classification = "Mixed behavior indicators; no malware family assigned"
    else:
        classification = "No configured indicators matched; status remains unverified"
    embed.add_field(name="BEHAVIOR ASSESSMENT", value=classification, inline=False)

    if findings:
        ordered = sorted(findings, key=lambda f: {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(f[0], 3))
        evidence = "\n\n".join(f"[{sev}] {title}\n{detail}" for sev, title, detail in ordered[:6])
        embed.add_field(name="INDICATORS & EVIDENCE", value=evidence[:1024], inline=False)
        if len(ordered) > 6:
            embed.add_field(name="Additional indicators", value=f"{len(ordered) - 6} additional rule(s) matched.", inline=False)
    else:
        embed.add_field(name="INDICATORS & EVIDENCE", value="No configured rule matched readable strings.", inline=False)

    if notes:
        embed.add_field(name="NETWORK, METADATA & ANALYSIS NOTES", value="\n".join("- " + n for n in notes)[:1024], inline=False)
    embed.add_field(name="CONFIDENCE", value="Heuristic confidence only. Static strings cannot reliably prove which endpoints execute, what data is transmitted, or whether a file is safe. Obfuscation and runtime downloads may evade this scan.", inline=False)
    embed.set_footer(text="Multiple indicators need manual confirmation • Never run suspicious JARs")
    return embed


ARCHIVE_CHANNEL_ID = 1560707571109855353



async def process_attachment(attachment, channel, user, origin_channel_id):
    if not attachment.filename.lower().endswith(".jar"):
        await channel.send("Please upload a Minecraft Java `.jar` file.")
        return
    if attachment.size > MAX_UPLOAD_BYTES:
        await channel.send("Maximum scan size is 20 MB.")
        return

    stage = "downloading uploaded file"
    try:
        timeout = aiohttp.ClientTimeout(total=45, connect=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(attachment.url) as response:
                if response.status != 200:
                    raise RuntimeError(f"Attachment CDN returned HTTP {response.status}")
                data = await response.read()
        if len(data) > MAX_UPLOAD_BYTES:
            await channel.send("The file exceeded the 20 MB scan limit.")
            return

        stage = "fetching archive channel"
        archive_channel = client.get_channel(ARCHIVE_CHANNEL_ID)
        if archive_channel is None:
            archive_channel = await client.fetch_channel(ARCHIVE_CHANNEL_ID)
        if not hasattr(archive_channel, "send"):
            await channel.send("The archive channel is not a text channel. Please check ARCHIVE_CHANNEL_ID.")
            return

        archive_embed = discord.Embed(
            title="UNTRUSTED JAR UPLOAD",
            description="Uploaded sample for moderator/security review. Do not download or run unless you know how to analyze malware safely.",
            color=discord.Color.dark_grey(),
        )
        archive_embed.add_field(name="Submitted filename", value=discord.utils.escape_markdown(attachment.filename)[:200], inline=False)
        archive_embed.add_field(name="Submitted by", value=f"{user} (ID: {user.id})", inline=False)
        archive_embed.add_field(name="Origin", value=f"<#{origin_channel_id}>", inline=True)
        archive_embed.add_field(name="Scan status", value="Analysis in progress", inline=True)

        stage = "uploading JAR to archive channel"
        await archive_channel.send(
            content="UNTRUSTED JAR UPLOAD for security review. Do not run this file.",
            file=discord.File(io.BytesIO(data), filename=attachment.filename),
            allowed_mentions=discord.AllowedMentions.none(),
        )
        try:
            await archive_channel.send(embed=archive_embed, allowed_mentions=discord.AllowedMentions.none())
        except discord.HTTPException as metadata_exc:
            print(f"Archive metadata message failed after file upload: status={metadata_exc.status}, code={metadata_exc.code}, text={metadata_exc.text}")

        stage = "scanning JAR"
        verdict, findings, notes = await asyncio.to_thread(scan_jar, data)
        report = make_embed(attachment.filename, len(data), verdict, findings, notes)
        report.add_field(name="Archived sample", value=f"Submitted sample was copied to <#{ARCHIVE_CHANNEL_ID}>.", inline=False)
        report.set_footer(text=f"Build {BUILD_ID} | Do not run suspicious JARs")
        stage = "sending report to upload channel"
        await channel.send(embed=report, allowed_mentions=discord.AllowedMentions.none())
    except discord.Forbidden as exc:
        print(f"Discord permission error during {stage}: status={exc.status}, code={exc.code}, text={exc.text}")
        await channel.send(f"Discord denied an action during {stage} (HTTP {exc.status}, code {exc.code}). Check Replit Console.")
    except discord.HTTPException as exc:
        print(f"Discord HTTP error during {stage}: status={exc.status}, code={exc.code}, text={exc.text}")
        await channel.send(f"Discord request failed during {stage} (HTTP {exc.status}, code {exc.code}). Build: {BUILD_ID}.")
    except (asyncio.TimeoutError, OSError, RuntimeError, aiohttp.ClientError) as exc:
        print(f"Scan/archive error during {stage}: {type(exc).__name__}: {exc}")
        await channel.send(f"Scan/archive failed during {stage}: {type(exc).__name__}. Check Replit Console.")


@tree.command(name="scan", description="Privately submit a Minecraft JAR for scanning")
@app_commands.describe(file="The Minecraft Java .jar file to scan")
async def scan(interaction: discord.Interaction, file: discord.Attachment):
    # The attachment is supplied directly to the slash command, not posted as a normal message.
    await interaction.response.send_message(
        "File received. Scanning now; the submitted sample will also be copied to the security archive channel.",
        ephemeral=True,
    )
    await process_attachment(file, interaction.channel, interaction.user, interaction.channel_id)


@client.event
async def on_ready():
    await tree.sync()
    print(f"Logged in as {client.user} (slash commands synced; build {BUILD_ID})")


if not TOKEN:
    raise RuntimeError("Set the DISCORD_TOKEN environment secret before starting the bot.")

client.run(TOKEN)
