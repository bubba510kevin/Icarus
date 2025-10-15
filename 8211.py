import discord
from discord.ext import commands

intents = discord.Intents.default()
intents.members = True
bot = commands.Bot(command_prefix='!', intents=intents)
TOKEN = "YOUR_BOT_TOKEN"
GUILD_ID = 1406111628990349423
LVAR = [ "Actor",
    "Affluenza",
    "Alley Rose",
    "Astronomy",
    "Best Friend",
    "Bourgeoisieses",
    "Boys & Girls",
    "(Can We Be Friends?)",
    "Caramel",
    "Care",
    "Checkmate",
    "Class Clown",
    "Comfort Crowd",
    "Connell",
    "Crush Culture",
    "Disaster",
    "Eleven Eleven",
    "The Exit",
    "Eye of the Night",
    "Fainted Love",
    "Fake",
    "Family Line",
    "The Final Fight",
    "Fight or Flight",
    "Footnote",
    "Forever with Me",
    "Found Heaven",
    "Generation Why",
    "Greek God",
    "Grow",
    "Heather",
    "Holidays",
    "Idle Town",
    "Jigsaw",
    "Killing Me",
    "The King",
    "Little League",
    "Lonely Dancers",
    "Lookalike",
    "Maniac",
    "Memories",
    "Miss You",
    "Movies",
    "My World",
    "Nauseous",
    "Never Ending Song",
    "(Online Love)",
    "The Other Side",
    "Overdrive",
    "People Watching",
    "Romeo",
    "The Story",
    "Summer Child",
    "Sunset Tower",
    "The Cut That Always Bleeds",
    "Telepath",
    "This Song",
    "Vodka Cranberry",
    "Winner",
    "Wish You Were Sober",
    "Yours"]
@bot.event
async def on_ready():
    CHANNEL_ID = 123456789012345678
    channel = bot.get_channel(CHANNEL_ID)
    await channel.send(f"Logged in as {bot.user}")

# finish the command changer
        
