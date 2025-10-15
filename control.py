import discord
from discord.ext import commands

intents = discord.Intents.default()
intents.members = True
bot = commands.Bot(command_prefix='!', intents=intents)
TOKEN = "YOUR_BOT_TOKEN"
GUILD_ID = 1378864359287292065
COMMAND_CH_ID = 1425622507083534386

@bot.event
async def on_message(message):
    if message.author == bot.user:
        return 

    if message.channel.id == COMMAND_CH_ID:
        if message.content.startswith("boot"):
            channel1 = 1425635856911306834
            await message.channel.send("true")


