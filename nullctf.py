import logging
logging.basicConfig(level=logging.INFO)

import asyncio
import discord
from discord.ext import commands
from typing import List

import config_vars
import healthcheck

class MalortronBot(commands.Bot):
    def __init__(
        self,
        *args,
        extensions: List[str],
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.initial_extensions = extensions

    async def setup_hook(self):
        for extension in self.initial_extensions:
            await self.load_extension('cogs.' + extension)
        await self.tree.sync()
        await healthcheck.start(self, port=config_vars.port)
    
    async def on_ready(self):
        print(f"{self.user.name} - Online")
        print(f"discord.py {discord.__version__}\n")
        print("-------------------------------")
        await self.change_presence(activity=discord.Activity(type=discord.ActivityType.watching, name="you.. >help"))

    async def on_command_error(self, ctx: commands.Context, error: commands.CommandError):
        if isinstance(error, commands.UserInputError):
            await ctx.send_help(ctx.command)
        # elif isinstance(error, commands.MissingPermissions):
        #     await ctx.send("You do not have the appropriate permissions to run this command.")
        # elif isinstance(error, commands.BotMissingPermissions):
        #     await ctx.send("I don't have sufficient permissions!")
        # elif isinstance(error, commands.MissingRole):
        #     await ctx.send("You don't have the appropriate role to run this command")
        else:
            try:
                error = error.original
            except AttributeError:
                pass
            await ctx.send(error)

async def main():
    # logger = logging.getLogger('discord')
    # logger.setLevel(logging.INFO)

    intents = discord.Intents.default()
    intents.message_content = True

    extensions = ['ctf', 'encoding', 'cipher', 'utility', 'inventory', 'secret', 'misc']

    bot = MalortronBot(command_prefix=">", intents=intents, extensions=extensions)
    await bot.start(config_vars.discord_token)

if __name__ == '__main__':
    asyncio.run(main())
