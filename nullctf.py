import logging
logging.basicConfig(level=logging.INFO)

import discord
from discord.ext.commands import Bot
from discord.ext import commands

import help_info
import config_vars

client = discord.Client()
bot = commands.Bot(command_prefix=">")

extensions = ['ctf', 'encoding', 'cipher', 'utility'] # 'ctftime', 'configuration',
cool_names = ['nullpxl', 'Yiggles', 'JohnHammond', 'voidUpdate', 'Michel Ney', 'theKidOfArcrania', 'l14ck3r0x01', 'hasu', 'KFBI', 'mrFu', 'warlock_rootx', 'd347h4ck'] 

@bot.event
async def on_ready():
    print(f"{bot.user.name} - Online")
    print(f"discord.py {discord.__version__}\n")
    print("-------------------------------")
    await bot.change_presence(activity=discord.Activity(type=discord.ActivityType.watching, name="you.. >help"))

@bot.command()
async def source(ctx):
    await ctx.send(config_vars.github_repo)

@bot.event
async def on_command_error(ctx: commands.Context, error):
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

@bot.command()
async def request(ctx, feature):
    # Bot sends a dm to creator with the name of the user and their request.
    creator = await bot.fetch_user(config_vars.maintainer_id)
    authors_name = str(ctx.author)
    await creator.send(f''':pencil: {authors_name}: {feature}''')
    await ctx.send(f''':pencil: Thanks! Submit "{feature}" request here {config_vars.github_repo}/issues/new?title={feature}''')
    

@bot.command()
async def report(ctx, error_report):
    # Bot sends a dm to creator with the name of the user and their report.
    creator = await bot.fetch_user(config_vars.maintainer_id)
    authors_name = str(ctx.author)
    await creator.send(f''':triangular_flag_on_post: {authors_name}: {error_report}''')
    await ctx.send(f''':triangular_flag_on_post: Thanks for the help, "{error_report}" has been reported!''')

@bot.command()
async def amicool(ctx):
    authors_name = str(ctx.author).split("#")[0]
    if authors_name in cool_names:
        await ctx.send('You are very cool :]')
    else:
        await ctx.send('lolno')
        await ctx.send('Psst, kid.  Want to be cool?  Find an issue and report it or request a feature!')

if __name__ == '__main__':
    for extension in extensions:
        bot.load_extension('cogs.' + extension)
    bot.run(config_vars.discord_token)
