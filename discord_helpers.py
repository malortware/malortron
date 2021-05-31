from discord.ext import commands

class DirectMessageOnly(commands.CheckFailure):
    pass

async def prompt(ctx:commands.Context, message, timeout=10):
    def check(msg):
        return ctx.author == msg.author

    await ctx.send(message)
    return await ctx.bot.wait_for('message', timeout=timeout, check=check)

async def enforce_direct_message(ctx:commands.Context):
    if ctx.guild is None:
        return True
    await ctx.message.delete()
    raise DirectMessageOnly('Shhh! Send your secrets to me privately!')
