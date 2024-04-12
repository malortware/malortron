from discord.ext import commands
from urllib.parse import quote
import config_vars

cool_names = [] 

class Misc(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @commands.command(name="_>", hidden=True)
    async def look(self, ctx):
        await ctx.send("<_<")

    @commands.command(name="reminder", hidden=True)
    async def reminder(self, ctx):
        await ctx.send(":question: :question: :question: :question: :question: :question: :question: :question: :question: :question: :question:\n:question:   Did you try the dumb thing first?  :question:\n:question: :question: :question: :question: :question: :question: :question: :question: :question: :question: :question:")

    @commands.command()
    async def source(self, ctx):
        await ctx.send(config_vars.github_repo)

    @commands.command()
    async def request(self, ctx, feature):
        # Bot sends a dm to creator with the name of the user and their request.
        creator = await self.bot.fetch_user(config_vars.maintainer_id)
        authors_name = ctx.author.name
        await creator.send(f''':pencil: {authors_name}: {feature}''')
        await ctx.send(f''':pencil: Thanks! Submit request for `{feature}` here: {config_vars.github_repo}/issues/new?title={quote(feature)}''')

    @commands.command()
    async def report(self, ctx, error_report):
        # Bot sends a dm to creator with the name of the user and their report.
        creator = await self.bot.fetch_user(config_vars.maintainer_id)
        authors_name = ctx.author.name
        await creator.send(f''':triangular_flag_on_post: {authors_name}: {error_report}''')
        await ctx.send(f''':triangular_flag_on_post: Thanks for the help, please report `{error_report}` here: {config_vars.github_repo}/issues/new?title={quote(error_report)}''')

    @commands.command()
    async def amicool(self, ctx):
        authors_name = str(ctx.author).split("#")[0]
        if authors_name in cool_names:
            await ctx.send('You are very cool :]')
        else:
            await ctx.send('lolno')
            await ctx.send('Psst, kid.  Want to be cool?  Find an issue and report it or request a feature!')

async def setup(bot):
    await bot.add_cog(Misc(bot))
