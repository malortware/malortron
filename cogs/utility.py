import urllib.parse
import urllib.request
import random
import re
import operator
import json
from discord.ext import commands
from collections import Counter
from bs4 import BeautifulSoup

class Utility(commands.Cog):

    def __init__(self, bot):
        self.bot = bot

    @commands.command(aliases=['char'])
    async def characters(self, ctx, string):
        await ctx.send(len(string))

    @commands.command(aliases=['wc'])
    async def wordcount(self, ctx, *args):
        await ctx.send(len(args))

    @commands.command(aliases=['rev'])
    async def reverse(self, ctx, message):
        await ctx.send(message[::(- 1)])

    @commands.command()
    async def counteach(self, ctx, message):
        count = {}
        
        for char in message:
            if char in count.keys():
                count[char] += 1
            else:
                count[char] = 1
        
        await ctx.send(str(count))

    @commands.command(aliases=['head'])
    async def magicb(self, ctx, filetype):
        file = open('magic.json').read()
        alldata = json.loads(file)
        try:
            messy_signs = str(alldata[filetype]['signs'])
            signs = messy_signs.split('[')[1].split(',')[0].split(']')[0].replace("'", '')
            filetype = alldata[filetype]['mime']
            await ctx.send(f'''{filetype}: {signs}''')
        except: # if the filetype is not in magicb.json...
            await ctx.send(f"{filetype} not found :(  If you think this filetype should be included please do `>request \"magicb {filetype}\"`")

    @commands.command()
    async def twitter(self, ctx, twituser):
        await ctx.send('https://twitter.com/' + twituser)

    @commands.command()
    async def github(self, ctx, gituser):
        await ctx.send('https://github.com/' + gituser)

    @commands.command(aliases=['5050', 'flip'])
    async def cointoss(self, ctx):
        choice = random.randint(1, 2)
        
        if choice == 1:
            await ctx.send('heads')
        
        if choice == 2:
            await ctx.send('tails')

    @commands.command()
    async def cewl(self, ctx: commands.Context, url, count: int = 100, word_len: str = "5-20", show_counts: bool = False):
        if not url.startswith("http"):
            url = f"https://{url}"

        body = urllib.request.urlopen(url).read()
        soup = BeautifulSoup(body, 'html.parser')

        element = soup.find("body")
        if "wikipedia.org" in url:
            element = soup.find(id="bodyContent")

        tokens = element.get_text(" ", strip=True).lower().split(" ")
        nonPunct = re.compile('.*[A-Za-z].*')
        raw_words = [w for w in tokens if nonPunct.match(w)]
        min_len, max_len = [int(n) for n in word_len.split("-")]
        raw_words = [word for word in raw_words if len(word) >= min_len and len(word) <= max_len and word.isalpha()]
        raw_word_count = Counter(raw_words)

        results = sorted(
            raw_word_count.items(),
            key=operator.itemgetter(1),
            reverse=count > 0
        )

        results = results[:abs(count)]
        results = "\n".join(f"{word} - {count}" if show_counts else word for word, count in results)
        await ctx.send(f'```\n{results}```')

async def setup(bot):
    await bot.add_cog(Utility(bot))
