import base64
import binascii
import collections
import string
import urllib.parse
import discord
from discord.ext import commands

class EncodingDecoding():

    def __init__(self, bot):
        self.bot = bot

    @commands.command()  # Encode or decode base64
    async def b64(self, ctx, encode_or_decode, string):  # Usage: b64 encode/decode <message> - if message has spaces use quotations
        byted_str = str.encode(string)
        if encode_or_decode == 'decode':
            decoded = base64.b64decode(byted_str).decode('utf-8')
            await ctx.send(decoded)
        if encode_or_decode == 'encode':
            encoded = base64.b64encode(byted_str).decode('utf-8').replace('\n', '')
            await ctx.send(encoded)

    @commands.command()
    async def binary(self, ctx, encode_or_decode, string):
        if encode_or_decode == 'decode':
            data = int(string, 2)
            decoded = data.to_bytes((data.bit_length() + 7) // 8, 'big').decode()  # Encode or decode binary
            await ctx.send(decoded)  # Usage: binary encode/decode <message> - if message has spaces use quotations
        if encode_or_decode == 'encode':
            encoded = bin(int.from_bytes(string.encode(), 'big')).replace('b', '')
            await ctx.send(encoded)

    @commands.command()
    async def hex(self, ctx, encode_or_decode, string):
        if encode_or_decode == 'decode':
            decoded = binascii.unhexlify(string).decode('ascii')
            await ctx.send(decoded)
        if encode_or_decode == 'encode':
            byted = string.encode()
            encoded = binascii.hexlify(byted).decode('ascii')  # Encode or decode hex
            await ctx.send(encoded)  # Usage: hex encode/decode <message> - if message has spaces use quotations

    @commands.command()
    async def url(self, ctx, encode_or_decode, message):
        if encode_or_decode == 'decode':
            if '%20' in message:
                message = message.replace('%20', '(space)')
                await ctx.send(urllib.parse.unquote(message))
            else:
                await ctx.send(urllib.parse.unquote(message))
        if encode_or_decode == 'encode':
            await ctx.send(urllib.parse.quote(message))
  # Encode or decode in url
def setup(bot):  # Usage: url encode/decode <message> - if message has spaces use quotations
    bot.add_cog(EncodingDecoding(bot))