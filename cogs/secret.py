import base64, hashlib, asyncio
import discord
from discord.ext import commands
from cryptography.fernet import Fernet
from pymodm import MongoModel, fields
from datetime import datetime
from discord_helpers import prompt, enforce_direct_message

class SecretChallenge(MongoModel):
    flag_hash = fields.CharField(required=True, primary_key=True)
    name = fields.CharField(required=True)
    message_enc = fields.CharField(required=True)
    creator = fields.CharField(required=True)
    created_at = fields.DateTimeField(required=True)
    solved_by = fields.ListField(fields.CharField(), default=[], blank=True)

    def add_solver(self, user):
        SecretChallenge.objects.raw({'_id': self.flag_hash}).update({'$addToSet': {'solved_by': user}})

def keygen(key: str):
    key = key.encode()
    if len(key) < 32:
        padding = b'0' * (32 - len(key))
        key = key + padding
    key = key[:32]
    return base64.urlsafe_b64encode(key)

def encrypt(key:str, msg:str):
    key = keygen(key)
    f = Fernet(key)
    return f.encrypt(msg.encode()).decode()

def decrypt(key:str, msg:str):
    key = keygen(key)
    f = Fernet(key)
    return f.decrypt(msg.encode()).decode()

class Secret(commands.Cog):

    def __init__(self, bot):
        self.bot = bot

    @commands.group(hidden=True)
    async def secret(self, ctx: commands.Context):
        """
        Manage Secret Challenges
        """
        if ctx.invoked_subcommand is None:
            await ctx.send_help(ctx.command)

    @secret.command(name='add', aliases=['create'])
    @commands.check(enforce_direct_message)
    async def add(self, ctx: commands.Context, name: str):
        """
        Add a secret challenge
        """
        flag = None
        msg = None
        try:
            flag = await prompt(ctx, 'Enter challenge flag:', timeout=60)
            msg = await prompt(ctx, 'Enter challenge completion message:', timeout=60)
        except asyncio.TimeoutError:
            await ctx.send('Challenge creation aborted.')
            return

        ciphertext = encrypt(flag.content, msg.content)
        flag_hash = hashlib.sha256(flag.content.encode()).hexdigest()

        secret = SecretChallenge(
            name=name,
            flag_hash=flag_hash,
            message_enc=ciphertext,
            creator=ctx.author.mention,
            created_at=datetime.utcnow(),
        )

        secret.save()

        await ctx.send(f'Created new secret challenge: `{name}`')
        for guild in ctx.bot.guilds:
            public_channel = discord.utils.get(guild.channels, name="general")
            if public_channel:
                await public_channel.send(f'{secret.creator} created a new secret challenge...')

    @secret.command(name='submit', aliases=['solve'])
    @commands.check(enforce_direct_message)
    async def submit(self, ctx:commands.Context, flag:str):
        """
        Solve a secret challenge
        """
        flag_hash = hashlib.sha256(flag.encode()).hexdigest()

        try:
            challenge = SecretChallenge.objects.get({'_id': flag_hash})
            challenge.add_solver(ctx.author.mention)

            msg = decrypt(flag, challenge.message_enc)
            msg = msg.format(user=ctx.author.mention)
            await ctx.send(msg)
            for guild in ctx.bot.guilds:
                public_channel = discord.utils.get(guild.channels, name="general")
                if public_channel:
                    await public_channel.send(msg)

        except SecretChallenge.DoesNotExist:
            await ctx.send("Sorry, thats not right...")

def setup(bot):
    bot.add_cog(Secret(bot))
