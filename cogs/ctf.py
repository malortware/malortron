import discord
from discord.ext import tasks, commands
import string
import json
import requests
import sys
import traceback
import asyncio
from datetime import datetime
sys.path.append("..")
from db_models import User, CTFModel, Challenge
from utils import chunkify
from errors import NotFound, ItemExists

CTF_MANAGER_ROLE = 'ctf_manager'

def strip_string(tostrip, whitelist):
    # for discord channel creation
    stripped = ''.join([ch for ch in tostrip if ch in whitelist])
    return stripped.strip()

default_channels = [
    'general',
    'bios',
    'scheds',
    'infra',
]

default_categories = [
    'cracking',
    'crypto',
    'exfil',
    'jail',
    're',
    'stego',
    'trivia',
    'web',
    'windows',
]

class CTF(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot

    def _get_ctf(self, ctx: commands.Context, ctf_name = None):
        if ctf_name:
            try:
                return CTFModel.objects.get({'guild_id': ctx.guild.id, 'name': ctf_name})
            except CTFModel.DoesNotExist:
                raise NotFound(f"No CTF named `{ctf_name}` found.\nRun `>ctf create [ctf-name]` to create a new ctf")
        elif isinstance(ctx.message.channel, discord.TextChannel):
            try:
                category_id = ctx.message.channel.category_id
                return CTFModel.objects.get({'guild_id': ctx.guild.id, 'category_id': category_id})
            except CTFModel.DoesNotExist:
                raise NotFound("No CTF found in channel.\nRun `>ctf create [ctf-name]` to create a new ctf")
        elif isinstance(ctx.message.channel, discord.DMChannel):
            member = self._get_member(ctx.message.author.id)
            if not member:
                raise Exception("You are not a member of any ctfs.")
            if not member.current_ctf:
                raise Exception("You haven't set an active ctf. Run `>setctf`")
            return member.current_ctf

    def _get_member(self, user_id):
        try:
            return User.objects.get({'_id': user_id})
        except User.DoesNotExist:
            return None

    def _add_ctf_member(self, user, ctf):
        member = self._get_member(user.id)
        if not member:
            member = User(user_id=user.id, name=user.name)
        if not ctf in member.ctfs:
            member.ctfs.append(ctf)
        member.save()
        return member

    async def _add_category_channel(self, ctx, ctf, category, type = 'text'):
        ctf_category = ctx.bot.get_channel(ctf.category_id)
        channel_name = f"{ctf.name}_{category}"

        if not discord.utils.get(ctf_category.channels, name=channel_name):
            # tags = sorted(ctf.tags + [category])
            # position = tags.index(category) + len(default_channels)
            channel = None
            if type == 'voice':
                channel = await ctf_category.create_voice_channel(channel_name)
            else:
                channel = await ctf_category.create_text_channel(channel_name)
            await ctx.send(f"Created new channel: {channel.mention}")

    async def prompt(self, ctx:commands.Context, message, timeout=10):
        await ctx.send(message)
        def check(message):
            return ctx.author == message.author

        return await ctx.bot.wait_for('message', timeout=timeout, check=check)

    async def announce(self, ctx:commands.Context, ctf, message, channels, public=False):
        ctf_category = ctx.bot.get_channel(ctf.category_id)

        await ctx.send(message)

        for channel in channels:
            channel = discord.utils.get(ctf_category.channels, name=f"{ctf.name}_{channel}")
            if channel and ctx.channel != channel:
                await channel.send(message)

        if public:
            public_channel = discord.utils.get(ctf_category.guild.channels, name="hype")
            if public_channel:
                await public_channel.send(f"{message} for {ctf.name} ctf")

    @commands.Cog.listener()
    @commands.bot_has_permissions(manage_roles=True)
    async def on_guild_join(self, guild: discord.Guild):
        manager_role = discord.utils.get(guild.roles, name=CTF_MANAGER_ROLE)
        if manager_role == None:
            await guild.create_role(name=CTF_MANAGER_ROLE)
            print(f'Created ctf manager role in {guild}')

    @commands.group()
    @commands.has_role(CTF_MANAGER_ROLE)
    @commands.bot_has_permissions(manage_channels=True, manage_roles=True)
    async def ctf(self, ctx: commands.Context):
        """
        Create and Manage CTFs
        """
        if ctx.invoked_subcommand is None:
            await ctx.send_help(ctx.command)

    @ctf.command(aliases=["new"])
    async def create(self, ctx: commands.Context, name: str):
        """
        Create a new CTF
        """

        ctf_name = strip_string(name, set(string.ascii_letters + string.digits + ' ' + '_')).replace(' ', '_').lower()

        try:
            if self._get_ctf(ctx, ctf_name=ctf_name):
                raise ItemExists(f'CTF: `{ctf_name}` already exists')
        except NotFound:
            pass

        ctf_role = discord.utils.get(ctx.guild.roles, name=f'{ctf_name}_ctf')
        if ctf_role == None:
            ctf_role = await ctx.guild.create_role(name=f'{ctf_name}_ctf', mentionable=True)
            await ctx.send(f'Created CTF role: {ctf_role.mention}')

        user = ctx.message.author
        await user.add_roles(ctf_role)

        overwrites = {
            ctx.guild.default_role: discord.PermissionOverwrite(read_messages=False),
            ctx.guild.me: discord.PermissionOverwrite(read_messages=True),
            ctf_role: discord.PermissionOverwrite(read_messages=True)
        }

        category = discord.utils.get(ctx.guild.categories, name=ctf_name)
        if category == None: # Checks if category exists, if it doesn't it will create it.
            category = await ctx.guild.create_category(name=ctf_name, overwrites=overwrites)
        else:
            # await category.edit(overwrites=overwrites) # this does not work?
            for target, overwrite in overwrites.items():
                await category.set_permissions(target, overwrite=overwrite)

        ctf = CTFModel(
            name=ctf_name,
            guild_id=ctx.guild.id,
            category_id=category.id,
            role_id=ctf_role.id,
            created_at=datetime.utcnow(),
            tags=default_categories
        )

        ctf.save()

        self._add_ctf_member(ctx.message.author, ctf)

        for channel in default_channels:
            channel_name = f'{ctf_name}_{channel}'
            if not discord.utils.get(category.channels, name=channel_name):
                await category.create_text_channel(channel_name)
        await ctx.message.add_reaction('✅')
        await ctx.send(f'Created new CTF: `{ctf_name}`')

    @ctf.command()
    async def delete(self, ctx: commands.Context, name = None):
        """
        Delete CTF data and role.
        """
        ctf = self._get_ctf(ctx, ctf_name=name)

        try:
            prompt = await self.prompt(ctx, f'Are you sure you want to delete CTF: `{ctf.name}`? [Y/n]')
            if str(prompt.content) != 'Y':
                await ctx.send('CTF deletion cancelled')
                return
        except asyncio.TimeoutError:
            await ctx.send('CTF deletion cancelled')
            return

        # Delete role from server, delete entry from db
        role = discord.utils.get(ctx.guild.roles, id=ctf.role_id)
        if role is not None:
            await role.delete()
            await ctx.send(f"`{role.name}` role deleted")

        ctf.delete()

        await ctx.send(f"`{ctf.name}` ctf deleted from database")

    # @ctf.command()
    # async def archive(self, ctx):
    #     role = discord.utils.get(ctx.guild.roles, name=str(ctx.message.channel))
    #     await role.delete()
    #     await ctx.send(f"`{role.name}` role deleted, archiving channel.")
    #     try:
    #         sconf = serverdb[str(ctx.guild.id) + '-CONF'] # put this in a try/except, if it doesn't exist set default to CTF
    #         servarchive = sconf.find_one({'name': "archive_category_name"})['archive_category']
    #     except:
    #         servarchive = "ARCHIVE"

    #     category = discord.utils.get(ctx.guild.categories, name=servarchive)
    #     if category == None: # Checks if category exists, if it doesn't it will create it.
    #         await ctx.guild.create_category(name=servarchive)
    #         category = discord.utils.get(ctx.guild.categories, name=servarchive)
    #     await ctx.message.channel.edit(syncpermissoins=True, category=category)
        
#     @ctf.command()
#     async def end(self, ctx):
#         await ctx.send("You can now use either `>ctf delete` (which will delete all data), or `>ctf archive/over` \
# which will move the channel and delete the role, but retain challenge info(`>config archive_category \
# \"archive category\"` to specify where to archive.")
    
    @ctf.command(name='invite')
    async def invite_user(self, ctx, users: commands.Greedy[discord.Member]):
        """
        Invite users to the CTF.
        """
        ctf = self._get_ctf(ctx)
        role = discord.utils.get(ctx.guild.roles, id=ctf.role_id)

        if len(users) == 0:
            return await ctx.send_help(self.invite_user)

        if role:
            for user in users:
                self._add_ctf_member(user, ctf)
                await user.add_roles(role)
                await ctx.send(f"{user.mention} has joined the {role.mention} team!")

    @ctf.command(name='kick')
    async def kick_user(self, ctx, user: discord.Member):
        """
        Kick a user from the CTF.
        """
        ctf = self._get_ctf(ctx)
        role = discord.utils.get(ctx.guild.roles, id=ctf.role_id)

        if role:
            await user.remove_roles(role)
            await ctx.send(f"{user.mention} has left the {role.mention} team.")

    @ctf.command(name='channel:text', aliases=['channel', 'text'])
    async def channel_text(self, ctx, name):
        """
        Add a text channel to the ctf category.
        """
        ctf = self._get_ctf(ctx)
        await self._add_category_channel(ctx, ctf, name)

    @ctf.command(name='channel:voice', aliases=['voice', 'vox'])
    async def channel_voice(self, ctx, name):
        """
        Add a voice channel to the ctf category.
        """
        ctf = self._get_ctf(ctx)
        await self._add_category_channel(ctx, ctf, name, 'voice')

    @commands.command()
    async def setctf(self, ctx: commands.Context):
        """
        Set your active CTF for bot direct messages
        """
        member = self._get_member(ctx.message.author.id)
        if not member:
            raise Exception("You are not a member of any ctfs.")

        ctf_str = "Select your active CTF for bot DMs:\n"
        ctf_str += "```\n"
        for idx, ctf in enumerate(member.ctfs):
            active = f"{'*' if member.current_ctf == ctf else ''}"
            ctf_str += f"{idx + 1}) {active}{ctf.name}\n"
        ctf_str += "```"

        try:
            prompt = await self.prompt(ctx, ctf_str)
            try:
                ctf_idx = int(prompt.content) - 1
                member.current_ctf = member.ctfs[ctf_idx]
                member.save()
                await ctx.send(f"Selected CTF: `{member.current_ctf.name}` for bot DMs")
            except (ValueError, IndexError):
                raise Exception("Invalid number entered.")
        except asyncio.TimeoutError:
            await ctx.send("CTF selection cancelled")

    @commands.group(aliases=["chal", "chall"])
    async def challenge(self, ctx: commands.Context):
        """
        Manage CTF Challenges
        """
        if ctx.invoked_subcommand is None:
            await ctx.send_help(ctx.command)

    @challenge.command(aliases=["a", "create"])
    async def add(self, ctx: commands.Context, name, category=None):
        """
        Add a new challenge.
        """
        ctf = self._get_ctf(ctx)

        try:
            if ctf.get_challenge(name):
                raise ItemExists(f"Challenge `{name}` already exists")
        except NotFound:
            pass

        if not category:
            if isinstance(ctx.channel, discord.TextChannel):
                category = ctx.channel.name.split(f'{ctf.name}_')[1]

        if category not in ctf.tags:
            category = None

        new_challenge = Challenge(
            name=name,
            tags=[category] if category != None else [],
            created_at=datetime.utcnow(),
        )

        if category:
            await self._add_category_channel(ctx, ctf, category)

        ctf.challenges.append(new_challenge)
        ctf.save()

        message = f"`{name}` added to the challenge list for `{ctf.name}`"
        await self.announce(ctx, ctf, message, new_challenge.tags)

    @challenge.command(aliases=["notes", "i"])
    async def info(self, ctx: commands.Context, name):
        """
        Get detailed challenge info.
        """
        ctf = self._get_ctf(ctx)
        public = False
        if '!' in name:
            name = name.replace('!','')
            public = True

        challenge = ctf.get_challenge(name)

        note_desc = f"```md\n# {challenge.name}```"
        note_url = ":pencil: notes : *No notebook URL*"

        attempts = f":snowflake: attempted by: `{', '.join(challenge.attempted_by) or '--'}`"
        working = f":fire: working on: `{', '.join(challenge.working_on) or '--'}`"
        solved_at = f"at {challenge.solved_at.strftime('%Y-%m-%d %H:%M:%S')} UTC" if challenge.solved_at else ""
        solved = f":triangular_flag_on_post: solved by: `{', '.join(challenge.solved_by) or '--'}` {solved_at}"

        info = f"{note_desc}\n{attempts}\n{working}\n{solved}"
        if public:
            await ctx.send(info)
        else:
            await ctx.message.author.send(info)

    @challenge.command(aliases=["t"])
    async def tag(self, ctx: commands.Context, name, category):
        """
        Add a tag to a challenge.
        """
        ctf = self._get_ctf(ctx)
        challenge = ctf.get_challenge(name)

        if not category in ctf.tags:
            valid_tags = ", ".join(ctf.tags)
            try:
                message = f"`{category}` tag does not exist. Would you like to create it? [Y/n]\nCurrent tags: `{valid_tags}`"
                prompt = await self.prompt(ctx, message)
                if str(prompt.content) == 'Y':
                    ctf.tags.append(category)
                else:
                    raise Exception("Tag creation cancelled")
            except asyncio.TimeoutError:
                raise Exception("Tag creation cancelled")

        await self._add_category_channel(ctx, ctf, category)

        if not category in challenge.tags:
            challenge.tags.append(category)
            ctf.save()
            message = f"`{ctx.author.name}` added `{category}` tag to `{challenge.name}`"
            await self.announce(ctx, ctf, message, challenge.tags)
        else:
            await ctx.send(f"`{challenge.name}` already tagged with `{category}`")

    @challenge.command(aliases=["ut"])
    async def untag(self, ctx: commands.Context, name, category):
        """
        Remove a tag from a challenge.
        """
        ctf = self._get_ctf(ctx)
        challenge = ctf.get_challenge(name)

        if category in challenge.tags:
            challenge.tags.remove(category)
            ctf.save()
            await ctx.send(f"`{ctx.author.name}` removed `{category}` tag from `{challenge.name}`")
        else:
            await ctx.send(f"`{challenge.name}` doesn't have tag `{category}`")

    @challenge.command(aliases=['s', 'solved'])
    async def solve(self, ctx, name, flag):
        """
        Mark a challenge as solved.
        """
        ctf = self._get_ctf(ctx)
        challenge = ctf.get_challenge(name)

        if challenge.solved_at:
            raise Exception(f"Challenge already solved by `{','.join(challenge.solved_by)}`")

        user = ctx.message.author
        solvers = [user] + ctx.message.mentions
        challenge.solved_by = [s.name for s in solvers]
        challenge.solved_at = datetime.utcnow()
        challenge.working_on = []
        challenge.flag = flag
        ctf.save()

        solvers_str = ", ".join([s.name for s in solvers])
        message = f":triangular_flag_on_post: `{challenge.name}` has been solved by `{solvers_str}`"
        await self.announce(ctx, ctf, message, challenge.tags + ['general'], public=True)

    @challenge.command(aliases=['as'])
    async def addsolve(self, ctx, name, flag):
        """
        Add and solve a challenge in one command.
        """
        ctf = self._get_ctf(ctx)
        user = ctx.message.author

        try:
            challenge = ctf.get_challenge(name)
            if challenge:
                raise ItemExists(f"Challenge `{name}` already exists.")
        except NotFound:
            pass

        challenge = Challenge(
            name=name,
            created_at=datetime.utcnow(),
            solved_at=datetime.utcnow(),
            solved_by=[user.name],
            flag=flag
        )

        ctf.challenges.append(challenge)
        ctf.save()

        message = f":triangular_flag_on_post: `{challenge.name}` has been solved by `{user.name}`"
        await self.announce(ctx, ctf, message, challenge.tags + ['general'], public=True)

    @challenge.command(aliases=['us'])
    async def unsolve(self, ctx, name):
        """
        Mark a challenge as unsolved.
        """
        ctf = self._get_ctf(ctx)
        challenge = ctf.get_challenge(name)

        if not challenge.solved_at:
            raise Exception(f"Challenge `{challenge.name}` hasn't been solved")

        challenge.solved_by = []
        challenge.solved_at = None
        challenge.flag = f"*unsolved* {challenge.flag}"
        ctf.save()

        await ctx.send(f"`{challenge.name}` has been marked unsolved")

    @challenge.command(aliases=['w', 'working'])
    async def start(self, ctx, name):
        """
        Signal that you are working on a challenge.
        """
        ctf = self._get_ctf(ctx)
        challenge = ctf.get_challenge(name)

        user = ctx.message.author

        if not user.name in challenge.working_on:
            challenge.working_on.append(user.name)
            if not user.name in challenge.attempted_by:
                challenge.attempted_by.append(user.name)
            ctf.save()

        message = (f"`{user.name}` is working on `{challenge.name}`!")
        await self.announce(ctx, ctf, message, challenge.tags)

    @challenge.command(aliases=['down'])
    async def stop(self, ctx, name):
        """
        Signal that you are done working on a challenge.
        """
        ctf = self._get_ctf(ctx)
        challenge = ctf.get_challenge(name)

        user = ctx.message.author

        if user.name in challenge.working_on:
            challenge.working_on.remove(user.name)
            ctf.save()

        message = (f"`{user.name}` stopped working on `{challenge.name}`")
        await self.announce(ctx, ctf, message, challenge.tags)

    @challenge.command()
    async def afk(self, ctx):
        """
        Stop working on all challenges.
        """
        ctf = self._get_ctf(ctx)
        user = ctx.message.author
        challenges = filter(lambda c: user.name in c.working_on, ctf.challenges)

        chal_names = []
        for challenge in challenges:
            challenge.working_on.remove(user.name)
            chal_names.append(challenge.name)

        if len(chal_names) == 0:
            raise NotFound("You are not working on any challenges.")

        ctf.save()

        message = (f"`{user.name}` stopped working on `{', '.join(chal_names)}`")
        await self.announce(ctx, ctf, message, ['general'])

    @challenge.command(aliases=['r', 'rm', 'delete', 'd'])
    async def remove(self, ctx, name):
        """
        Remove a challenge.
        """
        ctf = self._get_ctf(ctx)
        challenge = ctf.get_challenge(name)

        ctf.challenges.remove(challenge)
        ctf.save()

        await ctx.send(f"`{challenge.name}` removed from the challenge list for `{ctf.name}`")

    @challenge.command(aliases=['mv', 'rn'])
    async def rename(self, ctx, name, new_name):
        """
        Rename a challenge.
        """
        ctf = self._get_ctf(ctx)
        challenge = ctf.get_challenge(name)
        prev_name = challenge.name
        challenge.name = new_name
        ctf.save()

        await ctx.send(f"Challenge: `{prev_name}` renamed to `{challenge.name}`")

    @challenge.command(aliases=['ls', 'l'])
    async def list(self, ctx: commands.Context, category=None):
        """
        Show status of CTF challenges.
        Use `>chal ls [category]!` to post to channel.
        """
        ctf = self._get_ctf(ctx)

        public = False
        if category and '!' in category:
            category = category.replace('!','')
            public = True

        if not category:
            if isinstance(ctx.channel, discord.TextChannel):
                category = ctx.channel.name.split(f'{ctf.name}_')[1]
            else:
                category = 'all'

        if category not in ctf.tags:
            category = 'all'

        solved, unsolved = ctf.challenge_summary(category)
        desc = f'{category} challenges\n\n'
        if solved:
            desc += f'# solved\n{solved}\n'
        if unsolved:
            desc += f'# unsolved\n{unsolved}'

        for chunk in chunkify(desc, 1980):
            # emb = discord.Embed(title=f'{category} challenges', description=chunk, colour=4387968)
            # await ctx.message.author.send(embed=emb)
            if public:
                await ctx.send(f'```md\n{chunk}```')
            else:
                await ctx.message.author.send(f'```md\n{chunk}```')

def setup(bot):
    bot.add_cog(CTF(bot))
