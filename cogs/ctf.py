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
from db_models import CTFModel, Challenge

CTF_MANAGER_ROLE = 'ctf-manager'

def in_ctf_channel():
    async def tocheck(ctx):
        # A check for ctf context specific commands
        if teamdb[str(ctx.guild.id)].find_one({'name': str(ctx.message.channel)}):
            return True
        else:
            await ctx.send("You must be in a created ctf channel to use ctf commands!")
            return False
    return commands.check(tocheck)

def strip_string(tostrip, whitelist):
    # for discord channel creation
    stripped = ''.join([ch for ch in tostrip if ch in whitelist])
    return stripped.strip()

class InvalidProvider(Exception):
    pass
class InvalidCredentials(Exception):
    pass
class CredentialsNotFound(Exception):
    pass
class NonceNotFound(Exception):
    pass

def getChallenges(url, username, password):
    whitelist = set(string.ascii_letters+string.digits+' '+'-'+'!'+'#'+'$'+'_'+'['+']'+'('+')'+'?'+'@'+'+'+'<'+'>')
    fingerprint = "Powered by CTFd"
    s = requests.session()
    if url[-1] == "/": url = url[:-1]
    r = s.get(f"{url}/login")
    if fingerprint not in r.text:
        raise InvalidProvider("CTF is not based on CTFd, cannot pull challenges.")
    else:
        try:
            nonce = r.text.split("csrfNonce': \"")[1].split('"')[0]
        except: # sometimes errors happen here, my theory is that it is different versions of CTFd
            try:
                nonce = r.text.split("name=\"nonce\" value=\"")[1].split('">')[0]
            except:
                raise NonceNotFound("Was not able to find the nonce token from login, please >report this along with the ctf url.")
        r = s.post(f"{url}/login", data={"name": username, "password": password, "nonce": nonce})
        if "Your username or password is incorrect" in r.text:
            raise InvalidCredentials("Invalid login credentials")
        r_chals = s.get(f"{url}/api/v1/challenges")
        all_challenges = r_chals.json()
        r_solves = s.get(f"{url}/api/v1/teams/me/solves")
        team_solves = r_solves.json()
        if 'success' not in team_solves:
            # ctf is user based.  There is a flag on CTFd for this (userMode), but it is not present in all versions, this way seems to be.
            r_solves = s.get(f"{url}/api/v1/users/me/solves")
            team_solves = r_solves.json()
        
        solves = []
        if team_solves['success'] == True:
            for solve in team_solves['data']:
                cat = solve['challenge']['category']
                challname = solve['challenge']['name']
                solves.append(f"<{cat}> {challname}")
        challenges = {}
        if all_challenges['success'] == True:
            for chal in all_challenges['data']:
                cat = chal['category']
                challname = chal['name']
                name = f"<{cat}> {challname}"
                # print(name)
                # print(strip_string(name, whitelist))
                if name not in solves:
                    challenges.update({strip_string(name, whitelist): 'Unsolved'})
                else:
                    challenges.update({strip_string(name, whitelist): 'Solved'})
        else:
            raise Exception("Error making request")
        return challenges

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
            return CTFModel.objects.get({'name': ctf_name})
        else:
            category_id = ctx.message.channel.category_id
            return CTFModel.objects.get({'category_id': category_id})

    @commands.Cog.listener()
    async def on_ready(self):
        for guild in self.bot.guilds:
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
            await ctx.send_help(self.ctf)

    @ctf.command(aliases=["new"])
    async def create(self, ctx: commands.Context, name: str):
        """
        Create a new CTF
        """

        ctf_name = strip_string(name, set(string.ascii_letters + string.digits + ' ' + '-')).replace(' ', '-').lower()

        try:
            ctf = self._get_ctf(ctx, ctf_name=ctf_name)
            if ctf:
                raise Exception(f'CTF: `{ctf_name}` already exists')
        except CTFModel.DoesNotExist:
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
            category_id=category.id,
            role_id=ctf_role.id,
            created_at=datetime.now()
        )

        ctf.save()

        all_channels = default_channels + default_categories
        for channel in all_channels:
            channel_name = f'{ctf_name}_{channel}'
            if not discord.utils.get(category.channels, name=channel_name):
                await category.create_text_channel(channel_name)
        await ctx.message.add_reaction('✅')
        await ctx.send('Created new CTF: `{}`'.format(ctf_name))

    @ctf.command()
    async def delete(self, ctx: commands.Context, name = None):
        """
        Delete CTF data and role.
        """
        ctf = self._get_ctf(ctx, ctf_name=name)

        await ctx.send(f'Are you sure you want to delete CTF: `{ctf.name}`? [Y/n]')
        try:
            def check(message):
                return ctx.author == message.author

            prompt = await ctx.bot.wait_for('message', timeout=10, check=check)
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

        if role:
            print([u.mention for u in users])
            for user in users:
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

    @commands.group(aliases=["chal", "chall"])
    async def challenge(self, ctx: commands.Context):
        """
        Manage CTF Challenges
        """
        if ctx.invoked_subcommand is None:
            await ctx.send_help(self.challenge)

    @challenge.command(aliases=["a"])
    async def add(self, ctx: commands.Context, name, category=None):
        """
        Add a new challenge.
        """
        ctf = self._get_ctf(ctx)
        challenge = ctf.get_challenge(name)

        if challenge:
            raise commands.CommandInvokeError("Challenge already exists")

        new_challenge = Challenge(
            name=name,
            tags=[category] if category != None else [],
            created_at=datetime.now(),
            # attempted_by=[str(ctx.message.author).split('#')[0]],
        )

        ctf.challenges.append(new_challenge)
        ctf.save()

        await ctx.send(f"`{name}` added to the challenge list for `{ctf.name}`")

    @challenge.command(aliases=['s', 'solved'])
    async def solve(self, ctx, name, flag):
        """
        Marks the current challenge as solved.
        """
        ctf = self._get_ctf(ctx)
        challenge = ctf.get_challenge(name)

        if not challenge:
            raise Exception("Challenge not found")
        # if challenge.solved_at:
        #     raise Exception(f"Challenge already solved by `{challenge.solved_by}`")

        user = ctx.message.author
        solvers = [user] + ctx.message.mentions
        challenge.solved_by = [s.name for s in solvers]
        challenge.solved_at = datetime.now()
        challenge.flag = flag
        ctf.save()

        solvers_str = ", ".join([s.mention for s in solvers])
        await ctx.send(f":triangular_flag_on_post: `{name}` has been solved by {solvers_str}")

        # general_channel = discord.utils.get(
        #     ctx.channel.category.channels, name=f"{ctf.name}_general"
        # )

        # await general_channel.send(
        #     f"{solvers_str} solved the {name} challenge! :candy: :candy:"
        # )

    @challenge.command(aliases=['w'])
    async def working(self, ctx, name):
        """
        Signal that you are working on a challenge.
        """
        ctf = self._get_ctf(ctx)
        challenge = ctf.get_challenge(name)

        if not challenge:
            raise Exception("Challenge not found")

        user = ctx.message.author

        if user.name not in challenge.attempted_by:
            challenge.attempted_by.append(user.name)
            ctf.save()

        await ctx.send(f"{user.mention} is working on `{name}`!")
    
    @challenge.command(aliases=['r', 'rm', 'delete', 'd'])
    async def remove(self, ctx, name):
        """
        Remove a challenge.
        """
        ctf = self._get_ctf(ctx)
        challenge = ctf.get_challenge(name)

        if not challenge:
            raise commands.CommandInvokeError("Challenge not found")

        ctf.challenges.remove(challenge)
        ctf.save()

        await ctx.send(f"`{name}` removed from the challenge list for `{ctf.name}`")

    @staticmethod
    def gen_page(challengelist): # will return page w/ less than 2k chars (total)
        challenge_page = ""
        challenge_pages = []
        for c in challengelist:
            # print(c)
            if not len(challenge_page + c) >= 1989:
                challenge_page += c
                if c == challengelist[-1]: # if it is the last item
                    challenge_pages.append(challenge_page)
            
            elif len(challenge_page + c) >= 1989:
                challenge_pages.append(challenge_page)
                challenge_page = ""
                challenge_page += c

        # print(challenge_pages)
        return challenge_pages

    @challenge.command(aliases=['ls', 'l'])
    async def list(self, ctx):
        ctf = self._get_ctf(ctx)
        
        emb = discord.Embed(description=ctf.challenge_summary(), colour=4387968)
        await ctx.channel.send(embed=emb)

        # ctf_challenge_list = []
        # try:
        #     ctf_challenge_list = []
        #     challenges = ctx.ctf.get('challenges', {})
        #     for k, v in challenges.items():
        #         challenge = f"[{k}]: {v}\n"
        #         ctf_challenge_list.append(challenge)

        #     if(len(ctf_challenge_list) == 0):
        #         await ctx.send("Add some challenges with `>challenge add \"challenge name\"`")
        #         return

        #     for page in CTF.gen_page(ctf_challenge_list):
        #         await ctx.send(f"```ini\n{page}```")
        # except:
        #     traceback.print_exc()

    @ctf.error
    @challenge.error
    async def on_ctf_error(self, ctx: commands.Context, error: commands.CommandInvokeError):
        if isinstance(error.original, CTFModel.DoesNotExist):
            await ctx.send("No ctf found.\nRun `>ctf create [ctf-name]` to create a new ctf")

def setup(bot):
    bot.add_cog(CTF(bot))

    # @challenge.command(aliases=['get', 'ctfd'])
    # async def pull(self, ctx, url):
    #     try:
    #         try:
    #             pinned = await ctx.message.channel.pins() 
    #             user_pass = CTF.get_creds(pinned)
    #         except CredentialsNotFound as cnfm:
    #             await ctx.send(cnfm)
    #         ctfd_challs = getChallenges(url, user_pass[0], user_pass[1])
    #         ctf = teamdb[str(ctx.guild.id)].find_one({'name': str(ctx.message.channel)})
    #         try: # If there are existing challenges already...
    #             challenges = ctf['challenges']
    #             challenges.update(ctfd_challs)
    #         except:
    #             challenges = ctfd_challs
    #         ctf_info = {'name': str(ctx.message.channel),
    #         'challenges': challenges
    #         }
    #         teamdb[str(ctx.guild.id)].update({'name': str(ctx.message.channel)}, {"$set": ctf_info}, upsert=True)
    #         await ctx.message.add_reaction("✅")
    #     except InvalidProvider as ipm:
    #         await ctx.send(ipm)
    #     except InvalidCredentials as icm:
    #         await ctx.send(icm)
    #     except NonceNotFound as nnfm:
    #         await ctx.send(nnfm)
    #     except requests.exceptions.MissingSchema:
    #         await ctx.send("Supply a valid url in the form: `http(s)://ctfd.url`")
    #     except:
    #         traceback.print_exc()

    # # @commands.bot_has_permissions(manage_messages=True)
    # # @commands.has_permissions(manage_messages=True)
    # @ctf.command(aliases=['login'])
    # async def setcreds(self, ctx, username, password):
    #     pinned = await ctx.message.channel.pins()
    #     for pin in pinned:
    #         if "CTF credentials set." in pin.content:
    #             await pin.unpin()
    #     msg = await ctx.send(f"CTF credentials set. name:{username} password:{password}")
    #     await msg.pin()
    
    # # @commands.bot_has_permissions(manage_messages=True)
    # @ctf.command(aliases=['getcreds'])
    # async def creds(self, ctx):
    #     pinned = await ctx.message.channel.pins()
    #     try:
    #         user_pass = CTF.get_creds(pinned)
    #         await ctx.send(f"name:`{user_pass[0]}` password:`{user_pass[1]}`")
    #     except CredentialsNotFound as cnfm:
    #         await ctx.send(cnfm)

    # @staticmethod
    # def get_creds(pinned):
    #     for pin in pinned:
    #         if "CTF credentials set." in pin.content:
    #             user_pass = pin.content.split("name:")[1].split(" password:")
    #             return user_pass
    #     raise CredentialsNotFound("Set credentials with `>ctf setcreds \"username\" \"password\"`")
