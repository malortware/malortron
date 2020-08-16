import typing
import re
import discord
from discord.ext import tasks, commands
from db_models import User, InventoryItem

item_map = {
    r"shots?|malort": "malort"
}

matches = [
    (re.compile(regex, re.IGNORECASE), item) for regex, item in item_map.items()
]

async def update_inventory(user, item_name, amount):
    item = user.get_item(item_name)
    if not item and amount > 0:
        item = InventoryItem(
            name=item_name,
            amount=0
        )
        user.inventory.append(item)

    if not item or item.amount + amount < 0:
        raise Exception(f"You don't have enough {item_name} - aquire some shots of malort to be able to mint new items.")

    item.amount += amount
    user.save()
    return item.amount

async def default_handler(ctx, item, amount, from_user, to_users):
    await update_inventory(from_user, item, -(amount * len(to_users)))
    for user in to_users:
        await update_inventory(user, item, amount)
    return item

async def give_shot(ctx, item, amount, from_user, to_users):
    for user in to_users:
        user.shots_received += 1
        user.shots_available += 1
        user.save()

    from_user.shots_given += 1 * len(to_users)
    from_user.save()

    units = "shots" if amount > 1 else "shot"
    return f"{units} of malort (+1 credit)"

handlers = {
    "malort": give_shot
}

class Inventory(commands.Cog):

    def __init__(self, bot):
        self.bot = bot
        # self.replenish.start()

    def _get_user(self, member):
        try:
            return User.objects.get({'_id': member.id})
        except User.DoesNotExist:
            user = User(user_id=member.id, name=member.name)
            user.save()
            return user

    @commands.command()
    async def give(self, ctx: commands.Context, user: typing.Optional[discord.Member] = None, amount: typing.Union[int, str] = None, item: str = None):
        mentions = [user.mention for user in ctx.message.mentions]
        if len(mentions) == 0:
            raise Exception("Nobody to give it to :(")

        one_synonyms = [None, "a", "an"]
        if amount in one_synonyms:
            amount = 1
        
        amount_str = f"{amount} "

        if(isinstance(amount, str)):
            item = amount
            amount = 1
            amount_str = ""

        if not item or amount <= 0:
            raise Exception("I've got nothing to give!")

        item_match = None
        for regex, mapped_item in matches:
            match = regex.match(item)
            if(match):
                item = mapped_item
                item_match = match
                break

        if(ctx.message.author in ctx.message.mentions):
            raise Exception("You can't give items to yourself!")

        from_user = self._get_user(ctx.message.author)
        to_users = [self._get_user(user) for user in ctx.message.mentions]

        item_handler = handlers.get(item, default_handler)
        item_str = await item_handler(ctx, item, amount, from_user, to_users)
        mention_str = ', '.join(mentions)
        response =  f"{ctx.author.mention} gave {amount_str}{item_str} to {mention_str}"
        await ctx.send(response)

        if(ctx.bot.user in ctx.message.mentions):
            bot_user = self._get_user(ctx.bot.user)
            num_members = len(ctx.message.channel.members)
            if bot_user.shots_available >= num_members:
                to_users = [self._get_user(user) for user in ctx.message.channel.members]
                await give_shot(ctx, "malort", 1, bot_user, to_users)
                bot_user.shots_available -= num_members
                bot_user.save()
                await ctx.send(f"{ctx.bot.user.mention} bought everyone in {ctx.message.channel.mention} a round of malort!")

    @commands.command()
    async def mint(self, ctx: commands.Context, amount: typing.Optional[int], item_name: str):
        user = self._get_user(ctx.message.author)
        amount = amount or 1
        if(amount <= 0):
            raise Exception("You can't create negative things...")

        if(user.shots_available - amount >= 0):
            user.shots_available -= amount
            await update_inventory(user, item_name, amount)
            await ctx.send(f"Minted {amount} new {item_name}")
        else:
            raise Exception("You don't have enough shots of malort to do that... :(")


    @commands.command(aliases=["inv"])
    async def inventory(self, ctx: commands.Context, member: typing.Optional[discord.Member] = None):
        member = member or ctx.message.author
        user_data = self._get_user(member)
        if len(user_data.inventory) == 0:
            item_list = "No Items..."
        else:
            item_list = '\n'.join([f"{item.name}: {item.amount}" for item in user_data.inventory])

        header = f"{member.name}'s inventory:"
        bank_account = f"Malort Bank\n===========\ntotal shots given: {user_data.shots_given}\ntotal shots received: {user_data.shots_received}\nshots available: {user_data.shots_available}"
        inventory_items = f"Items\n===========\n{item_list}"
        response =  f"```{header}\n\n{bank_account}\n\n{inventory_items}```"
        await ctx.send(response)

    # @tasks.loop(seconds=10.0)
    # async def replenish(self):
    #     pass


def setup(bot):
    bot.add_cog(Inventory(bot))
