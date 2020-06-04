import os
import logging
import hashlib

from pymodm import MongoModel, EmbeddedMongoModel, fields, connect
from pymongo.operations import IndexModel
from errors import NotFound
import config_vars

connect(f"{config_vars.mongodb_connection}?retryWrites=false")

# class BotConfig(object):
#     ANNOUNCEMENTS_CHANNEL = fields.IntegerField()
#     REMINDERS_CHANNEL = fields.IntegerField()


# class InstalledCogs(MongoModel):
#     name = fields.CharField(required=True)
#     enabled = fields.BooleanField(default=True)


class Challenge(EmbeddedMongoModel):
    name = fields.CharField(required=True)
    created_at = fields.DateTimeField(required=True)
    tags = fields.ListField(fields.CharField(), default=[], blank=True)
    attempted_by = fields.ListField(fields.CharField(), default=[], blank=True)
    working_on = fields.ListField(fields.CharField(), default=[], blank=True)
    solved_at = fields.DateTimeField(blank=True)
    solved_by = fields.ListField(fields.CharField(), default=[], blank=True)
    notebook_url = fields.CharField(default="", blank=True)
    flag = fields.CharField(blank=True)


class CTFModel(MongoModel):
    name = fields.CharField(required=True)
    guild_id = fields.IntegerField()
    category_id = fields.IntegerField()
    role_id = fields.IntegerField()
    description = fields.CharField()
    created_at = fields.DateTimeField(required=True)
    finished_at = fields.DateTimeField()
    start_date = fields.DateTimeField()
    end_date = fields.DateTimeField()
    url = fields.URLField()
    username = fields.CharField()
    password = fields.CharField()
    challenges = fields.EmbeddedDocumentListField(Challenge, default=[], blank=True)
    pending_reminders = fields.ListField(blank=True, default=[])
    tags = fields.ListField(fields.CharField(), default=[], blank=True)

    def status(self, members_joined_count):

        description_str = self.description + "\n" if self.description else ""

        solved_count = len(
            list(filter(lambda x: x.solved_at is not None, self.challenges))
        )
        total_count = len(self.challenges)
        status = (
            f":triangular_flag_on_post: **{self.name}** ({members_joined_count} Members joined)\n{description_str}"
            # + f"```CSS\n{draw_bar(solved_count, total_count, style=5)}\n"
            + f" {solved_count} Solved / {total_count} Total"
        )
        if self.start_date:
            fmt_str = "%d/%m %H:\u200b%M"
            start_date_str = self.start_date.strftime(fmt_str)
            end_date_str = self.end_date.strftime(fmt_str) if self.end_date else "?"
            status += f"\n {start_date_str} - {end_date_str}\n"
        status += "```"
        return status

    def credentials(self):
        response = f":busts_in_silhouette: **Username**: {self.username}\n:key: **Password**: {self.password}"
        if self.url is not None:
            response += f"\n\nLogin Here: {self.url}"
        return response
    
    def get_chal_hash(self, name):
        return hashlib.sha1(f'{self.category_id}{name}'.encode()).hexdigest()[:7]

    def get_challenge(self, name):
        challenge = next((c for c in self.challenges if c.name == name or self.get_chal_hash(c.name) == name), None)
        if not challenge:
            raise NotFound("Challenge not found.")
        return challenge
        # return next((c for c in self.challenges if c.name == name or self.get_chal_hash(c.name) == name), None)

    def challenge_summary(self, category):
        if len(self.challenges) == 0:
            raise NotFound("No challenges found. Add one with `>challenge add <name> <category>`")

        solved_response, unsolved_response = "", ""

        challenges = self.challenges
        if category and category != 'all':
            challenges = filter(lambda c: category in c.tags, challenges)
        challenges = sorted(challenges, key=lambda c: (c.tags, c.name, c.solved_at or c.created_at))

        for challenge in challenges:
            chal_hash = self.get_chal_hash(challenge.name)
            challenge_details = f'[{chal_hash} :: {challenge.name}]'
            notes_url = f'[notes]({challenge.notebook_url})'
            flag = f'{{{challenge.flag or ""}}}'
            tags = ",".join(challenge.tags)

            if challenge.solved_at:
                solved_response += f'> {challenge_details}({tags}) <{",".join(challenge.solved_by)}> {flag}\n'
            else:
                if len(challenge.working_on) > 0:
                    unsolved_response += f'* {challenge_details}({tags}) <{",".join(challenge.working_on)}> {flag}\n'
                else:
                    unsolved_response += f'< {challenge_details}({tags}) < -- > {flag}\n'

        return solved_response, unsolved_response

    class Meta:
        collection_name = "ctf"
        ignore_unknown_fields = True
        indexes = [
            IndexModel([('guild_id', 1), ('name', 1)], unique=True),
            IndexModel([('guild_id', 1), ('category_id', 1)], unique=True)
        ]


class User(MongoModel):
    user_id = fields.IntegerField(primary_key=True, required=True)
    name = fields.CharField(required=True)
    ctfs = fields.ListField(fields.ReferenceField(CTFModel, on_delete=fields.ReferenceField.PULL), default=[])
    current_ctf = fields.ReferenceField(CTFModel, blank=True, on_delete=fields.ReferenceField.NULLIFY)
