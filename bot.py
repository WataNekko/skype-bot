#!/usr/bin/env python3

import re
from skpy import SkypeEventLoop, SkypeNewMessageEvent, SkypeMsg
import keyring
from os import path
from pathlib import Path
import os
import signal
import atexit
from bs4 import BeautifulSoup, Tag
from datetime import datetime
from dateutil import tz
import traceback
import logging
import json
from typing import NotRequired, TypedDict

RESPONSE_COMMANDS_FILE_PATH = path.join(path.dirname(__file__), "response_cmd.json")


def handle_program_singleton():
    pid_cache_path = path.join(path.dirname(__file__), ".pid")

    if path.isfile(pid_cache_path):
        with open(pid_cache_path) as f:
            try:
                pid = int(f.read())
                os.kill(pid, signal.SIGTERM)
            except:
                pass

    with open(pid_cache_path, "w") as f:
        f.write(str(os.getpid()))

    def delete_pid_cache():
        os.remove(pid_cache_path)

    atexit.register(delete_pid_cache)


def parse_skype_msg(skype_msg: SkypeMsg) -> tuple[None | Tag, BeautifulSoup]:
    if not re.search("rich", skype_msg.type, re.I):
        return None, skype_msg.content

    msg = BeautifulSoup(skype_msg.content, "html.parser")
    tag = next(msg.children)

    return tag.extract() if tag.name == "quote" else None, msg


class ResponseCommand(TypedDict):
    chats: list[str]
    triggers: list[str]

    class Response(TypedDict):
        quote: NotRequired[str]
        text: NotRequired[str]

        class File(TypedDict):
            path: str
            name: NotRequired[str]
            is_image: NotRequired[bool]

        file: NotRequired[File]
        raw: NotRequired[dict[str, dict]]

    response: Response


ResponseCommands = dict[str, ResponseCommand]


def read_response_cmds() -> ResponseCommands:
    rsp_cmds = {}
    if path.isfile(RESPONSE_COMMANDS_FILE_PATH):
        with open(RESPONSE_COMMANDS_FILE_PATH) as f:
            try:
                rsp_cmds = json.load(f)
            except:
                pass

    return rsp_cmds


def write_response_cmds(rsp_cmds: ResponseCommands):
    with open(RESPONSE_COMMANDS_FILE_PATH, "w") as f:
        json.dump(rsp_cmds, f, indent=2)


def get_rest_after_split(string: str, split: list[str]):
    for s in split:
        _, string = string.split(s, 1)

    return string


class MySkype(SkypeEventLoop):
    def merge_to_rsp_chats(self, changed_rsp_chats: dict[str, ResponseCommands]):
        for chat, rsp_cmds in changed_rsp_chats.items():
            self._rsp_chats[chat] = self._rsp_chats.get(chat, {}) | rsp_cmds

    def rsp_cmd(self, name: str) -> ResponseCommand:
        return self._rsp_cmds.setdefault(name, {})

    def rsp_chats(self, name: str | None = None) -> dict[str, ResponseCommands]:
        if name is not None:
            rsp_cmd = self.rsp_cmd(name)
            return {chat: {name: rsp_cmd} for chat in rsp_cmd.get("chats", [])}

        return self._rsp_chats

    def reset_rsp_cmd(self):
        self._rsp_cmds = read_response_cmds()
        self._rsp_chats: dict[str, ResponseCommands] = {}

        for name in self._rsp_cmds.keys():
            self.merge_to_rsp_chats(self.rsp_chats(name))

    def __init__(self, *args, **kwargs):
        super(MySkype, self).__init__(*args, **kwargs)
        self.reset_rsp_cmd()

    def save_rsp_cmd(self, name: str | None):
        if name is not None:
            changed_chats = self.rsp_chats(name)
            self.merge_to_rsp_chats(changed_chats)

        write_response_cmds(self._rsp_cmds)

    def onEvent(self, event):
        if isinstance(event, SkypeNewMessageEvent):
            self.handle_new_message_event(event)

    def handle_new_message_event(self, event: SkypeNewMessageEvent):
        if event.msg.userId == self.userId:
            quote, msg = parse_skype_msg(event.msg)
            msg = msg.text

            if msg.startswith("!"):
                self.handle_self_commands(event, quote, msg)
                return

        if (id := event.msg.chat.id) in (chats := self.rsp_chats()):
            self.handle_response_triggers(event, chats[id])

    def handle_self_commands(
        self, event: SkypeNewMessageEvent, quote: Tag | None, msg: str
    ):
        print(">>", msg)
        cmd_txt = msg[1:]
        cmd = cmd_txt.split()

        event.msg.delete()

        if (
            cmd_txt == "del"
            and quote is not None
            and quote["conversation"] == event.msg.chat.id
        ):
            msgs = event.msg.chat.getMsgs()
            cmd_idx = next(i for i, x in enumerate(msgs) if x.id == event.msg.id)
            msgs = msgs[cmd_idx:]

            done = False

            while True:
                for msg in msgs:
                    if msg.time.replace(tzinfo=tz.UTC) >= datetime.fromtimestamp(
                        int(quote["timestamp"]), tz.tzlocal()
                    ):
                        msg.delete()

                    if msg.id == quote["messageid"]:
                        done = True
                        break

                if done:
                    break

                msgs = event.msg.chat.getMsgs()

        elif cmd_txt == "quote" and quote is not None:
            event.msg.chat.sendMsg(str(quote), rich=False)

        elif cmd[:2] == ["rsp", "reload"]:
            self.reset_rsp_cmd()

        elif cmd[:2] == ["rsp", "print"]:
            event.msg.chat.sendMsg(
                "_rsp_cmds = " + json.dumps(self._rsp_cmds, indent=4)
            )
            event.msg.chat.sendMsg(
                "_rsp_chats = " + json.dumps(self._rsp_chats, indent=4)
            )

        elif cmd[:2] == ["rsp", "quote"] and quote is not None:
            name = cmd[2]

            rsp_cmd = self.rsp_cmd(name)
            rsp = rsp_cmd.setdefault("response", {})

            rsp["quote"] = str(quote)
            self.save_rsp_cmd(name)

        elif cmd[:2] == ["rsp", "trigger"]:
            name = cmd[2]
            trigger = " ".join(cmd[3:])

            rsp_cmd = self.rsp_cmd(name)
            triggers = rsp_cmd.setdefault("triggers", [])
            triggers.append(trigger)

            unique = dict.fromkeys(triggers)
            triggers.clear()
            triggers.extend(unique)

            self.save_rsp_cmd(name)

        elif cmd[:2] == ["rsp", "triggerchat"]:
            name = cmd[2]
            new_chats = cmd[3:]

            rsp_cmd = self.rsp_cmd(name)
            chats = rsp_cmd.setdefault("chats", [])

            if quote or new_chats:
                if quote is not None:
                    new_chats.append(quote["conversation"])

                chats.extend(new_chats)
            else:
                chats.append(event.msg.chat.id)

            unique = dict.fromkeys(chats)
            chats.clear()
            chats.extend(unique)

            self.save_rsp_cmd(name)

        elif cmd[:2] == ["rsp", "text"]:
            name = cmd[2]
            text = get_rest_after_split(cmd_txt, cmd[:3]).lstrip()

            if not text and quote is not None:
                text = "".join(
                    str(e) for e in quote.children if e.name != "legacyquote"
                )

            if text:
                rsp_cmd = self.rsp_cmd(name)
                rsp = rsp_cmd.setdefault("response", {})

                rsp["text"] = text
                self.save_rsp_cmd(name)

        elif cmd[:2] == ["rsp", "raw"]:
            name, raw_id, key = cmd[2:5]
            value = get_rest_after_split(cmd_txt, cmd[:5]).lstrip()

            rsp_cmd = self.rsp_cmd(name)
            rsp = rsp_cmd.setdefault("response", {})

            raw = rsp.setdefault("raw", {})
            raw_rsp = raw.setdefault(raw_id, {})
            raw_rsp[key] = value

            self.save_rsp_cmd(name)

    def handle_response_triggers(
        self, event: SkypeNewMessageEvent, rsp_cmds: ResponseCommands
    ):
        quote, msg = parse_skype_msg(event.msg)
        msg = str(msg)

        for name, rsp_cmd in rsp_cmds.items():
            triggers = rsp_cmd.setdefault("triggers", [])

            if not triggers:
                continue

            triggers = map(lambda t: f"({t})", triggers)
            triggers = "|".join(triggers)

            m = re.search(triggers, msg, re.I)
            if m is not None:
                print("<<", name, f"/{triggers}/")

                quote = SkypeMsg.quote(
                    event.msg.user,
                    event.msg.chat,
                    event.msg.time.replace(tzinfo=tz.UTC).astimezone(tz.tzlocal()),
                    m[0],
                )
                soup = BeautifulSoup(quote, "html.parser")
                soup.quote["conversation"] = event.msg.chat.id
                soup.quote["messageid"] = event.msg.id
                quote = str(soup)
                event.msg.chat.sendMsg(quote, rich=True)

                rsp = rsp_cmd.setdefault("response", {})

                raw = rsp.get("raw")
                if raw:
                    for raw_rsp in raw.values():
                        event.msg.chat.sendRaw(**raw_rsp)

                file = rsp.get("file")
                if file:
                    path = file["path"]
                    name = file.get("name", Path(path).stem)
                    is_image = file.get("is_image", False)

                    with open(path, "rb") as f:
                        event.msg.chat.sendFile(f, name, is_image)

                quote = rsp.get("quote", "")
                text = rsp.get("text", "")

                response = quote + text
                if response:
                    event.msg.chat.sendMsg(response, rich=True)


def main():
    cred = keyring.get_credential("skype_python_bot", None)
    token_file_path = path.join(path.dirname(__file__), ".token")

    print("Connecting to Skype")
    sk = MySkype(cred.username, cred.password, token_file_path)
    print("Connected")

    while True:
        try:
            sk.loop()
        except Exception:
            logging.error(traceback.format_exc())


if __name__ == "__main__":
    try:
        handle_program_singleton()
        main()
    except KeyboardInterrupt:
        pass
