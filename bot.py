#!/usr/bin/env python3

from skpy import SkypeEventLoop, SkypeNewMessageEvent, SkypeMsg
import keyring
from os import path
import os
import signal
import atexit
from bs4 import BeautifulSoup, Tag
from datetime import datetime
from dateutil import tz
import traceback
import logging
import json

RESPONSE_COMMAND_FILE_PATH = path.join(path.dirname(__file__), "response_cmd.json")


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
    msg = BeautifulSoup(skype_msg.content)
    tag = next(msg.children)

    return tag.extract() if tag.name == "quote" else None, msg


def read_response_cmd(name: str | None) -> dict:
    response_cmd = {}
    if path.isfile(RESPONSE_COMMAND_FILE_PATH):
        with open(RESPONSE_COMMAND_FILE_PATH) as f:
            try:
                response_cmd = json.load(f)
            except:
                pass

    if name is not None:
        response_cmd.setdefault(name, {})

    return response_cmd


def write_response_cmd(response_cmd: dict):
    with open(RESPONSE_COMMAND_FILE_PATH, "w") as f:
        json.dump(response_cmd, f, indent=5)


class MySkype(SkypeEventLoop):
    def onEvent(self, event):
        if isinstance(event, SkypeNewMessageEvent) and event.msg.userId == self.userId:
            quote, msg = parse_skype_msg(event.msg)
            msg = str(msg)

            if not msg.startswith("!"):
                return

            print(msg)
            cmd = msg[1:]

            event.msg.delete()

            if (
                cmd == "del"
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

            if cmd == "info" and quote is not None:
                event.msg.chat.sendMsg(str(quote), rich=False)

            cmd = cmd.split()

            if cmd[:2] == ["rsp", "quote"] and quote is not None:
                name = cmd[2]

                response_cmd = read_response_cmd(name)
                rsp = response_cmd[name].setdefault("response", {})

                rsp["quote"] = json.dumps(str(quote))
                write_response_cmd(response_cmd)

            if cmd[:2] == ["rsp", "trigger"]:
                name = cmd[2]
                trigger = " ".join(cmd[3:])

                response_cmd = read_response_cmd(name)
                response_cmd[name]["trigger"] = trigger
                write_response_cmd(response_cmd)

            if cmd[:2] == ["rsp", "triggerchat"]:
                name = cmd[2]
                chat = "*" if "*" in cmd[3:] else cmd[3:]

                if isinstance(chat, list) and quote is not None:
                    chat.append(quote["conversation"])

                response_cmd = read_response_cmd(name)
                response_cmd[name]["chat"] = chat
                write_response_cmd(response_cmd)

            if cmd[:2] == ["rsp", "file"]:
                raise NotImplementedError()


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
