from skpy import SkypeEventLoop, SkypeNewMessageEvent
import keyring
from os import path
import os
import signal
import atexit


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


class MySkype(SkypeEventLoop):
    def onEvent(self, event):
        if (
            isinstance(event, SkypeNewMessageEvent)
            and event.msg.userId == self.userId
            # and "he" in event.msg.content
        ):
            # event.msg.chat.sendMsg("prr")
            print(event.msg)


def main():
    cred = keyring.get_credential("skype_python_bot", None)
    token_file_path = path.join(path.dirname(__file__), ".token")

    print("Connecting to Skype")
    sk = MySkype(cred.username, cred.password, token_file_path)
    print("Connected")

    sk.loop()


if __name__ == "__main__":
    try:
        handle_program_singleton()
        main()
    except KeyboardInterrupt:
        pass
