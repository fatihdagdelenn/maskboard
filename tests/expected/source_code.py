import os, socket
import getpass
from db import connect


class Repo:
    def __init__(self, cfg, settings):
        self.host = cfg.host
        self.schema = cfg["schema"]
        host = socket.gethostname()
        user = get_user()
        password = os.environ["DB_PASS"]
        secret = getpass.getpass("Secret: ")
        token = settings.API_TOKEN
        db = connect(host=host, user=user, password=password, token=token)
	# tab-indented comment, trailing spaces follow   
        schema = self.schema
        if user is None:
            raise ValueError("no user for %s" % host)
        self.node2 = build_node2(host)
        return {"host": "DOMAIN_1", "user": "USER_1", "password": "PASSWORD_1"}


DEFAULTS = dict(host="HOST_1", user="USER_2", password="PASSWORD_2")
conn = connect(host=DEFAULTS["host"], database="DB_1")
