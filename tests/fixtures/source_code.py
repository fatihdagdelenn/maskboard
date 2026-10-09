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
        return {"host": "db01.example-corp.com", "user": "appuser", "password": "S3cret.Pass1"}


DEFAULTS = dict(host="billing01", user="svc_billing", password="Winter.2026x")
conn = connect(host=DEFAULTS["host"], database="ledgerdb")
