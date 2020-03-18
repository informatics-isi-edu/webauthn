from deriva.core import DerivaServer, BaseCLI, HatracStore, get_credential, DEFAULT_HEADERS
from datetime import datetime
from random import randrange
import time
import threading
import json
from requests.exceptions import HTTPError

class StressTest:
    def __init__(self, host, credential_map, catalog_number, threads, params = None, verbose=False):
        self.threads = threads
        credential_map["anon"] = {"credential": None, "expected_statuses": [401]}
        self.credential_map = credential_map
        self.host = host
        self.credential_map = credential_map
        self.ermrest_path = ermrest_path
        self.catalog_number = catalog_number
        self.ermrest_min = ermrest_min
        self.ermrest_max = ermrest_max
        self.credential_map["anon"] = {"credential": None, "expected_statuses": [401]}
        self.handled_statuses = [200, 304, 401, 403]
        self.verbose=verbose
        self.nocache_headers = {}
        self.keys = sorted(self.credential_map.keys())
        self.params = params
        if self.threads > len(self.keys):
            raise ValueError("thread count {t} greater than credential count{c}".format
                             (t=self.threads, c=len(self.keys)))
        for k in DEFAULT_HEADERS.keys():
            self.nocache_headers[k] = DEFAULT_HEADERS[k]
        self.nocache_headers["Cache-Control"] = "no-cache"

    def run_many(self, threads=5, iterations=100, sleeptime=180):
        for label in self.credential_map.keys():
            for i in range(0, threads):
                t = threading.Timer(randrange(1, 1000)/1000, self.run_threaded, args=(iterations, sleeptime, label))
                t.start()

    def run_threaded(self, iterations, sleeptime, label):
            print("{n} {l} {t}: starting".format(n=threading.current_thread().name, l = label, t=datetime.isoformat(datetime.now())))
            for i in range(0, iterations):
                threading.Timer(sleeptime if i > 1 else 0, self.run_one, args=[label]).run()
                     
    def run_one(self, label):
        self.one_test(label)        
        try:
            self.one_test(label)
        except Exception as ex:
            print("{n} {t}: {e}".format(t=datetime.isoformat(datetime.now()), n=threading.current_thread().name, e=str(ex)))

    def one_test(self, label):
        credential = self.credential_map[label]["credential"]
        expected_statuses = self.credential_map[label]["expected_statuses"]
        server = DerivaServer("https", self.host, credential)
        catalog = server.connect_ermrest(self.catalog_number)
        print(self.host)
        
        ermrest_iterations = randrange(self.ermrest_min, self.ermrest_max) if self.ermrest_max else 0
        path = "{base}?authz_test_label={label}".format(base=self.ermrest_path, label=label)

        resp = None
        for i in range(0, ermrest_iterations):
            try:
                resp = catalog.get(path)
            except HTTPError as ex:
                if ex.response.status_code not in self.handled_statuses:
                    raise(ex)
                resp = ex.response
            if resp.status_code not in expected_statuses:
                print("ERROR: unexpected http status {s} for user {u}".format(s=resp.status_code, u=label))

if __name__ == '__main__':
    cli = BaseCLI("ad-hoc table tool", None, 1, hostname_required=True)
    cli.parser.add_argument("session_map", help="File with credential list -- json array {label: session_cookie}")
    cli.parser.add_argument("--ermrest-path", help="Path for ermrest request", default="/entity/public:ERMrest_Client");
    cli.parser.add_argument("--catalog-number", help="ermrest catalog number", type=int, default=1)
    cli.parser.add_argument("--ermrest-min", help="minimum number of ermrest calls per thread per iteration",
                            type=int, default=4)
    cli.parser.add_argument("--ermrest-max", help="minimum number of ermrest calls per thread per iteration",
                            type=int, default=10)
    cli.parser.add_argument("--iterations-per-thread", help="number of iterations per thread",
                            type=int, default=100)
    cli.parser.add_argument("--sleeptime", help="number of seconds to sleep between iterations",
                            type=int, default=180)
    cli.parser.add_argument("--threads-per-session", help="number of threads to start per session (as listed in session_file)",
                            type=int, default=5)

    args = cli.parse_cli()
    params = {
        "ermrest_path" : args.ermrest_path,
        "ermrest_min" :  args.ermrest_min,
        "ermrest_max" : args.ermrest_max
    }
    
    credential_map=json.load(open(args.session_map))
    param_obj = StressTest(args.host, credential_map, args.catalog_number, args.threads_per_session,
                           params = params, verbose=args.verbose)
    test_obj = AuthTestUtil(param_obj.test_func, param_obj.params, verbose=args.verbose, threads=args.threads_per_session, iterations_per_thread=args.iterations_per_thread, sleeptime=args.sleeptime, label_func = param_obj.make_label)
    test_obj.run_many(param_obj.params, threads=args.threads_per_session,
                      iterations=args.iterations_per_thread, sleeptime=args.sleeptime)
    test_obj.summarize_results()
