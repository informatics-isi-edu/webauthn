from deriva.core import DerivaServer, BaseCLI, HatracStore, get_credential, DEFAULT_HEADERS
from random import randrange
import json
from requests.exceptions import HTTPError
from auth_test_util import AuthTestUtil
from pprint import pprint

class StressTest:
    def __init__(self, host, credential_map, catalog_number, threads, ermrest_path,
                 ermrest_min, ermrest_max, verbose=False):
        self.threads = threads
        credential_map["anon"] = {"credential": None, "expected_statuses": [401]}
        self.credential_map = credential_map
        self.host = host
        self.catalog_number = catalog_number
        self.handled_statuses = [200, 304, 401, 403]
        self.verbose=verbose
        self.params = {
            "ermrest_path" : ermrest_path,
            "ermrest_min" :  ermrest_min,
            "ermrest_max" : ermrest_max,

        }
        self.nocache_headers = {}
        self.keys = sorted(self.credential_map.keys())
        if self.threads > len(self.keys):
            raise ValueError("thread count {t} greater than credential count{c}".format
                             (t=self.threads, c=len(self.keys)))
        for k in DEFAULT_HEADERS.keys():
            self.nocache_headers[k] = DEFAULT_HEADERS[k]
        self.nocache_headers["Cache-Control"] = "no-cache"

    def make_label(self, iteration, lable_params):
        return self.keys[iteration]

    def test_func(self, label, params):
        credential = self.credential_map[label].get("credential")
        expected_statuses = self.credential_map[label]["expected_statuses"]
        server = DerivaServer("https", self.host, credential)
        catalog = server.connect_ermrest(self.catalog_number)
        
        ermrest_iterations = randrange(params.get("ermrest_min"), params.get("ermrest_max"))
        path = "{base}?authz_test_label={label}".format(base=params.get("ermrest_path"), label=label)
        
        resp = None
        for i in range(0, ermrest_iterations):
            try:
                resp = catalog.get(path)
            except HTTPError as ex:
                if ex.response.status_code not in self.handled_statuses:
                    server.destroy()
                    raise(ex)
                resp = ex.response
            if self.verbose and (resp.status_code not in expected_statuses):
                print("ERROR: unexpected http status {s} for user {u} (expected {e}".format(s=resp.status_code, u=label, e=str(expected_statuses)))
                server.destroy()
            return(resp.status_code in expected_statuses)

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
    cli.parser.add_argument('-v', '--verbose', help="verbose", action="store_true")

    args = cli.parse_cli()
    credential_map=json.load(open(args.session_map))
    param_obj = StressTest(args.host, credential_map, args.catalog_number, args.threads_per_session, args.ermrest_path,
                           args.ermrest_min, args.ermrest_max, verbose=args.verbose)
    test_obj = AuthTestUtil(param_obj.test_func, param_obj, verbose=args.verbose, threads=args.threads_per_session, iterations_per_thread=args.iterations_per_thread, sleeptime=args.sleeptime, label_func = param_obj.make_label)
    test_obj.run_many(param_obj.params, threads=args.threads_per_session,
                      iterations=args.iterations_per_thread, sleeptime=args.sleeptime)
    test_obj.summarize_results()
