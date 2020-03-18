from requests.exceptions import HTTPError
from deriva.core import DerivaServer, BaseCLI, HatracStore, get_credential, DEFAULT_HEADERS
from random import randrange
import json
from auth_test_util import AuthTestUtil
from pprint import pprint
import sys
from pathlib import Path

class GroupTest:
    def __init__(self, host, credential_map, threads, verbose=False):
        self.host = host
        self.credential_map = credential_map
        self.threads = threads
        self.verbose = verbose
        self.params = None
        self.label_params = None
        self.sessions = []
        self.handled_statuses = [200, 304, 401, 403, 404]
        self.result_options = ["passed", "failed", "skipped", "error"]
        self.results = {"summary" : {"counts" : {}}}
        for k in self.result_options:
            self.results[k] = []
        self.nocache_headers = {}
        self.keys = sorted(self.credential_map.keys())
        if self.threads > len(self.keys):
            raise ValueError("thread count {t} greater than credential count{c}".format
                             (t=self.threads, c=len(self.keys)))
        for k in DEFAULT_HEADERS.keys():
            self.nocache_headers[k] = DEFAULT_HEADERS[k]
            self.nocache_headers["Cache-Control"] = "no-cache"

    def advance_current_item(self):
        item = self.credential_map.popitem()
        self.current_item = item[1]
        self.current_item["test_info"] = {"name" : item[0]}

    def test_func(self, label, params):
        status = self.test_anon()
        if status != "passed":
            return(status)
        try:
            self.advance_current_item()
        except KeyError:
            for k in self.result_options:
                self.results["summary"]["counts"][k] = len(self.results[k])
            return(self.results["summary"]["counts"]["failed"] == 0 and self.results["summary"]["counts"]["error"] == 0)
        expected_statuses = self.current_item["expected_statuses"]
        self.sessions = self.test_all_map_entries()
        for key in self.results.keys():
            if key != "passed" and len(self.results[key]) != 0:
                return False
        return True
    
    def test_all_map_entries(self):
        self.current_item["test_info"]["authenticate"] = True
        item = self.current_item
        for key in item.get("credential_lists").keys():
            self.test_credential_list(item, item["credential_lists"][key])

    def test_anon(self):
        server = DerivaServer("https", self.host)
        status = None
        status_detail = None
        response_code = None
        try:
            response = server.get("/authn/session")
            status = "failed"
        except HTTPError as ex:
            if ex.response.status_code == 404:
                status = "passed"
            else:
                response_code = ex.response.status_code
                status = "failed"
        except Exception as ex:
            status = "error"
            status_detail = str(ex)
        self.results[status].append(
            {
                "test_info" :  {
                    "authenticate" : False,
                    "name" : "anon",
                    "status" : status,
                    "status_detail" : status_detail,
                    "response_code" : response_code
                    }
            }
        )
        return(status)
            

    def test_credential_list(self, item, credential_list):
        result = {
            "expected_statuses" : item["expected_statuses"],
            "expected_groups" : item["expected_groups"],
            "test_info" : {"status" :"skipped"}
        }
        while result["test_info"].get("status") == "skipped" and len(credential_list) > 0:
            credential = credential_list.pop()
            try:
                test1 = self.test_one_entry(credential, self.current_item)
                for key in test1.keys():
                    result["test_info"][key] = test1[key]
            except HTTPError as ex:
                result["test_info"]["response_code"] = ex.response.status_code
                if ex.response.status_code != 404:
                    result["test_info"]["status"] = "failed" if ex.response.status_code in self.handled_statuses else "error"
            except KeyError:
                result["test_info"]["status"] = "skipped"
            except Exception as ex:
                result["test_info"]["status"] = "error"
                result["test_info"]["status_detail"] = str(ex)
            finally:
                result["credential"] = credential
        self.results[result["test_info"]["status"]].append(result)

    def test_one_entry(self, credential, item):
        server = DerivaServer("https", self.host, credential)
        response = server.get("/authn/session")
        session = json.loads(response.text)
        grouplist = []
        result = None
#        json.dump({"item": item, "current_item": self.current_item}, sys.stdout)
#        pprint(session)

        for group in session.get("attributes"):
            if group.get("display_name") is not None and group.get("identities") is None:
                grouplist.append(group["display_name"])        
        result = set(grouplist) == set(item["expected_groups"])
        return {"user" : session["client"].get("display_name"), "status" : ("passed" if result and response.status_code in item["expected_statuses"] else "failed"),
                "response_code" : response.status_code, "groups" : grouplist}
        
    def make_label(self, iteration, label_params, item=None):
        if item is None:
            item = self.current_item
        return item.keys()[0]

    @staticmethod
    def trim_credlist(credential_map):
        status_map = dict()
        new_map = dict()
        key_types = set(["credential", "expected_statuses"])
        for name in credential_map.keys():
            val = credential_map[name]
            expected_statuses = val.get("expected_statuses")
            status_map[frozenset(expected_statuses)] = {name : val}
            current_types = key_types.intersection(val.keys())
            if "expected_statuses" in key_types:
                current_types.add(frozenset(val.get("expected_statuses")))
            if frozenset(current_types) != status_map.keys():
                status_map[frozenset(current_types)] = {name : val}

        for key in status_map.keys():
            entry = status_map[key]
            for k in entry.keys():
                new_map[k] = entry[k]
        return(new_map)

    def dump_credential_map(self):
        json.dump(list(credential_map.values()), sys.stdout)

    def summarize_results(self):
        pprint(self.results)        

if __name__ == '__main__':
    cli = BaseCLI("ad-hoc table tool", None, 1, hostname_required=True)
    cli.parser.add_argument("--group_map", default= Path.home().joinpath(".deriva", "group_map.json"), help="File with credential list -- json array {label: session_cookie}")
    cli.parser.add_argument("--iterations-per-thread", help="number of iterations per thread",
                            type=int, default=1)
    cli.parser.add_argument("--sleeptime", help="number of seconds to sleep between iterations",
                            type=int, default=180)
    cli.parser.add_argument("--threads-per-session", help="number of threads to start per session (as listed in session_file)",
                            type=int, default=1)
    cli.parser.add_argument('-v', '--verbose', help="verbose", action="store_true")
    args = cli.parse_cli()

    credential_map=json.load(open(args.group_map))
    status_map = credential_map
#
#    print("status_map")
#    pprint(status_map)
#    print("aftwe status_map")     

    gtest = GroupTest(args.host, status_map, args.threads_per_session, args.verbose)
    test_obj = AuthTestUtil(gtest.test_func, gtest, verbose=args.verbose, threads=args.threads_per_session, iterations_per_thread=args.iterations_per_thread, sleeptime=args.sleeptime)
    test_obj.run_many(gtest.params, threads=args.threads_per_session,
                      iterations=args.iterations_per_thread, sleeptime=args.sleeptime)
#    test_obj.summarize_results()
    gtest.summarize_results()
