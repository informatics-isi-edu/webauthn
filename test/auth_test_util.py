from datetime import datetime
from random import randrange
import time
import threading
from requests.exceptions import HTTPError
import json
import sys

RESULT_NAMES = {True: "PASSED", False: "FAILED"}

class AuthTestResult:
    def __init__(self, label, passed):
        self.result = {"label" : label, "passed" : passed, "thread" : threading.current_thread().name}

class AuthTestUtil:
    # func should be the function to call to run the test. It should take one argument.
    # label_func is an optional function to add a label to each thread.
    # label_func should take two arguments: an iteration number and optional second param
    # and return a string
    def __init__(self, func, test_obj, verbose=False, threads=5, iterations_per_thread=100, sleeptime=100, label_func = None):
        self.verbose = verbose
        self.threads = threads
        self.iterations = iterations_per_thread
        self.sleeptime = sleeptime
        self.test_func = func
        self.label_func = label_func
        self.results = dict()

    @staticmethod
    def label(iteration, label_params):
        return("auth_test iteration {i}".format(i=iteration))
        
    def run(self, params):
        self.test_func(params)

    def run_many(self, params, label_params = None, threads=5, iterations=100, sleeptime=180):
        label_func = self.label_func if self.label_func else self.label
        threadlist = []
        for i in range(0, threads):
            label = label_func(i, label_params)
            self.results[label] = []
            t = threading.Timer(randrange(1, 1000)/1000, self.run_threaded, args=(iterations, sleeptime, label, params))
            threadlist.append(t)
            t.start()
        for t in threadlist:
            t.join()

    def run_threaded(self, iterations, sleeptime,label, params):
        for i in range(0, iterations):
            if (self.verbose):
                print("{n} {l} {t}: starting".format(n=threading.current_thread().name, l = label, t=datetime.isoformat(datetime.now())))
            threading.Timer(sleeptime if i > 1 else 0, self.run_one, args=[label, params]).run()

    def run_one(self, label, params):
        self.test_func(label, params)
        try:
            result = self.run_test_func(label, params)
            if self.verbose:
                print("{r}: thread {t}  {l}".format(r=RESULT_NAMES[result], t=threading.current_thread().name, l=label))
            self.results[label].append(AuthTestResult(label, result).result)
        except Exception as ex:
            print("{n} {t}: {e}".format(t=datetime.isoformat(datetime.now()), n=threading.current_thread().name, e=str(ex)))

    def run_test_func(self, label, params):
        resp = False
        for i in range(0, self.iterations):
            result = self.test_func(label, params)
            if self.verbose:
                print("{l}: {r}".format(l=label, r=result))
            return(result)

    def summarize_results(self):
        json.dump(self.results, sys.stdout)
