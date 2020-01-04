from deriva.core import DerivaServer, BaseCLI, HatracStore, get_credential
from datetime import datetime
from random import randrange
import time
import threading

class StressTest:
    def __init__(self, host, credential, hatrac_path, catalog_number, ermrest_path,
                 ermrest_min, ermrest_max, hatrac_min, hatrac_max):
        self.host = host
        self.credential = credential
        self.ermrest_path = ermrest_path
        self.hatrac_path = hatrac_path
        self.catalog_number = catalog_number
        self.ermrest_min = ermrest_min
        self.ermrest_max = ermrest_max
        self.hatrac_min = hatrac_min
        self.hatrac_max = hatrac_max

    @classmethod
    def run_many(cls, test_obj, threads=5, iterations=100, sleeptime=180):
        for i in range(0, threads):
            print(str(i))
            t = threading.Timer(randrange(1, 1000)/1000, cls.run_threaded, args=(test_obj, iterations, sleeptime))
            t.start()

    @classmethod
    def run_threaded(cls, test_obj, iterations, sleeptime):
        print("{n} {t}: starting".format(n=threading.current_thread().name, t=datetime.isoformat(datetime.now())))
        for i in range(0, iterations):
            threading.Timer(sleeptime if i > 1 else 0, cls.run_one, args=[test_obj]).run()
                     
    @classmethod
    def run_one(cls, test_obj):
        try:
            cls.one_test(test_obj)
        except Exception as ex:
            print("{n} {t}: {e}".format(t=datetime.isoformat(datetime.now()), n=threading.current_thread().name, e=str(ex)))

    @classmethod
    def one_test(cls, test_obj):
        server = DerivaServer("https", test_obj.host, test_obj.credential)
        catalog = server.connect_ermrest(test_obj.catalog_number)
        hatrac_server = HatracStore("https", test_obj.host, test_obj.credential)
        
        ermrest_iterations = randrange(test_obj.ermrest_min, test_obj.ermrest_max) if test_obj.ermrest_max else 0
        hatrac_iterations = randrange(test_obj.hatrac_min, test_obj.hatrac_max) if test_obj.hatrac_max else 0

        for i in range(0, ermrest_iterations):
            try:
                resp = catalog.get(test_obj.ermrest_path)
            except Exception as ex:
                raise RuntimeError("ermrest failed with {e}".format(e=str(ex)))

        for i in range(0, hatrac_iterations):
            try:
                resp = hatrac_server.head(test_obj.hatrac_path)
            except Exception as ex:
                raise RuntimeError("hatrac failed with {e}".format(e=str(ex)))
    

if __name__ == '__main__':
    cli = BaseCLI("ad-hoc table tool", None, 1, hostname_required=True)
    cli.parser.add_argument("hatrac_path", help="Path for hatrac request (e.g. /hatrac/resources/my_file.txt)")
    cli.parser.add_argument("--ermrest-path", help="Path for ermrest request", default="/entity/public:ERMrest_Client");
    cli.parser.add_argument("--catalog-number", help="ermrest catalog number", type=int, default=1)
    cli.parser.add_argument("--ermrest-min", help="minimum number of ermrest calls per thread per iteration",
                            type=int, default=4)
    cli.parser.add_argument("--ermrest-max", help="minimum number of ermrest calls per thread per iteration",
                            type=int, default=10)
    cli.parser.add_argument("--hatrac-min", help="minimum number of hatrac calls per thread per iteration",
                            type=int, default=0)
    cli.parser.add_argument("--hatrac-max", help="minimum number of hatrac calls per thread per iteration",
                            type=int, default=50)
    cli.parser.add_argument("--iterations-per-thread", help="number of iterations per thread",
                            type=int, default=100)
    cli.parser.add_argument("--sleeptime", help="number of seconds to sleep between iterations",
                            type=int, default=180)
    cli.parser.add_argument("--threads", help="number of threads to start",
                            type=int, default=5)

    args = cli.parse_cli()
    credential = get_credential(args.host)
    
    test_obj = StressTest(args.host, credential, args.hatrac_path, args.catalog_number, args.ermrest_path,
                          args.ermrest_min, args.ermrest_max, args.hatrac_min, args.hatrac_max)
    StressTest.run_many(test_obj, args.threads, args.iterations_per_thread, args.sleeptime)

