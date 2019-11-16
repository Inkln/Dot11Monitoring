import tqdm
import threading
import sys
import time

class Formatter:
    @staticmethod
    def format_list(data: list=None) -> str:
        result = ''

        it = 0
        while it < len(data):
            begin = it
            end = it
            while it + 1 < len(data) and data[it + 1] == data[it] + 1:
                it += 1
                end += 1
            if begin == end:
                result += '{},'.format(data[begin])
            else:
                result += '{}-{},'.format(data[begin], data[end])
            it += 1

        if result == '':
            return '[]'
        else:
            return '[' + result[:-1] + ']'


class ProgressBar:
    def __init__(self, timeout: float, desk=None):
        self.timeout = timeout
        self.desc = desk

    def __enter__(self):
        self.thread = threading.Thread(target=self.worker)
        self.thread.start()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.thread.join()

    def worker(self):
        n_steps = 100
        s = tqdm.tqdm(range(n_steps),  desc=self.desc, total=n_steps, bar_format='{l_bar}[{bar}]', file=sys.stdout)

        for _ in s:
            time.sleep(self.timeout / n_steps)