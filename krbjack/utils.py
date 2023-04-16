from threading import Timer


# A Small utility class wrapper around threading.Timer to start
# tasks periodically undefinitely unless asked to stop.
# Use : t = PeriodicTimer(float -> interval, function, *args, **kwargs)
#       f.start()
# The function passed in parameter is called instantly the first time
#   then every n seconds.
# This class is used to perform periodic DNS poisoning.
class PeriodicTimer():
    def __init__(self, seconds, target, *args, **kwargs):
        self._should_continue = False
        self.is_running = False
        self.seconds = seconds
        self.target = target
        self.args = args
        self.kwargs = kwargs
        self.thread = None
        self.is_first = True

    def _handle_target(self):
        self.is_running = True
        self.target(*self.args, **self.kwargs)
        self.is_running = False
        self._start_timer()

    def _start_timer(self):
        if self._should_continue:
            if self.is_first:
                self.thread = Timer(0, self._handle_target)
                self.is_first = False
            else:
                self.thread = Timer(self.seconds, self._handle_target)
            self.thread.start()

    def start(self):
        if not self._should_continue and not self.is_running:
            self._should_continue = True
            self._start_timer()

    def cancel(self):
        if self.thread is not None:
            self._should_continue = False
            self.thread.cancel()
