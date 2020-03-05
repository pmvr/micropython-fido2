import pyb

timer_wink = None
timer_wink_counter = 0


def init_timer():
    global timer_wink, timer_wink_counter
    timer_wink = pyb.Timer(4)
    timer_wink.init(freq=2)
    timer_wink.callback(None)
    timer_wink_counter = 0


def setup_timer(counter=10):
    global timer_wink, timer_wink_counter
    timer_wink.callback(None)
    timer_wink_counter = counter
    timer_wink.callback(flash_led)


def flash_led(self):
    global timer_wink_counter
    if timer_wink_counter > 0:
        timer_wink_counter -= 1
        pyb.LED(1).toggle()
