import pyb

button = False


def cb_switch():
    global button
    button = True


def up_check():
    return True
    global button
    MAX_TIME = const(10000)  # 10 seconds
    DELAY_TIME = const(10)   # 10 ms
    WINK_FREQ = 10  # Hz
    sw = pyb.Switch()
    sw.callback(cb_switch)
    counter = 0
    while button is False and counter < MAX_TIME:
        if ((counter * WINK_FREQ) // 2000) % 2 == 0:
            pyb.LED(1).on()
        else:
            pyb.LED(1).off()
        pyb.delay(DELAY_TIME)
        counter += DELAY_TIME

    sw.callback(None)
    return button
