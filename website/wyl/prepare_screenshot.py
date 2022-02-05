import json
import os
import sys
import time

import mss
import mss.tools
from screeninfo import get_monitors


def on_exists(fname):
    # type: (str) -> None
    """
    Callback example when we try to overwrite an existing screenshot.
    """

    if os.path.isfile(fname):
        newfile = fname + ".old"
        if os.path.isfile(newfile):
            os.remove(newfile)
        print("{} -> {}".format(fname, newfile))
        os.rename(fname, newfile)


def single_monitor():
    with mss.mss() as sct:
        filename = sct.shot(output="current_screenshots/mon-{mon}.png", callback=on_exists)
        print(filename)


class ScreenShot(object):
    region = None
    im = None

    def __init__(self):
        pass

    def set_region(self, region):
        self.region = region

    def make_screenshot(self):
        for current_monitor_num in range(0, 4):
            with mss.mss() as sct:
                mon = sct.monitors[current_monitor_num]
                monitor = {
                    "top": mon["top"],
                    "left": mon["left"],
                    "width": mon["width"],
                    "height": mon["height"],
                    "mon": current_monitor_num,
                }
                output = "current_screenshots/sct-mon{mon}_{top}x{left}_{width}x{height}.png".format(**monitor)
                sct_img = sct.grab(monitor)
                if os.path.isfile(output):
                    print("existing")
                mss.tools.to_png(sct_img.rgb, sct_img.size, output=output)

    def make_single_screenshot(self, monitor_number, region):
        with mss.mss() as sct:
            mon = sct.monitors[monitor_number]
            print("w: " + str(region[2]))
            print("h: "+str(region[3]))
            monitor = {
                "top": region[1],
                "left": region[0],
                "width": region[2],
                "height": region[3],
                "mon": monitor_number,
            }
            output = "current_screenshots/sct-single-mon{mon}_{top}x{left}_{width}x{height}.png".format(**monitor)
            sct_img = sct.grab(monitor)
            if os.path.isfile(output):
                print("existing")
            mss.tools.to_png(sct_img.rgb, sct_img.size, output=output)


last_screenshot_t = 0


if __name__ == '__main__':
    s = ScreenShot()
    monitors_ = []
    for monitor in get_monitors():
        width = monitor.width
        height = monitor.height
        monitors_.append((width, height))
        print(str(width) + 'x' + str(height))
    print(monitors_)
    all_width = 0
    for m in monitors_:
        all_width += m[0]
    print(all_width)
    third_monitor_x = all_width - monitors_[len(monitors_)-1][0]
    x_start = third_monitor_x
    y_start = monitors_[0][1] - 460

    x_width = monitors_[len(monitors_)-1][0]
    y_height = 420

    try:
        while True:
            if last_screenshot_t == 0:
                s.make_single_screenshot(3, (x_start, y_start, x_width, y_height))
                last_screenshot_t = time.time()
            else:
                if int(time.time() - last_screenshot_t) >= 1:
                    s.make_single_screenshot(3, (x_start, y_start, x_width, y_height))
                    last_screenshot_t = time.time()
            time.sleep(1)
    except KeyboardInterrupt:
        print("interrupted")