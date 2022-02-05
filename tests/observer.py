import time
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler
import os
import subprocess

modified_ = {}

def on_created(event):
    print(f"hey, {event.src_path} has been created!")

def on_deleted(event):
    print(f"what the f**k! Someone deleted {event.src_path}!")

basenames_ = ["templates"]

in_progress = False

def on_modified(event):
    global in_progress
    if os.path.isdir(event.src_path):
        if os.path.basename(event.src_path) in basenames_:
            print(f"hey buddy, {event.src_path} has been modified")
            if event.src_path not in modified_.keys():
                in_progress = True
                print("starting proess")
                with subprocess.Popen("systemctl restart flask-oauth2-server", shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE) as ps:
                    out, err = ps.communicate()
                    if len(err) == 0:
                        print(out)
                print("starting proess")
                with subprocess.Popen("systemctl restart nginx", shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE) as ps:
                    out, err = ps.communicate()
                    if len(err) == 0:
                        print(out)
                in_progress = False
                modified_[event.src_path] = {
                    "t": time.time()
                }
            else:
                if int(time.time() - modified_[event.src_path]["t"]) > 10:
                    if not in_progress:
                        print("restarting process")
                        print("starting proess")
                        in_progress = True
                        with subprocess.Popen("systemctl restart flask-oauth2-server", shell=True,
                                              stderr=subprocess.PIPE, stdout=subprocess.PIPE) as ps:
                            out, err = ps.communicate()
                            if len(err) == 0:
                                print(out)
                        print("starting proess")
                        with subprocess.Popen("systemctl restart nginx", shell=True, stderr=subprocess.PIPE,
                                              stdout=subprocess.PIPE) as ps:
                            out, err = ps.communicate()
                            if len(err) == 0:
                                print(out)

                        in_progress = False
                    else:
                        print("already processing...")
                else:
                    print("not in time")
                    if not in_progress:
                        print("and in progress")


def on_moved(event):
    print(f"ok ok ok, someone moved {event.src_path} to {event.dest_path}")


if __name__ == "__main__":
    patterns = ["*"]
    ignore_patterns = None
    ignore_directories = False
    case_sensitive = True
    my_event_handler = PatternMatchingEventHandler(patterns, ignore_patterns, ignore_directories, case_sensitive)

    my_event_handler.on_created = on_created
    my_event_handler.on_deleted = on_deleted
    my_event_handler.on_modified = on_modified
    my_event_handler.on_moved = on_moved

    path = "/usr/local/oauth2-server"
    go_recursively = True
    my_observer = Observer()
    my_observer.schedule(my_event_handler, path, recursive=go_recursively)

    my_observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        my_observer.stop()
        my_observer.join()
