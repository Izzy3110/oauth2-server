import json
import os.path
import sys
import time

import pytesseract
from pytesseract import Output
import argparse
import cv2

args = argparse.ArgumentParser()
args.add_argument("-i", "--image", required=True,
                  help="path to input image to be OCR'd")
args.add_argument("-d", "--digits", type=int, default=1,
                  help="whether or not *digits only* OCR will be performed")
args_ = vars(args.parse_args())

while True:
    print("tick")
    image = cv2.imread(args_["image"])
    tmp_image = cv2.imread(args_["image"])
    im_gray = cv2.imread(args_["image"], cv2.IMREAD_GRAYSCALE)
    rgb = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)

    options = ""
    if args_["digits"] > 0:
        options = "outputbase digits"

    d = pytesseract.image_to_data(rgb, output_type=Output.DICT)
    n_boxes = len(d['level'])
    for i in range(n_boxes):
        (x, y, w, h) = (d['left'][i], d['top'][i], d['width'][i], d['height'][i])
        cv2.rectangle(tmp_image, (x, y), (x + w, y + h), (0, 255, 0), 2)
    f_splitted = os.path.basename(args_["image"]).split(".")
    cv2.imwrite(os.path.join("current_screenshots", f_splitted[0]+"_tmp"+".png"), tmp_image)
    cv2.imwrite(os.path.join("current_screenshots", f_splitted[0]+"_gray"+".png"), im_gray)
    time.sleep(5)
