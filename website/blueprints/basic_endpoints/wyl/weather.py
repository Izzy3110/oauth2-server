import json
import os.path
import time

import requests

last_weather_data = {

}


class Weather(object):
    message = None
    owm_token = None

    lat = None
    lon = None

    last_weather_data = None

    def __init__(self, owm_token, lat=None, lon=None):
        if lat is not None:
            self.lat = float(lat)
        if lon is not None:
            self.lon = float(lon)
        if (lat is not None and lon is None) or (lon is not None and lat is None):
            print("error: lat requires lon and vice versa")
            return

        self.owm_token = owm_token
        if self.lat is not None and self.lon is not None:
            self.last_weather_data = self.get_weather_data(self.lat, self.lon)

    def get_weather_data(self, lat, lon):
        url = "https://api.openweathermap.org/data/2.5/weather?lat=%s&lon=%s&appid=%s&units=metric" % (
        lat, lon, self.owm_token)
        response = requests.get(url)
        data = json.loads(response.text)

        new_content = [{
            "lat": lat,
            "lon": lon,
            "t": time.time(),
            "data": data
        }]

        if not os.path.isfile("last_weather_data.json"):
            with open("last_weather_data.json","w") as last_weather_data_f:
                last_weather_data_f.write(json.dumps(new_content, indent=4))
                last_weather_data_f.close()
        else:
            with open("last_weather_data.json") as last_weather_data_fr:
                content = last_weather_data_fr.read()
                if len(content) > 0:
                    try:
                        json_content = json.loads(content)
                        # for item in json_content:
                        #    print(item.keys())
                        new_list = json_content
                        new_list.append(new_content[0])
                        with open("last_weather_data.json", "w") as last_weather_data_f:
                            last_weather_data_f.write(json.dumps(new_list,indent=4))
                            last_weather_data_f.close()
                        # print("appended")
                    except json.decoder.JSONDecodeError:
                        with open("last_weather_data.json", "w") as last_weather_data_f:
                            last_weather_data_f.write(json.dumps(new_content, indent=4))
                            last_weather_data_f.close()
                        pass
                else:
                    with open("last_weather_data.json", "w") as last_weather_data_f:
                        last_weather_data_f.write(json.dumps(new_content, indent=4))
                        last_weather_data_f.close()

        return data

    def process_message(self, message):
        print(message.author.name)
        print(message.content)

