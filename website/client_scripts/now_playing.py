import os
import time
import urllib3
import requests
import spotipy
from datetime import datetime


def update_song(artist, title, song_id):
    print("updating")
    client_id = os.environ["CLIENT_ID"]
    client_secret = os.environ["CLIENT_SECRET"]

    req_session = requests.session()

    # Basic Auth
    req_session.auth = (client_id, client_secret)

    resp = req_session.post("https://oauth2.wyl-online.de/oauth/token",data={
        "username": os.environ["APP_USERNAME"],
        "password": os.environ["USER_PASSWORD"],
        "scope": "spotify:now-playing",
        "grant_type": "password"
    })

    if resp.status_code == 200:
        resp_json = resp.json()
        req_session_ = requests.session()
        req_session_.headers = {"Authorization": "Bearer "+resp_json["access_token"]}
        params_new = {
            "artist": artist,
            "title": title,
            "id": song_id
        }
        resp = req_session_.post("https://oauth2.wyl-online.de/api/spotify/now-playing", data=params_new)
        if resp.status_code == 200:
            print("ok - inserted")
    else:
        print(resp.status_code)
        print(resp.text)

urllib3.disable_warnings()

scope = "user-read-currently-playing"

spotifyOAuth = spotipy.SpotifyOAuth(client_id=os.environ['SPOTIPY_CLIENT_ID'],
                                    client_secret=os.environ['SPOTIPY_CLIENT_SECRET'],
                                    redirect_uri=os.environ['SPOTIPY_REDIRECT_URI'],
                                    scope=scope)
token = spotifyOAuth.get_access_token()
spotifyObject = spotipy.Spotify(auth=token['access_token'])

resltObj = {
    "id": None,
    "artist": "",
    "title": "",
    "current_type": None
}

results_ = None
current_track = {}
current_track_t = 0


def gen_date():
    return datetime.now().strftime("%d.%m.%Y %H:%M:%S.%f")


ad_detected_outputted = False


def update_current_track():
    global spotifyObject, token, \
        current_track_t, results_, \
        resltObj, ad_detected_outputted

    if resltObj["current_type"] is not None:
        try:
            current = spotifyObject.currently_playing()
            current_type = current['currently_playing_type']
            if current_type != "ad":
                if ad_detected_outputted is True:
                    ad_detected_outputted = False
                artist = current['item']['artists'][0]['name']
                title = current['item']['name']
                song_id = current["item"]["id"]
                resltObj["id"] = song_id
                if artist == results_["artist"] and title == results_["title"]:
                    return
                else:
                    resltObj["artist"] = artist
                    resltObj["title"] = title
                    print(gen_date() + ": (" + resltObj["id"] + ") " + artist + " - " + title)
                    update_song(artist, title, song_id)
                if current_type != resltObj["current_type"]:
                    print(current_type)
                    print(resltObj["current_type"])
                    print("type changed")
                    resltObj["current_type"] = current_type

            else:
                if ad_detected_outputted is False:
                    print("ad detected")
                    ad_detected_outputted = True
                    resltObj["id"] = None
                    resltObj["current_type"] = "ad"
        except spotipy.exceptions.SpotifyException as e:
            print(str(e))
        except requests.exceptions.ReadTimeout as rt:
            print(str(rt))
    else:
        print(">> updating current track")
        current_track_t = time.time()
        current = spotifyObject.currently_playing()
        current_type = current['currently_playing_type']
        if current_type == "track":
            artist = current['item']['artists'][0]['name']
            title = current['item']['name']
            song_id = current["item"]["id"]
            resltObj["artist"] = artist
            resltObj["title"] = title
            resltObj["id"] = song_id
            print(gen_date() + ": (" + resltObj["id"] + ") " + artist + " - " + title)
            update_song(artist, title, song_id)
            """
            length_ms = current['item']['duration_ms']
            progress_ms = current['progress_ms']
            time_ms = length_ms - progress_ms
            time_sec = int((time_ms / 1000))
            """

        elif current_type == "ad":
            print(">> ad popped up -- sleeping...")
            resltObj["id"] = None
        resltObj["current_type"] = current_type
        results_ = resltObj
    # Check if access token has expired or not
    if spotifyOAuth.is_token_expired(token):
        print(">> access token has expired -- refreshing...")
        token = spotifyOAuth.get_access_token()
        spotifyObject = spotipy.Spotify(auth=token['access_token'])


if __name__ == '__main__':
    while True:
        if current_track_t == 0:
            update_current_track()
        else:
            if int(time.time() - current_track_t) > 1:
                update_current_track()
        time.sleep(.5)
