# WKS-KEY Apple Music Ripper
#
# This script is an ADDON to WKS-KEY
#
# pip install m3u8 pathvalidate coloredlogs music_tag pillow
#
# requires yt-dlp and shaka-packager (or mp4decrypt if desired) to be installed in the system path

import argparse
import base64
import json
import logging
import os
import re
import subprocess
import sys
from base64 import b64encode
from pathlib import Path

import m3u8
import music_tag
import requests
from coloredlogs import ColoredFormatter
from pathvalidate import sanitize_filename
from pywidevine.L3.cdm import deviceconfig
from pywidevine.L3.cdm.formats.widevine_pssh_data_pb2 import WidevinePsshData
from pywidevine.L3.decrypt.wvdecryptcustom import WvDecrypt

BANNER = """
    ___                __        __  ___           _         ____  _                      
   /   |  ____  ____  / /__     /  |/  /_  _______(_)____   / __ \(_)___  ____  ___  _____
  / /| | / __ \/ __ \/ / _ \   / /|_/ / / / / ___/ / ___/  / /_/ / / __ \/ __ \/ _ \/ ___/
 / ___ |/ /_/ / /_/ / /  __/  / /  / / /_/ (__  ) / /__   / _, _/ / /_/ / /_/ /  __/ /    
/_/  |_/ .___/ .___/_/\___/  /_/  /_/\__,_/____/_/\___/  /_/ |_/_/ .___/ .___/\___/_/     
      /_/   /_/                                                 /_/   /_/                                                         
By Puyodead1
Version 1.0.10
"""

# setup logger
logging.root.setLevel(logging.INFO)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = ColoredFormatter("[%(asctime)s] %(levelname)s: %(message)s", datefmt="%I:%M:%S")
stream = logging.StreamHandler()
stream.setLevel(logging.INFO)
stream.setFormatter(formatter)
logger.addHandler(stream)

BEARER_TOKEN = "Bearer xxxxxxxxxxxxxxxxxxxxxx"  # edit this as needed
APPLE_MUSIC_TOKEN = "xxxxxxxxxxxxxxxxxxxxxx"  # edit this as needed
DEVICE = deviceconfig.device_android_generic  # edit this as needed

# you shouldn't need to change anything below this
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0",
    "Accept": "application/json",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Referer": "https://music.apple.com/",
    "authorization": BEARER_TOKEN,
    "content-type": "application/json",
    "x-apple-music-user-token": APPLE_MUSIC_TOKEN,
    "x-apple-renewal": "true",
    "Origin": "https://music.apple.com",
    "DNT": "1",
    "Connection": "keep-alive",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-site",
}

VAULT_FILE_PATH = Path(os.getcwd(), "keys.json")

session = requests.Session()
session.headers.update(HEADERS)

AMP_URL = "https://amp-api.music.apple.com/v1/catalog/us/{type}/{id}"
PLAYBACK_URL = "https://play.music.apple.com/WebObjects/MZPlay.woa/wa/webPlayback"
PLAYLIST_URL = "https://amp-api.music.apple.com/v1/catalog/us/albums/{playlist_id}?l=en-us&platform=web&omit[resource]=autos&include=tracks,artists&include[songs]=artists,composers&extend[url]=f"

# ALBUM_MUSIC_VIDEO_REGEX = re.compile(r"//music\.apple\.com/.*/(?P<type>.*)/(?P<name>.*)/(?P<track_id>\d*)$")
# TRACK_REGEX = re.compile(r"//music.apple.com/.*/(?P<album_id>\d*)\?i=(?P<track_id>\d*)$")
REGEX = re.compile(r"//music\.apple\.com/.*/(?P<type>.*)/(?P<name>.*)/(?P<id>\d*)[\?i=]*(?P<track_id>\d*)?$")


URL: str = None
INFO_ONLY = False
USE_MKV = False
USE_MP4_DECRYPT = False


def WV_Function(track_id, key_id, license_url, cert_data_b64):
    pssh_data = WidevinePsshData()
    pssh_data.algorithm = 1
    pssh_data.key_id.append(base64.b64decode(key_id.split(",")[1]))
    pssh = base64.b64encode(pssh_data.SerializeToString()).decode("utf8")
    wvdecrypt = WvDecrypt(init_data_b64=pssh, cert_data_b64=cert_data_b64, device=DEVICE)

    data = {"challenge": b64encode(wvdecrypt.get_challenge()).decode("utf-8"), "key-system": "com.widevine.alpha", "uri": key_id, "adamId": track_id, "isLibrary": False, "user-initiated": True}
    license_response = session.post(url=license_url, data=json.dumps(data))
    if license_response.status_code != 200:
        logger.fatal(f"[{license_response.status_code}] {license_response.reason}: {license_response.content}")
        sys.exit(1)
    license_response_json = license_response.json()
    if not "license" in license_response_json:
        logger.fatal("Invalid license response")
        logger.fatal(license_response_json)
        sys.exit(1)
    license_b64 = license_response_json["license"]

    wvdecrypt.update_license(license_b64)
    correct, keys = wvdecrypt.start_process()
    if correct:
        return correct, keys


def WV_Function_MV(track_id, key_id, license_url, cert_data_b64):
    wvdecrypt = WvDecrypt(init_data_b64=key_id.split(",")[-1], cert_data_b64=cert_data_b64, device=DEVICE)

    data = {"challenge": b64encode(wvdecrypt.get_challenge()).decode("utf-8"), "key-system": "com.widevine.alpha", "uri": key_id, "adamId": track_id, "isLibrary": False, "user-initiated": True}
    license_response = session.post(url=license_url, data=json.dumps(data))
    if license_response.status_code != 200:
        logger.fatal(f"[{license_response.status_code}] {license_response.reason}: {license_response.content}")
        sys.exit(1)
    license_response_json = license_response.json()
    if not "license" in license_response_json:
        logger.fatal("Invalid license response")
        logger.fatal(license_response_json)
        sys.exit(1)
    license_b64 = license_response_json["license"]

    wvdecrypt.update_license(license_b64)
    correct, keys = wvdecrypt.start_process()
    if correct:
        return correct, keys


def get_service_certificate(track_id, key_id, license_url):
    data = {"adamId": track_id, "challenge": "CAQ=", "isLibrary": False, "key-system": "com.widevine.alpha", "uri": key_id, "user-initiated": True}
    license_response = session.post(url=license_url, data=json.dumps(data))
    if license_response.status_code != 200:
        logger.fatal(f"[{license_response.status_code}] {license_response.reason}: {license_response.content}")
        sys.exit(1)
    if license_response.status_code != 200:
        logger.fatal(f"[{license_response.status_code}] {license_response.reason}: {license_response.content}")
        sys.exit(1)
    license_response_json = license_response.json()
    if not "license" in license_response_json:
        logger.fatal("Invalid license response")
        logger.fatal(license_response_json)
        sys.exit(1)
    return license_response_json["license"]


# def extract_track_id(url):
#     obj = re.search(
#         r"//.*\?i=(?P<track_id>\d*)", url)
#     if obj:
#         return obj.group('track_id')


# def extract_playlist_id(url):
#     obj = re.search(
#         r"//[a-zA-Z./]*(?P<playlist_id>\d*)", url)
#     if obj:
#         return obj.group('playlist_id')


def get_info(type, id):
    req = session.get(AMP_URL.format(type=type, id=id))
    if req.status_code != 200:
        logger.fatal(f"[{req.status_code}] {req.reason}: {req.content}")
        return None
    return req.json()


def get_playback_info(track_id):
    data = {"salableAdamId": str(track_id)}
    req = session.post(PLAYBACK_URL, data=json.dumps(data))
    if req.status_code != 200:
        logger.fatal(f"[{req.status_code}] {req.reason}: {req.content}")
        return None
    return req.json()


def download_song(url: str, output_name: str):
    ret_code = subprocess.Popen(["yt-dlp", "--allow-unplayable", "-o", output_name, url]).wait()
    return ret_code


def download_from_playlist(url: str, output_name: str):
    playlist = m3u8.load(url)
    fn = playlist.segments[0].uri
    file_url = playlist.base_uri + fn
    return download_song(file_url, output_name)


def decrypt_file(in_file, out_file, key):
    ret_code = subprocess.Popen(["mp4decrypt", "--key", f"1:{key}", in_file, out_file]).wait()
    return ret_code


def shaka_decrypt(encrypted, decrypted, keys, stream=0):
    decrypt_command = [
        "shaka-packager",
        "--enable_raw_key_decryption",
        "-quiet",
        "input={},stream={},output={}".format(encrypted, stream, decrypted),
    ]
    if isinstance(keys, list):
        for key in keys:
            decrypt_command.append("--keys")
            decrypt_command.append("key={}:key_id={}".format(key[1], key[0]))
    else:
        decrypt_command.append("--keys")
        decrypt_command.append("key={}:key_id={}".format(keys[1], keys[0]))
    wvdecrypt_process = subprocess.Popen(decrypt_command, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    stdoutdata, stderrdata = wvdecrypt_process.communicate()
    ret_code = wvdecrypt_process.wait()
    return ret_code


def get_vault() -> list[str]:
    if VAULT_FILE_PATH.exists():
        with VAULT_FILE_PATH.open() as vault_file:
            return json.load(vault_file)
    else:
        # create vault file with empty array
        with VAULT_FILE_PATH.open("w") as vault_file:
            json.dump([], vault_file)
        return []


def save_vault(vault: list[str]):
    with VAULT_FILE_PATH.open("w") as vault_file:
        json.dump(vault, vault_file)


def save_key_to_vault(key_id: str, keys: list[str]):
    VAULT = get_vault()
    for key in keys:
        if key in VAULT:
            logger.warning(f"+ Key {key} already in vault, skipping")
            continue
        VAULT.append(f"{key_id}:{key}")
    save_vault(VAULT)


def get_key_from_vault(key_id: str):
    VAULT = get_vault()
    for key in VAULT:
        if key_id in key:
            s = key.split(":")
            return [f"{s[1]}:{s[2]}"]
    return None


def process(track_id, folder=None, track_number=None):
    directory = folder if folder != None else os.getcwd()
    logger.info("[+] Fetching playback information")
    playback_info = get_playback_info(track_id)
    if not playback_info or "failureType" in playback_info:
        raise Exception("Failed to get playback information!")
    song = playback_info["songList"][0]
    license_url = song["hls-key-server-url"]
    assets = song["assets"]
    asset = next((x for x in assets if x["flavor"] == "28:ctrp256"), None)
    if not asset:
        raise Exception("Failed to find 28:ctrp256 asset")
    asset_url = asset["URL"]
    metadata = asset["metadata"]
    artist_name = sanitize_filename(metadata["artistName"])
    song_name = sanitize_filename(metadata["itemName"])
    file_extension = metadata["fileExtension"]
    filename_tmp = f"{str(track_number) if track_number != None else ''}{'.' if track_number != None else ''} {artist_name} - {song_name}.enc.{file_extension}".strip()
    filename = f"{str(track_number) if track_number != None else ''}{'.' if track_number != None else ''} {artist_name} - {song_name}.{file_extension.replace('m4p', 'm4a')}".strip()
    logger.info(f"[+] Output filename: {filename}")
    tmp_path = os.path.join(directory, filename_tmp)
    out_path = os.path.join(directory, filename)

    # dont process if file already downloaded
    if os.path.exists(out_path):
        logger.warning("[+] File exists, skipping")
        return

    # dont download if we have the encrypted track
    if os.path.exists(tmp_path):
        logger.warning("[+] File exists, skipping download")
    else:
        download_from_playlist(asset_url, tmp_path)

    logger.info("[+] Extracting key id...")
    playlist = m3u8.load(asset_url)
    key_id = playlist.keys[0].uri
    logger.info(f"[+] KID: {key_id}")

    # check if key is in vault
    pssh = key_id.split(",")[1]
    keys = get_key_from_vault(pssh)

    if not keys:
        # if the key is not in the vault, we want to request it
        logger.info("[-] Key not found in vault, license will be requested")
        logger.info("[+] Fetching service certificate...")
        cert_data_b64 = get_service_certificate(track_id, key_id, license_url)
        if not cert_data_b64:
            raise Exception("Failed to get service certificate")

        logger.info("[+] Requesting license...")
        correct, keys = WV_Function(track_id, key_id, license_url, cert_data_b64)
        if not correct or not keys:
            raise Exception("Failed to get license")
        logger.info("[+] Saving key to vault...")
        try:
            save_key_to_vault(pssh, keys)
        except Exception as e:
            raise Exception(f"[-] Failed to save key to vault: {e}")

    else:
        logger.info("[+] Key found in vault, using it")

    formatted_keys = []
    for key in keys:
        kid, key = key.split(":")
        logger.info(f"[+] {kid}:{key}")
        formatted_keys.append((kid, key))

    if len(formatted_keys) > 1:
        logger.info("[+] Multiple keys found, manual intervention required")
    else:
        key = formatted_keys[0]
        logger.info(f"[+] Attempting decryption with key: {key[1]}")
        if USE_MP4_DECRYPT:
            ret_code = decrypt_file(tmp_path, out_path, key[1])
        else:
            ret_code = shaka_decrypt(tmp_path, out_path, key)
        if ret_code != 0:
            raise Exception("Decryption failure")
        else:
            logger.info("[+] Removing temporary file")
            os.remove(tmp_path)
            # tag
            logger.info("[+] Adding metadata")

            data = {
                "album": metadata["playlistName"],
                "albumartist": metadata["artistName"],
                "artist": metadata["artistName"],
                "comment": metadata["copyright"],
                "compilation": metadata["compilation"],
                "composer": metadata["composerName"],
                "discnumber": metadata["discNumber"],
                "genre": metadata["genre"],
                "totaldiscs": metadata["discCount"],
                "totaltracks": metadata["trackCount"],
                "tracknumber": metadata["trackNumber"],
                "tracktitle": metadata["itemName"],
                "year": metadata["year"],
                "isrc": metadata["xid"],
            }

            artwork_request = requests.get(asset["artworkURL"])
            if artwork_request.ok:
                data["artwork"] = artwork_request.content
            else:
                logger.warning("[+] Failed to get artwork")

            try:
                tag_file(data, out_path)
            except Exception as e:
                logger.warning(f"[+] Failed to tag file: {e}")


def process_album(album_id):
    album_info = get_info("albums", album_id)
    if not album_info:
        raise Exception("Failed to get album info")
    album_name = sanitize_filename(album_info["data"][0]["attributes"]["name"])
    # remove trailing periods from album name that can cause issues on windows
    album_name = "".join(album_name.rsplit(".", 1))
    if not os.path.exists(album_name):
        os.mkdir(album_name)
    tracks = album_info["data"][0]["relationships"]["tracks"]["data"]
    for track in tracks:
        track_id = track["id"]
        track_name = track["attributes"]["name"]
        track_number = track["attributes"]["trackNumber"]
        logger.info(f"[+] Processing track {str(track_number)} - {track_name}")
        try:
            process(track_id, album_name, track_number)
        except Exception as e:
            logger.error(f"[-] Failed to process track {str(track_number)} - {track_name}")
            logger.error(e)


def process_music_video(id):
    logger.info("[+] Fetching video information")
    video_info = get_info("music-videos", id)
    if not video_info:
        raise Exception("[-] Failed to get video info")
    metadata = video_info["data"][0]["attributes"]
    logger.info("[+] Fetching playback information")
    playback_info = get_playback_info(id)
    if not playback_info:
        raise Exception("Failed to get playback info")
    song = playback_info["songList"][0]
    license_url = song["hls-key-server-url"]
    asset_url = song["hls-playlist-url"]
    artist_name = sanitize_filename(metadata["artistName"])
    song_name = sanitize_filename(metadata["name"])

    # encrypt files
    audio_enc_filename = f"{artist_name} - {song_name}.audio.enc.m4p".strip()
    video_enc_filename = f"{artist_name} - {song_name}.video.enc.mp4".strip()
    #

    # decrypted files
    audio_dec_filename = f"{artist_name} - {song_name}.audio.dec.m4a".strip()
    video_dec_filename = f"{artist_name} - {song_name}.video.dec.mp4".strip()
    #
    filename = f"{artist_name} - {song_name}.{'mkv' if USE_MKV else 'mp4'}".strip()
    logger.info(f"[+] Output filename: {filename}")

    # encrypted files
    audio_enc_path = os.path.join(os.getcwd(), audio_enc_filename)
    video_enc_path = os.path.join(os.getcwd(), video_enc_filename)
    #

    # decrypted files
    audio_dec_path = os.path.join(os.getcwd(), audio_dec_filename)
    video_dec_path = os.path.join(os.getcwd(), video_dec_filename)
    #
    out_path = os.path.join(os.getcwd(), filename)

    playlist = m3u8.load(asset_url)
    audio_playlist_url = [x for x in playlist.media if x.type == "AUDIO"][-1].uri
    video_playlist_url = playlist.playlists[-1].uri

    # dont process if file already downloaded
    if os.path.exists(out_path):
        logger.warning("[+] File exists, skipping")
        return

    # dont download audio if we have it already
    if os.path.exists(audio_enc_path) or os.path.exists(audio_dec_path):
        logger.warning("[+] Audio File exists, skipping download")
    else:
        download_song(audio_playlist_url, audio_enc_path)

    # dont download video if we have it already
    if os.path.exists(video_enc_path) or os.path.exists(video_dec_path):
        logger.warning("[+] Video File exists, skipping download")
    else:
        download_song(video_playlist_url, video_enc_path)

    if not os.path.exists(audio_dec_path):
        logger.info("[+] Extracting key id for audio...")
        audio_playlist = m3u8.load(audio_playlist_url)
        audio_key_id = next(x for x in audio_playlist.keys if x.keyformat == "urn:uuid:edef8ba9-79d6-4ace-a3c8-27dcd51d21ed").uri
        if not audio_key_id:
            logger.fatal("[-] Failed to find audio key id with widevine system id")
            exit(1)

        logger.info(f"[+] Audio Key ID: {audio_key_id}")
        postprocess_mv(id, audio_key_id, license_url, audio_enc_path, audio_dec_path)
    else:
        logger.warning("[+] Decrypted audio file already exists, skipping")

    if not os.path.exists(video_dec_path):
        video_playlist = m3u8.load(video_playlist_url)
        video_key_id = next(x for x in video_playlist.keys if x.keyformat == "urn:uuid:edef8ba9-79d6-4ace-a3c8-27dcd51d21ed").uri
        if not video_key_id:
            logger.fatal("[-] Failed to find video key id with widevine system id")
            exit(1)

        logger.info(f"[+] Video Key ID: {video_key_id}")

        postprocess_mv(id, video_key_id, license_url, video_enc_path, video_dec_path)
    else:
        logger.warning("[+] Decrypted video file already exists, skipping")

    logger.info("[+] Merging audio and video")
    if USE_MKV:
        merge_mkv(audio_dec_path, video_dec_path, out_path)
    else:
        merge(audio_dec_path, video_dec_path, out_path)

    logger.info("[+] Removing temporary files")

    try_remove_file(audio_enc_path)
    try_remove_file(video_enc_path)
    try_remove_file(audio_dec_path)
    try_remove_file(video_dec_path)


def try_remove_file(path):
    try:
        os.remove(path)
    except:
        logger.warning(f"[-] Failed to remove file: {path}")


def postprocess_mv(id, key_id, license_url, tmp_path, out_path):
    logger.info("[+] Fetching service certificate...")
    cert_data_b64 = get_service_certificate(id, key_id, license_url)
    if not cert_data_b64:
        raise Exception("Failed to get service certificate")

    logger.info("[+] Requesting license...")
    correct, keys = WV_Function_MV(id, key_id, license_url, cert_data_b64)
    if not correct or not keys:
        raise Exception("Failed to get license")

    formatted_keys = []
    for key in keys:
        print(key)
        kid, key = key.split(":")
        logger.info(f"[+] {kid}:{key}")
        formatted_keys.append((kid, key))

    if len(formatted_keys) > 1:
        logger.error("[-] Multiple keys found, manual intervention required")
    else:
        key = formatted_keys[0]
        logger.info(f"[+] Attempting decryption with key: {key[1]}")
        if USE_MP4_DECRYPT:
            ret_code = decrypt_file(tmp_path, out_path, key[1])
        else:
            ret_code = shaka_decrypt(tmp_path, out_path, key)
        if ret_code != 0:
            raise Exception("Decryption failure")
        else:
            logger.info("[+] Removing temporary file")
            try_remove_file(tmp_path)


def merge(audio, video, final):
    ret_code = subprocess.Popen(["ffmpeg", "-fflags", "+igndts", "-i", video, "-i", audio, "-c", "copy", final]).wait()
    if ret_code != 0:
        raise Exception("Failed to merge audio and video: non-zero return code")
    return ret_code


def merge_mkv(audio, video, final):
    ret_code = subprocess.Popen(
        ["mkvmerge", "--priority", "lower", "--output", final, "--language", "0:und", "(", video, ")", "--language", "0:und", "(", audio, ")", "--track-order", "0:0,1:0"]
    ).wait()
    if ret_code != 0:
        raise Exception("Failed to merge audio and video: non-zero return code")
    return ret_code


def tag_file(data: dict, path: str):
    f = music_tag.load_file(path)

    for key, value in data.items():
        f[key] = value

    f.save()


if __name__ == "__main__":
    logger.info(BANNER)

    parser = argparse.ArgumentParser(description="Apple Music Ripper")
    parser.add_argument("url", type=str, help="Song, Album or Music Video URL", metavar="URL")

    parser.add_argument("-d", "--debug", dest="debug", action="store_true", help="Enable debug logging")
    parser.add_argument("-mkv", "--mkv", dest="use_mkv", action="store_true", help="Merge with mkvmerge instead of ffmpeg")
    parser.add_argument("-i", "--info", dest="info", action="store_true", help="Prints information about this title, doesn't download anything or obtain any keys")
    parser.add_argument("-m4", "--mp4decrypt", dest="mp4_decrypt", action="store_true", help="Use mp4decrypt instead of shaka-packager to decrypt files")

    args = parser.parse_args()

    url = args.url
    if args.debug:
        logging.root.setLevel(logging.DEBUG)
        logger.setLevel(logging.DEBUG)
        stream.setLevel(logging.DEBUG)
    if args.info:
        INFO_ONLY = True
    if args.use_mkv:
        USE_MKV = True
    if args.mp4_decrypt:
        USE_MP4_DECRYPT = True

    matches = re.search(REGEX, url)
    if not matches:
        logger.fatal("[-] Invalid URL: Only Songs, Albums, and Music Videos are supported")
        exit(1)

    url_type = matches.group(1)
    name = matches.group(2)
    main_id = matches.group(3)
    track_id = matches.group(4)

    try:
        if url_type == "album" and track_id:
            process(track_id)
        elif url_type == "album":
            process_album(main_id)
        elif url_type == "music-video":
            process_music_video(main_id)
        else:
            logger.fatal("[-] Invalid URL: Only Songs, Albums, and Music Videos are supported")
    except Exception as e:
        logger.exception(f"[-] Error: {e}")
