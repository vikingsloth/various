#!/usr/bin/env python3
# The D-Region Absorption Product addresses the operational impact of the
# solar X-ray flux and SEP events on HF radio communication. Long-range
# communications using high frequency (HF) radio waves (3 - 30 MHz) depend on
# reflection of the signals in the ionosphere. Radio waves are typically
# reflected near the peak of the F2 layer (~300 km altitude), but along the
# path to the F2 peak and back the radio wave signal suffers attenuation due
# to absorption by the intervening ionosphere.
# https://www.swpc.noaa.gov/products/d-region-absorption-predictions-d-rap
#
# This tool grabs the latest D region absorbtion data showing the highest
# frequency affected by 1dB of absorbtion based on the closest coordinates
# to the given maidenhead grid square locator value. When this value spikes
# you're likely to see radio blackouts below the given frequency value in
# mhz.
#
# An example during a flare when the sun is over the atlantic affecting that
# region but not yet in Montana. This would affect communication with Europe
# but not Asia.
# $ ./drap.py DN47
# 0.0
# $ ./drap.py HL888
# 16.4


import requests
import re

class GridSquare:

    def __init__(self, grid = None):
        self.grid = grid

    def field_char_offset(self, char):
        return ord(char) - ord('A')

    def get_lonlat(self):
        if not self.grid or len(self.grid) < 4:
            raise Exception("Missing grid square locator")

        chars = list(self.grid)
        lon_chars = chars[0::2]
        lat_chars = chars[1::2]

        lon = -180
        lat = -90

        # Field
        lon += self.field_char_offset(lon_chars[0]) * 20 
        lat += self.field_char_offset(lat_chars[0]) * 10 

        # Square
        lon += int(lon_chars[1]) * 2
        lat += int(lat_chars[1]) * 1

        return (lon, lat)


class SolarDRap:

    RE_LON = re.compile("^\s*[-]*\d+ \|")
    RE_WSPACE = re.compile("\s+")

    def __init__(self, lon, lat, filename = None):
        self.lon = self.round_coord(lon, 2)
        self.lat = self.round_coord(lat, 4)
        self.lon_pos = int(self.lon_offset())
        self.lat_pos = int(self.lat_offset())
        self.filename = filename

    def parse_drap_data(self, data):
        out = []
        for line in data.splitlines():
            match = self.RE_LON.match(line)
            if match:
                # " 89 | 3.8 3.8 "...
                parts = line.split("|")
                # ['3.8','3.8',...]
                out.append(self.RE_WSPACE.sub(",", parts[1][2:]).split(","))
                continue
        return out

    def round_coord(self, coord, interval):
        # Lat coords come in intervals of 4 starting at 2. Lons come in 2s starting at 1
        # 6 % 4 == 2, 2 % 4 == 2
        # Find the smallest difference in the modulos and sum it with the value
        mod = coord % interval
        if mod == 2:
            return coord
        diff = 2 - mod
        return coord + diff

    def lon_offset(self):
        diff = self.lat - -89
        return abs(diff) / 2

    def lat_offset(self):
        diff = -178 - self.lat
        return abs(diff) / 4

    def get_drap_http(self, url = "https://services.swpc.noaa.gov/text/drap_global_frequencies.txt"):
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36"
        }
        r = requests.get(url, headers = headers)
        if r.status_code != 200:
            return None
        return r.text

    def get_drap_file(self, filename):
        return open(filename, "r").read()

    def get(self):
        if self.filename:
            raw = self.get_drap_file(self.filename)
        else:
            raw = self.get_drap_http()
        data = self.parse_drap_data(raw)
        return data[self.lon_pos][self.lat_pos]



if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        sys.stderr.write(f"Usage: {sys.argv[0]} <grid>\n")
        sys.exit(-1)

    grid = sys.argv[1]
    if len(sys.argv) >= 3:
        filename = sys.argv[2]
    else:
        filename = None

    lon, lat = GridSquare(grid).get_lonlat()
    #print(f"Fetching DRap data for {grid} {lat},{lon}")
    drap = SolarDRap(lon, lat, filename)
    print(drap.get())
