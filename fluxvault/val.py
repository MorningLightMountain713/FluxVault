# Will need to do this sooner or later. Keeper should sign message from nodes

import subprocess

data = "action=sign&message=1668139811204u8pw3875jueid3a4955tbnl9vzxr474chbrowvofh4&icon=https%3A%2F%2Fraw.githubusercontent.com%2Frunonflux%2Fflux%2Fmaster%2FzelID.svg&callback=https://api.runonflux.io/id/verifylogin"

subprocess.run(["open", "-a", "zelcore", data])
