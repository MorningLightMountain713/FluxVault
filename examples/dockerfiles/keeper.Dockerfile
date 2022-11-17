# syntax=docker/dockerfile:1.3-labs

FROM python:3.9-bullseye

RUN pip install fluxvault

WORKDIR /app

RUN <<EOF
echo "1844 Samuel FB Morse: What hath God Wrought?
1876 Alexander Graham Bell: Mr. Watson -- come here -- I want to see you.
2022 Dan Keller: Don't be Evil, again" > quotes.txt
EOF

CMD ["fluxvault", "keeper"]
