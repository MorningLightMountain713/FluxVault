FROM python:3.11.2-bullseye

RUN apt update && apt install python3-apt -y

RUN ln -s /usr/lib/python3/dist-packages/apt_pkg.cpython-39-x86_64-linux-gnu.so /usr/lib/python3/dist-packages/apt_pkg.so

ENV PYTHONPATH="/usr/lib/python3/dist-packages"

# Default powerline10k theme, no plugins installed
RUN sh -c "$(wget -O- https://github.com/deluan/zsh-in-docker/releases/download/v1.1.4/zsh-in-docker.sh)"

RUN pip install fluxvault==0.9.14

RUN python -m compileall

ENTRYPOINT ["fluxvault"]

CMD ["--help"]
