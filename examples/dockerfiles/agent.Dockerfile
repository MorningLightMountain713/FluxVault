FROM python:3.10.10-bullseye

RUN pip install fluxvault==0.7.10

# Default powerline10k theme, no plugins installed
RUN sh -c "$(wget -O- https://github.com/deluan/zsh-in-docker/releases/download/v1.1.4/zsh-in-docker.sh)"

CMD ["fluxvault", "agent"]
