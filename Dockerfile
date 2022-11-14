FROM python:3.9-bullseye

RUN pip install fluxvault

CMD ["fluxvault", "agent"]
