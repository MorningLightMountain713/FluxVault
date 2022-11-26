FROM python:3.9-bullseye

ENV BUILDKIT_PROGRESS plain

RUN python -m pip install --upgrade pip && pip install fluxvault --no-cache-dir

CMD ["fluxvault", "agent"]
