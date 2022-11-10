FROM python:3.9-bullseye

RUN mkdir /app
RUN mkdir /fluxvault_agent
WORKDIR /fluxvault_agent

RUN pip3 install aiotinyrpc[socket] aiofiles requests

ADD fluxvault ./fluxvault
COPY agent.py .

CMD ["python", "agent.py"]
