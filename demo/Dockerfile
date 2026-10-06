FROM python:3.12-slim
RUN pip install --no-cache-dir cryptography==50.0.0 && useradd --uid 10001 --create-home lab
WORKDIR /lab
COPY lab.py .
USER 10001:10001
CMD ["python", "lab.py"]
