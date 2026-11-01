FROM python:3.9
WORKDIR /code
COPY ./requirements.txt /code/requirements.txt
RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt
COPY . .
# GeoLite2 databases — لازم يكونوا في جذر المشروع قبل الـ build
COPY GeoLite2-City.mmdb /code/GeoLite2-City.mmdb
COPY GeoLite2-ASN.mmdb  /code/GeoLite2-ASN.mmdb
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "7860"]
