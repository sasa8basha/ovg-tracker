FROM python:3.9
WORKDIR /code
COPY ./requirements.txt /code/requirements.txt
RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt
COPY . .

# نزّل ملف City الكبير من الـ Release
RUN curl -L -o /code/GeoLite2-City.mmdb https://github.com/sasa8basha/ovg-tracker/releases/download/geoip-data-v1/GeoLite2-City.mmdb

# ملف ASN المرفوع عادي في المشروع
COPY GeoLite2-ASN.mmdb /code/GeoLite2-ASN.mmdb

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "7860"]
