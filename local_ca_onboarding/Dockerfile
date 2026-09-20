ARG BUILD_FROM
FROM ${BUILD_FROM}

RUN apk add --no-cache python3 py3-pip \
    && python3 -m pip install --no-cache-dir --break-system-packages "qrcode==8.2"

COPY app /app
COPY run.sh /run.sh
RUN chmod 0755 /run.sh

WORKDIR /app
EXPOSE 8099
CMD ["/run.sh"]

LABEL \
    org.opencontainers.image.title="Home Assistant App: Local HTTPS Onboarding" \
    org.opencontainers.image.description="Consent-based local CA installation guidance" \
    org.opencontainers.image.licenses="MIT"
