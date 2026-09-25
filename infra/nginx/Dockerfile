FROM nginx:alpine

RUN apk add --no-cache openssl

COPY nginx.conf /etc/nginx/nginx.conf
COPY generate-cert.sh /generate-cert.sh
RUN chmod +x /generate-cert.sh

ENTRYPOINT ["/bin/sh", "-c", "/generate-cert.sh && exec nginx -g 'daemon off;'"]
