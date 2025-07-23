 docker exec -it cert-signer /bin/sh
 docker exec cert-signer step version

 docker logs cert-signer | grep -i "csr" -A 3

docker exec cert-signer cat /home/step/secrets/password

docker exec cert-signer ls -l /tmp
docker exec cert-signer ls -l /tmp | grep '\.csr'
 docker exec cert-signer ls -ld /tmp
docker exec cert-signer sh -c 'touch /tmp/testfile && ls -l /tmp/testfile && rm /tmp/testfile'

docker logs cert-signer | grep -A 15 'Received CSR request'
docker exec cert-signer cat /tmp/tmp-1-xxxxxxxxxxxxxxxx-.csr

docker exec cert-signer which step


