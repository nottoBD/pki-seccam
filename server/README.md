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


###### COPY TRUSTED USERS CERTIF AND PROVE THEY ARE PKI SIGNED
docker cp step-ca:/home/step/certs/root_ca.crt .
docker cp step-ca:/home/step/certs/intermediate_ca.crt .
docker cp server:/certs/org_{orgname}_{countryCode}.crt.pem org.crt
docker cp server:/certs/{trustedUsername}.crt.pem user.crt
openssl verify -CAfile root_ca.crt -untrusted intermediate_ca.crt org.crt
openssl verify -CAfile root_ca.crt -untrusted intermediate_ca.crt user.crt