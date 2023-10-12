<!-- Red Hat Linux -->
172.16.3.103
root
1T@pps1548

<!-- MSSQL + Domain -->
172.16.3.102
Administrator
Admin_1018

<!-- generate private key -->
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
<!-- generate public key -->
openssl rsa -pubout -in private_key.pem -out public_key.pem

<!-- encrypt (txt) -->
echo "helloworld" | openssl pkeyutl -encrypt -pubin -inkey public_key.pem -out encrypted.bin
<!-- decrypt -->
openssl pkeyutl -decrypt -inkey private_key.pem -in encrypted.bin -out decrypt.txt

<!-- encrypt (file) -->
openssl pkeyutl -encrypt -pubin -inkey public_key.pem -in pw.txt -out encrypted.txt
<!-- decrypt  -->
openssl pkeyutl -decrypt -inkey private_key.pem -in encrypted.txt -out decrypted.txt
