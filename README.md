# SCU Applied Cryptography Experiments

## DES

### Content

1. The four operation modes ECB, CBC, CFB, and OFB are implemented separately for DES, and each operation mode has a corresponding set of test data to check the correctness of the program. The CFB operation mode is an 8-bit CFB operation mode, and the OFB operation mode is an 8-bit OFB operation mode.

2. It is required to specify the location and name of the plaintext file, the key file, the initialization vector file, the operation mode of encryption, and the location and name of the ciphertext file after encryption is completed. When encrypting, the information is first read from the specified plaintext file, key file and initialization vector file, and then encrypted according to the specified operation mode, and finally the ciphertext (in hexadecimal) is written to the specified ciphertext file.

3. To test the encryption and decryption speed of each operation mode separately, 5MB of random test data are generated in the program (random number generator is not required), encrypted and decrypted 20 times continuously, and the total time (milliseconds) and speed (MByte/sec) of encryption and decryption of each mode are recorded and reported.

### Format

```
e1des -p plainfile -k keyfile [-v vifile] -m mode -c cipherfile
-p plainfile  //Specify the location and name of the plaintext file
-k keyfile  //Specify the location and name of the key file
-v vifile //Specify the location and name of the initialization vector file
-m mode //Specify the mode of operation for encryption
-c cipherfile //Specify the location and name of the cipher file.
```

### Test Data
```
plaintext : 4E6574776F726B205365637572697479	-128bit
key : 57696C6C69616D53	-64bit
vi : 5072656E74696365 -64bit
cipher:
	ECB : 958920B1358EF1972B9EE4548DC08E8A
	CBC : 5EB15B91506B9AE7CEB65954AE115E03
	CFB : F70F01584ACF4D966ADC143EB240C962
	OFB : F7B0FFCDC0B9BBA76092B929D769417A
```

## AES
### Content
Only AES with a block length of 128 bits and a key length of 128 bits is required to implement the four modes of operation ECB, CBC, CFB, and OFB, respectively. Each operation mode has a corresponding set of test data to check the correctness of the program. The CFB operation mode is the 32-bit CFB operation mode, and the OFB operation mode is the 32-bit OFB operation mode.

### Format
```
e2aes -p plainfile -k keyfile [-v vifile] -m mode -c cipherfile
-p plainfile  //Specify the location and name of the plaintext file
-k keyfile  //Specify the location and name of the key file
-v vifile //Specify the location and name of the initialization vector file
-m mode //Specify the mode of operation for encryption
-c cipherfile //Specify the location and name of the cipher file.
```

### Test Data
```
plaintext : 7970746F6437277B536563757269747926170687920616E64204E6574776F726 -256bit
key : 69616D537461657696C6CC6C696E6773 -128bit
iv : 5072656E7469636548616C6C496E632E -128bit
cipher : (Not given in document. Here are my encrypted results.)
	ECB : 6B7C0FDF69703706F4364C4904FF3028488F8516865DDD294024474064B0C101
	CBC : 962BDC16A0BFD257D3340D1DBAFA0E195C967BCB51DDCBDF127A529FE8403BC5
	OFB : A7FADD309641CBDD2703C4A47229F0965F7A01A40D2F16CE3BD904E2CAE469B9
	CFB : A7FADD30DA499DFD06A14C8DBD4369CFFB99C68A9741FE32796B7849BABA007C
```

## RSA
### Content
1. Requires implementation of RSA key generation, data encryption, and digital signatures.
2. The key generation consists of generating two large prime numbers `p,q`, computing n=p×q and `φ(n)=(p-1)(q-1)`, then choosing an integer` e` that is mutually prime with `φ(n)` and less than `φ(n)`, computing `d=e(-1) mod φ(n)`, and finally obtaining the public key `{e, n}` and the private key `{d, n}`. The generated integers `p, q, n, e` and `d` are written to the files p.txt, q.txt, n.txt, e.txt, and d.txt respectively. Note that all integers must be displayed in hexadecimal notation.

### Format
```
e3rsa -p plainfile -n nfile [-e efile] [-d dfile] -c cipherfile
-p plainfile  //Specify the location and name of the plaintext file
-n nfile //Specify the location and name of the file that holds the integer n
-e efile //Specify the location and name of the file that holds the integer e when data encryption
-d dfile //Specify the location and name of the file that holds the integer n when digital signature
-c cipherfile //Specify the location and name of the cipher file.
```

### Test Data
```
plaintext : 63727970746F677261706879
publickey : 
	n : 73299B42DBD959CDB3FB176BD1
	e : 10001
privatekey : 
	n : 73299B42DBD959CDB3FB176BD1
	d : 63C3264A0BF3A4FC0FF0940935
cipher : 
	encryption : 6326DC198AAE1DB64FDC32D440
	signature : CA653B30EED2C6B77DCB8381F
```

## IntegratedPractice
......