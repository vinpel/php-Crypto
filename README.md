# PHP Crypto library

Just a group of function crypto implementations



#Sign / Verify
- Verifing a singature

```javascript
//Sign a message
$signature=$dsa->sign($privKey,$message);
// Check the signed message
$res=$dsa->verifySign($pubKey,$message,$signature);

if ($res==true){
  print "message is signed & verified !";
}
else{
  print "Wrong signature";
}
```
Function definition :
```javascript
public function sign($privateKeyPem,$data,$signature_alg=OPENSSL_ALGO_DSS1)
public function verifySign($publicKeyPem,$data,$signature,$signature_alg=OPENSSL_ALGO_DSS1){
```


# Expand function

- Modified [Experimental HKDF implementation for CodeIgniter's encryption  ](https://gist.github.com/narfbg/8793435) rfc5869 : [HKDF](https://tools.ietf.org/rfc/rfc5869.txt) class function :
```javascript
\Crypto\Crypto::HKDF($secretToken, $hashmode,null,$hashmod_digest_size,self::HKDF_INFO_SIGNING);
```
- [scrypt](http://fr.wikipedia.org/wiki/Scrypt) function, will use [DomBlack](https://github.com/DomBlack/php-scrypt) module if available :
```javascript
return Crypto::myScrypt($AuthPW, $salt,64*1024, 8, 1, 32);
```
- Pbkdf2 function
```javascript
Pbkdf2($hash, $pass=null, $salt=null, $iterations, $length)
```
- Diverse function :
```javascript
  function hexdecKey($arrayKey){
  function bchexdec($hex)
  function bcdechex($number)
```

# Key  manipulation
- Creating a DSA key :

````
use Crypto\Crypto;
Crypto::generateNewDSAKey('./keyDirectory');
````

```javascript
  function addPublicHeaderFooter($Key)
  function removeHeaderFooter($pemKey)
  function PemToDer($Pem)
  function DerToKey($der)
  function viewPEMElement($PEMKey)
  function make_printable($result, $i = 0)
  function print_line($start, $depth, $length, $headerlength, $constructed, $type, $extra = false)
```
