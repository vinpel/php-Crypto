# PHP Crypto library

You will find the integration  of :

* scrypt (Zend Framework (http://framework.zend.com/))
* pbkdf2 (Zend Framework (http://framework.zend.com/))
* hdkf
* sign / check signature

This library is created for the [gaspSync](http://github.com/vinpel/gaspSync) projet


# unit Test

This library use the [codeception](http://www.codeception.com) tools.

I have implemented the common test vector.


```javascript
codecept run
```

What **will** fail for now :

* test scrypt vector 4
* test scrypt vector 5
* test scrypt vector6
* test scrypt vector7
* test scrypt vector4


# Sign / check signature

Function definition :
```javascript
public function sign($privateKeyPem,$data,$signature_alg=OPENSSL_ALGO_DSS1)
public function verifySign($publicKeyPem,$data,$signature,$signature_alg=OPENSSL_ALGO_DSS1){
```


# Expand function

- hkdf [Experimental HKDF implementation for CodeIgniter's encryption  ](https://gist.github.com/narfbg/8793435)  
```javascript
$hkdf = \Crypto\Crypto::HKDF($secretToken, $hashmode,null,$hashmod_digest_size,self::HKDF_INFO_SIGNING);
```
rfc5869 : [HKDF](https://tools.ietf.org/rfc/rfc5869.txt)

- [scrypt](http://fr.wikipedia.org/wiki/Scrypt) function
```javascript
$scrypt =  \Crypto\Crypto::myScrypt($password, $salt,64*1024, 8, 1, 32);
```
 * the function do a hex2bin() for the $password and $salt.
 * the function will use [DomBlack](https://github.com/DomBlack/php-scrypt) PHP module if available (don't forget to add it to command line for the tests)


- pbkdf2 function
```javascript
$crypto = new \Crypto\Crypto();
$key = $crypto->Pbkdf2($hash, $pass=null, $salt=null, $iterations, $length)
```

- Diverse function :
```javascript
  function hexdecKey($arrayKey){
  function bchexdec($hex)
  function bcdechex($number)
```

# Key  manipulation
- Creating private / public key DSA (can be used for the sign / verifySign function):
````
\CryptoCrypto::generateNewDSAKey('./keyDirectory');
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
## Copyright

When not explicitly set, files are placed under a [3 clause BSD license](http://www.opensource.org/licenses/BSD-3-Clause)
