<?php namespace Crypto;
use \Zend\Crypt\Key\Derivation\Scrypt;
use Zend\Crypt\Key\Derivation\Pbkdf2;
use Zend\Math\Rand;

use Codeception\Util\Debug;

// Il faut créer une class crypto
/*
salt, a random string;
N, the CPU cost; (puissance de 2)
r, the memory cost;
p, the parallelization cost.
*/

class Crypto{
	/*
	*
	*
	*/
	function myScrypt($pass, $salt,$N,$r,$p,$size){
		//we want same format, input & output will be in hex, but pass & salt need to bin in binary
		$pass=hex2bin($pass);
		$salt=hex2bin($salt);
		if ($N == 0 || ($N & ($N - 1)) != 0) {
			throw new \InvalidArgumentException("N must be > 0 and a power of 2");
		}

		if ($N > PHP_INT_MAX / 128 / $r) {
			throw new \InvalidArgumentException("Parameter N is too large");
		}

		if ($r > PHP_INT_MAX / 128 / $p) {
			throw new \InvalidArgumentException("Parameter r is too large");
		}
		if (!extension_loaded("scrypt"))
		return bin2hex(Scrypt::calc($pass, $salt,$N,$r,$p,$size));	//tyhe function return in binary
		else
		return scrypt($pass, $salt,$N,$r,$p,$size);		//return in already in hex
	}
	/**
	*
	*/
	function Pbkdf2($hash, $pass=null, $salt=null, $iterations, $length)
	{
		if ($salt ==null)
		$salt = Rand::getBytes(strlen($pass), true);
		$key  = Pbkdf2::calc($hash, $pass, $salt, $iterations, $length);
		return $key;
	}

	//https://gist.github.com/narfbg/8793435
	/**
	* HKDF
	*
	* @link	https://tools.ietf.org/rfc/rfc5869.txt
	* @param	$key	Input key
	* @param	$digest	A SHA-2 hashing algorithm
	* @param	$salt	Optional salt
	* @param	$length	Output length (defaults to the selected digest size)
	* @param	$info	Optional context/application-specific info
	* @return	string	A pseudo-random key
	*/
	static function hkdf($key, $digest = 'sha512', $salt = NULL, $length = NULL, $info = '')
	{
		// toujours pareil, on met de l'hexa en entrée et ne sorti
		$key=hex2bin($key);
		$salt=hex2bin($salt);

		if ( ! in_array($digest, array('sha224', 'sha256', 'sha384', 'sha512'), TRUE))
		{
			return FALSE;
		}

		$digest_length = substr($digest, 3) / 8;
		if (empty($length) OR ! is_int($length))
		{
			$length = $digest_length;
		}
		elseif ($length > (255 * $digest_length))
		{
			return FALSE;
		}

		isset($salt) OR $salt = str_repeat("\0", substr($digest, 3) / 8);

		$prk = hash_hmac($digest, $key, $salt, TRUE);
		$key = '';
		for ($key_block = '', $block_index = 1; strlen($key) < $length; ++$block_index)
		{
			$key_block = hash_hmac($digest, $key_block.$info.chr($block_index), $prk, TRUE);
			$key .= $key_block;
		}

		return bin2hex(substr($key, 0, $length));
	}
	/**
	*
	*/
	function now(){
		return date('Y-m-d H:i:s');
	}


	/*
	store public,private key in ./myApp/storage/SSL/
	may store key element for futher tests
	*/
	static public function generateNewDSAKey($SSLRep,$force=false,$storeKeyElement=true) {

		if (!is_dir($SSLRep)){
			@mkdir($SSLRep, 0777, true);
		}
		//we don't recreate key if one exist ( and no force arg)
		if ( !is_file($SSLRep . 'private_key.pem') || $force===true){
			//create new Key
			$SSLConfFile = substr(__DIR__, 0, strlen(__DIR__) - 7) . DIRECTORY_SEPARATOR .  'openssl.cnf';

			$configargs  = array(
				"config" => $SSLConfFile,
				"digest_alg" => "SHA1",
				"private_key_bits" => 2048,
				"private_key_type" => OPENSSL_KEYTYPE_DSA,
				"encrypt_key" => false
			);

			$new_key_pair = openssl_pkey_new($configargs);
			if ($new_key_pair == false) {
				echo "\n*** Errors After calling openssl_pkey_new\n";
				while (($e = openssl_error_string()) !== false) {
					var_dump($e);
				}
			}
			openssl_pkey_export($new_key_pair, $private_key_pem, null, $configargs);
			$details = openssl_pkey_get_details($new_key_pair);
			$public_key_pem = $details['key'];

			if ($storeKeyElement){
				foreach ($details['dsa'] as $key => $val)
				$details['dsa'][$key] = mb_strtoupper(bin2hex($val));
				$DSAKey = $details['dsa'];

				self::array_unshift_assoc($DSAKey,"algorithm","DS");

				$y=$DSAKey['pub_key'];
				$x=$DSAKey['priv_key'];
				$DSAKey['x']=$x;

				unset($DSAKey['pub_key']);
				unset($DSAKey['priv_key']);
				//private no y but x
				file_put_contents($SSLRep . 'private_key_content.txt', json_encode($DSAKey));
				//public no x, but y
				$DSAKey['y']=$y;unset($DSAKey['x']);
				file_put_contents($SSLRep . 'public_key_content.txt', json_encode($DSAKey));
			}
			//Store the keys
			file_put_contents($SSLRep . 'private_key.pem', $private_key_pem);
			file_put_contents($SSLRep . 'public_key.pem', $public_key_pem);
		}
	}

	function array_unshift_assoc(&$arr, $key, $val)
	{
		$arr = array_reverse($arr, true);
		$arr[$key] = $val;
		$arr = array_reverse($arr, true);
		return count($arr);
	}
	/*        $der = $this->PemToDer($public_key_pem);
	//$this->Der2Array($der);

	$p=$DSAKey->p;

	*/

	/*
	passe tout les champs d'une representation HEXA a DECIMAL (necessite bcmath)
	*/
	function hexdecKey($arrayKey){
		if (is_object($arrayKey)){
			foreach ($arrayKey as $key=>$val){
				$arrayKey->{$key}=$this->bchexdec($val);
			}
		}
		else
		foreach ($arrayKey as $key=>$val){
			$arrayKey[$key]=$this->bchexdec($val);
		}
		return $arrayKey;
	}
	/*
	*
	*/
	function bchexdec($hex)
	{
		$len = strlen($hex);
		$dec='';
		for ($i = 1; $i <= $len; $i++)
		$dec = bcadd($dec, bcmul(strval(hexdec($hex[$i - 1])), bcpow('16', strval($len - $i))));

		return $dec;
	}

	function bcdechex($number)
	{
		$hexvalues = array('0','1','2','3','4','5','6','7',
		'8','9','A','B','C','D','E','F');
		$hexval = '';
		while($number != '0')
		{
			$hexval = $hexvalues[bcmod($number,'16')].$hexval;
			$number = bcdiv($number,'16',0);
		}
		return $hexval;
	}




	function addPublicHeaderFooter($Key){
		return "-----BEGIN PUBLIC KEY-----\n".$Key."-----END PUBLIC KEY-----";
	}
	function removeHeaderFooter($pemKey){
		print $pemKey;
		//Split lines:
		$lines = explode("\n", trim($pemKey));
		//Remove last and first line:
		unset($lines[count($lines) - 1]);
		unset($lines[0]);
		//Join remaining lines:
		$result = implode("\n", $lines);
		return chunk_split(str_replace("\n",'',$result),64,"\n");
	}
	/*
	*
	*/
	function PemToDer($Pem) {
		$result=$this->removeHeadFoot($Pem);
		return base64_decode($result);
	}
	/*
	*
	*/
	public function DerToKey($der) {
		include_once('File/ASN1.php');
		$ASN1   = new \File_ASN1();
		$result = $ASN1->decodeBER($der);
		$this->make_printable($result[0]);
	}
	/*
	* We generate a key for DSA without Header
	* @deprecated
	*/
	public function KeyToDsaPem($key){
		return false;
		$int1= new \PHPASN1\ASN_Integer($key->p);
		$int2= new \PHPASN1\ASN_Integer($key->q);
		$int3= new \PHPASN1\ASN_Integer($key->g);
		if (!isset($key->pub_key) && isset($key->y)){
			$key->pub_key=$key->y;
			unset($key->y);
		}
		var_dump($key);
		//A trouver 02820100 ...
		$BIT_STRING=new \PHPASN1\ASN_BitString('02820100'.$this->bcdechex($key->pub_key)) ;

		$objectIdentifier1 = new \PHPASN1\ASN_ObjectIdentifier('1.2.840.10040.4.1');//dsa
		$sequence = new \PHPASN1\ASN_Sequence($int1,$int2,$int3);
		$sequence_ident=new \PHPASN1\ASN_Sequence($objectIdentifier1,$sequence);
		$sequence_bit=new \PHPASN1\ASN_Sequence($sequence_ident,$BIT_STRING);
		$final = $sequence_bit->getBinary();
		$calculatedPEM=chunk_split(base64_encode($final),64,"\n");
		return $calculatedPEM;
	}
	/*
	*   Sign data with the public Key
	*/
	public function sign($privateKeyPem,$data,$signature_alg=OPENSSL_ALGO_DSS1) {
		openssl_sign($data, $signature, $privateKeyPem, $signature_alg);
		return $signature;

	}
	/*
	*
	*/
	public function verifySign($publicKeyPem,$data,$signature,$signature_alg=OPENSSL_ALGO_DSS1){
		$ok = openssl_verify($data, $signature, $publicKeyPem, $signature_alg);
		if ($ok == 1) {
			return true;
		} elseif ($ok == 0) {
			return false;
		} else {
			echo "ugly, error checking signature";
			while (($e = openssl_error_string()) !== false) {
				var_dump($e);
				return $false;
			}

		}
	}
	/*
	*   presentation function
	*/
	function viewPEMElement($PEMKey){
		print '<pre>';
		$binaryData = base64_decode($PEMKey);
		$asnObject = \PHPASN1\ASN_Object::fromBinary($binaryData);
		$this->printObject($asnObject);
		print '</pre>';
	}
	/*
	*
	*/
	function printObject(\PHPASN1\ASN_Object $object, $depth=0) {
		$treeSymbol = '';
		$depthString = str_repeat('━', $depth);
		if($depth > 0) {
			$treeSymbol = '┣';
		}

		$name = strtoupper(\PHPASN1\Identifier::getShortName($object->getType()));
		echo "{$treeSymbol}{$depthString}<b>{$name}</b> : ";

		echo $object->__toString() . '<br/>';

		$content = $object->getContent();
		if(is_array($content)) {
			foreach ($object as $child) {
				$this->printObject($child, $depth+1);
			}
		}
	}
	/*
	*
	*/
	function _string_shift(&$string, $index = 1)
	{
		$substr = substr($string, 0, $index);
		$string = substr($string, $index);
		return $substr;
	}


	public $oids = array('0' => 'undefined', '1.3.14.3.2' => 'algorithm', '1.2.840.113549' => 'rsadsi', '1.2.840.113549.1' => 'pkcs', '1.2.840.113549.2.2' => 'md2', '1.2.840.113549.2.5' => 'md5', '1.2.840.113549.3.4' => 'rc4', '1.2.840.113549.1.1.1' => 'rsaEncryption', '1.2.840.113549.1.1.2' => 'md2WithRSAEncryption', '1.2.840.113549.1.1.4' => 'md5WithRSAEncryption', '1.2.840.113549.1.5.1' => 'pbeWithMD2AndDES-CBC', '1.2.840.113549.1.5.3' => 'pbeWithMD5AndDES-CBC', '2.5' => 'X500', '2.5.4' => 'X509', '2.5.4.3' => 'commonName', '2.5.4.6' => 'countryName', '2.5.4.7' => 'localityName', '2.5.4.8' => 'stateOrProvinceName', '2.5.4.10' => 'organizationName', '2.5.4.11' => 'organizationalUnitName', '2.5.8.1.1' => 'rsadsi', '1.2.840.113549.1.7' => 'pkcs7', '1.2.840.113549.1.7.1' => 'pkcs7-data', '1.2.840.113549.1.7.2' => 'pkcs7-signedData', '1.2.840.113549.1.7.3' => 'pkcs7-envelopedData', '1.2.840.113549.1.7.4' => 'pkcs7-signedAndEnvelopedData', '1.2.840.113549.1.7.5' => 'pkcs7-digestData', '1.2.840.113549.1.7.6' => 'pkcs7-encryptedData', '1.2.840.113549.1.3' => 'pkcs3', '1.2.840.113549.1.3.1' => 'dhKeyAgreement', '1.3.14.3.2.6' => 'des-ecb', '1.3.14.3.2.9' => 'des-cfb', '1.3.14.3.2.7' => 'des-cbc', '1.3.14.3.2.17' => 'des-ede', '1.3.6.1.4.1.188.7.1.1.2' => 'idea-cbc', '1.2.840.113549.3.2' => 'rc2-cbc', '1.3.14.3.2.18' => 'sha', '1.3.14.3.2.15' => 'shaWithRSAEncryption', '1.2.840.113549.3.7' => 'des-ede3-cbc', '1.3.14.3.2.8' => 'des-ofb', '1.2.840.113549.1.9' => 'pkcs9', '1.2.840.113549.1.9.1' => 'emailAddress', '1.2.840.113549.1.9.2' => 'unstructuredName', '1.2.840.113549.1.9.3' => 'contentType', '1.2.840.113549.1.9.4' => 'messageDigest', '1.2.840.113549.1.9.5' => 'signingTime', '1.2.840.113549.1.9.6' => 'countersignature', '1.2.840.113549.1.9.7' => 'challengePassword', '1.2.840.113549.1.9.8' => 'unstructuredAddress', '1.2.840.113549.1.9.9' => 'extendedCertificateAttributes', '2.16.840.1.113730' => 'Netscape Communications Corp.', '2.16.840.1.113730.1' => 'Netscape Certificate Extension', '2.16.840.1.113730.2' => 'Netscape Data Type', '1.3.14.2.26.05 <- wrong */' => 'sha1', '1.2.840.113549.1.1.5' => 'sha1WithRSAEncryption', '1.3.14.3.2.13' => 'dsaWithSHA', '1.3.14.3.2.12' => 'dsaEncryption-old', '1.2.840.113549.1.5.11' => 'pbeWithSHA1AndRC2-CBC', '1.2.840.113549.1.5.12' => 'PBKDF2', '1.3.14.3.2.27' => 'dsaWithSHA1-old', '2.16.840.1.113730.1.1' => 'Netscape Cert Type', '2.16.840.1.113730.1.2' => 'Netscape Base Url', '2.16.840.1.113730.1.3' => 'Netscape Revocation Url', '2.16.840.1.113730.1.4' => 'Netscape CA Revocation Url', '2.16.840.1.113730.1.7' => 'Netscape Renewal Url', '2.16.840.1.113730.1.8' => 'Netscape CA Policy Url', '2.16.840.1.113730.1.12' => 'Netscape SSL Server Name', '2.16.840.1.113730.1.13' => 'Netscape Comment', '2.16.840.1.113730.2.5' => 'Netscape Certificate Sequence', '2.5.29' => '', '2.5.29.14' => 'X509v3 Subject Key Identifier', '2.5.29.15' => 'X509v3 Key Usage', '2.5.29.16' => 'X509v3 Private Key Usage Period', '2.5.29.17' => 'X509v3 Subject Alternative Name', '2.5.29.18' => 'X509v3 Issuer Alternative Name', '2.5.29.19' => 'X509v3 Basic Constraints', '2.5.29.20' => 'X509v3 CRL Number', '2.5.29.32' => 'X509v3 Certificate Policies', '2.5.29.35' => 'X509v3 Authority Key Identifier', '1.3.6.1.4.1.3029.1.2' => 'bf-cbc', '2.5.8.3.101' => 'mdc2', '2.5.8.3.100' => 'mdc2withRSA', '2.5.4.42' => 'givenName', '2.5.4.4' => 'surname', '2.5.4.43' => 'initials', '2.5.4.45' => 'uniqueIdentifier', '2.5.29.31' => 'X509v3 CRL Distribution Points', '1.3.14.3.2.3' => 'md5WithRSAEncryption', '2.5.4.5' => 'serialNumber', '2.5.4.12' => 'title', '2.5.4.13' => 'description', '1.2.840.113533.7.66.10' => 'cast5-cbc', '1.2.840.113533.7.66.12' => 'pbeWithMD5AndCast5CBC', '1.2.840.10040.4.3' => 'dsaWithSHA1-old', '1.3.14.3.2.29' => 'sha1WithRSAEncryption', '1.2.840.10040.4.1' => 'dsaWithSHA', '1.3.36.3.2.1' => 'ripemd160', '1.3.36.3.3.1.2' => 'ripemd160WithRSA', '1.2.840.113549.3.8' => 'rc5-cbc', '1.1.1.1.666.1' => 'run length compression', '1.1.1.1.666.2' => 'zlib compression', '2.5.29.37' => 'X509v3 Extended Key Usage', '1.3.6.1.5.5.7' => '', '1.3.6.1.5.5.7.3' => '', '1.3.6.1.5.5.7.3.1' => 'TLS Web Server Authentication', '1.3.6.1.5.5.7.3.2' => 'TLS Web Client Authentication', '1.3.6.1.5.5.7.3.3' => 'Code Signing', '1.3.6.1.5.5.7.3.4' => 'E-mail Protection', '1.3.6.1.5.5.7.3.8' => 'Time Stamping', '1.3.6.1.4.1.311.2.1.21' => 'Microsoft Individual Code Signing', '1.3.6.1.4.1.311.2.1.22' => 'Microsoft Commercial Code Signing', '1.3.6.1.4.1.311.10.3.1' => 'Microsoft Trust List Signing', '1.3.6.1.4.1.311.10.3.3' => 'Microsoft Server Gated Crypto', '1.3.6.1.4.1.311.10.3.4' => 'Microsoft Encrypted File System', '2.16.840.1.113730.4.1' => 'Netscape Server Gated Crypto', '2.5.29.27' => 'X509v3 Delta CRL Indicator', '2.5.29.21' => 'CRL Reason Code', '2.5.29.24' => 'Invalidity Date', '1.3.101.1.4.1' => 'Strong Extranet ID', '1.2.840.113549.1.12' => '', '1.2.840.113549.1.12. 1' => '', '1.2.840.113549.1.12. 1. 1' => 'pbeWithSHA1And128BitRC4', '1.2.840.113549.1.12. 1. 2' => 'pbeWithSHA1And40BitRC4', '1.2.840.113549.1.12. 1. 3' => 'pbeWithSHA1And3-KeyTripleDES-CBC', '1.2.840.113549.1.12. 1. 4' => 'pbeWithSHA1And2-KeyTripleDES-CBC', '1.2.840.113549.1.12. 1. 5' => 'pbeWithSHA1And128BitRC2-CBC', '1.2.840.113549.1.12. 1. 6' => 'pbeWithSHA1And40BitRC2-CBC', '1.2.840.113549.1.12. 10' => '', '1.2.840.113549.1.12. 10. 1' => '', '1.2.840.113549.1.12. 10. 1. 1' => 'keyBag', '1.2.840.113549.1.12. 10. 1. 2' => 'pkcs8ShroudedKeyBag', '1.2.840.113549.1.12. 10. 1. 3' => 'certBag', '1.2.840.113549.1.12. 10. 1. 4' => 'crlBag', '1.2.840.113549.1.12. 10. 1. 5' => 'secretBag', '1.2.840.113549.1.12. 10. 1. 6' => 'safeContentsBag', '1.2.840.113549.1.9. 20' => 'friendlyName', '1.2.840.113549.1.9. 21' => 'localKeyID', '1.2.840.113549.1.9. 22' => '', '1.2.840.113549.1.9. 22. 1' => 'x509Certificate', '1.2.840.113549.1.9. 22. 2' => 'sdsiCertificate', '1.2.840.113549.1.9. 23' => '', '1.2.840.113549.1.9. 23. 1' => 'x509Crl', '1.2.840.113549.1.5.13' => 'PBES2', '1.2.840.113549.1.5.14' => 'PBMAC1', '1.2.840.113549.2.7' => 'hmacWithSHA1', '1.3.6.1.5.5.7.2.1' => 'Policy Qualifier CPS', '1.3.6.1.5.5.7.2.2' => 'Policy Qualifier User Notice', '1.2.840.113549.1.9.15' => 'S/MIME Capabilities', '1.2.840.113549.1.5.4' => 'pbeWithMD2AndRC2-CBC', '1.2.840.113549.1.5.6' => 'pbeWithMD5AndRC2-CBC', '1.2.840.113549.1.5.10' => 'pbeWithSHA1AndDES-CBC', '1.3.6.1.4.1.311.2.1.14' => 'Microsoft Extension Request', '1.2.840.113549.1.9.14' => 'Extension Request', '2.5.4.41' => 'name', '2.5.4.46' => 'dnQualifier', '1.3.6.1.5.5.7.1' => '', '1.3.6.1.5.5.7.48' => '', '1.3.6.1.5.5.7.1.1' => 'Authority Information Access', '1.3.6.1.5.5.7.48.1' => 'OCSP', '1.3.6.1.5.5.7.48.2' => 'CA Issuers', '1.3.6.1.5.5.7.3.9' => 'OCSP Signing');
	/*
	*
	*/
	function make_printable($result, $i = 0) {
		global $str;

		$length = $result['length'] - $result['headerlength'];
		if (isset($result['constant'])) {
			$constructed = is_array($result['content'][0]);
			$this->print_line($result['start'], $i, $length, $result['headerlength'], $constructed, 'cont [ ' . $result['constant'] . ' ]');
			if ($constructed) {
				$this->make_printable($result['content'][0], $i + 1);
			}
			return;
		}

		switch ($result['type']) {
			case FILE_ASN1_TYPE_SEQUENCE:
			case FILE_ASN1_TYPE_SET:
			$type = $result['type'] == FILE_ASN1_TYPE_SEQUENCE ? 'SEQUENCE' : 'SET';
			$this->print_line($result['start'], $i, $length, $result['headerlength'], true, $type);
			for ($j = 0; $j < count($result['content']); $j++) {
				$this->make_printable($result['content'][$j], $i + 1);
			}
			break;
			case FILE_ASN1_TYPE_INTEGER:
			$value = $result['content']->toHex();
			if (empty($value)) {
				$value = '00';
			}
			$this->print_line($result['start'], $i, $length, $result['headerlength'], false, 'INTEGER', strtoupper($value));
			break;
			case FILE_ASN1_TYPE_OBJECT_IDENTIFIER:
			$this->print_line($result['start'], $i, $length, $result['headerlength'], false, 'OBJECT', strtr($result['content'], $this->oids));
			break;
			case FILE_ASN1_TYPE_BIT_STRING:
			$this->print_line($result['start'], $i, $length, $result['headerlength'], false, 'BIT STRING');
			break;
			case FILE_ASN1_TYPE_BOOLEAN:
			$this->print_line($result['start'], $i, $length, $result['headerlength'], false, 'BOOLEAN', ord(substr($str, $result['start'] + $result['headerlength'], $result['length'] - $result['headerlength'])));
			break;
			case FILE_ASN1_TYPE_OCTET_STRING:
			$this->print_line($result['start'], $i, $length, $result['headerlength'], false, 'OCTET STRING');
			break;
			case FILE_ASN1_TYPE_NULL:
			$this->print_line($result['start'], $i, $length, $result['headerlength'], false, 'NULL');
			break;
			case FILE_ASN1_TYPE_NUMERIC_STRING:
			$type = 'NUMERICSTRING';
			case FILE_ASN1_TYPE_PRINTABLE_STRING:
			if (!isset($type)) {
				$type = 'PRINTABLESTRING';
			}
			case FILE_ASN1_TYPE_TELETEX_STRING:
			if (!isset($type)) {
				$type = 'T61STRING';
			}
			case FILE_ASN1_TYPE_VIDEOTEX_STRING:
			if (!isset($type)) {
				$type = 'VIDEOTEXSTRING';
			}
			case FILE_ASN1_TYPE_VISIBLE_STRING:
			if (!isset($type)) {
				$type = 'VISIBLESTRING';
			}
			case FILE_ASN1_TYPE_IA5_STRING:
			if (!isset($type)) {
				$type = 'IA5STRING';
			}
			case FILE_ASN1_TYPE_GRAPHIC_STRING:
			if (!isset($type)) {
				$type = 'GRAPHICSTRING';
			}
			case FILE_ASN1_TYPE_GENERAL_STRING:
			if (!isset($type)) {
				$type = 'GENERALSTRING';
			}
			case FILE_ASN1_TYPE_UTF8_STRING:
			if (!isset($type)) {
				$type = 'UTF8STRING';
			}
			case FILE_ASN1_TYPE_BMP_STRING:
			if (!isset($type)) {
				$type = 'BMPSTRING';
			}
			print_line($result['start'], $i, $length, $result['headerlength'], false, $type, $result['content']);
			break;
			case FILE_ASN1_TYPE_GENERALIZED_TIME:
			case FILE_ASN1_TYPE_UTC_TIME:
			$type = $result['type'] == FILE_ASN1_TYPE_GENERALIZED_TIME ? 'GENERALIZEDTIME' : 'UTCTIME';
			print_line($result['start'], $i, $length, $result['headerlength'], false, $type, substr($str, $result['start'] + $result['headerlength'], $result['length'] - $result['headerlength']));
		}
	}
	/*
	*
	*/
	function print_line($start, $depth, $length, $headerlength, $constructed, $type, $extra = false) {
		echo str_pad($start, 5, ' ', STR_PAD_LEFT) . ':';
		echo 'd=' . str_pad($depth, 3);
		echo 'hl=' . str_pad($headerlength, 2);
		echo 'l=' . str_pad($length, 4, ' ', STR_PAD_LEFT) . ' ';
		echo ($constructed ? 'cons' : 'prim') . ': ';
		echo str_repeat(' ', $depth) . $type;
		if ($extra !== false) {
			echo str_repeat(' ', 18 - strlen($type)) . ':' . $extra;
		}
		echo "\r\n";
	}
}
?>
