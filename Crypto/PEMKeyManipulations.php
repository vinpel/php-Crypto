<?php namespace Crypto;
use \Zend\Crypt\Key\Derivation\Scrypt;
use \Zend\Crypt\Key\Derivation\Pbkdf2;
use \Zend\Math\Rand;


/**
* Manipulation of key, no generation
* Sign & verify sign
* salt, a random string;
* N, the CPU cost; (puissance de 2)
* r, the memory cost;
* p, the parallelization cost.
*/
class PEMKeyManipulations{

	/**
	* Add header/footer for an armored Key
	*
	* @param string hex encoded Key
	* @return string PEM key
	*/
	function addPublicHeaderFooter($Key){
		return "-----BEGIN PUBLIC KEY-----\n".$Key."-----END PUBLIC KEY-----";
	}
	/**
	* Remove header/footer for a PEM Key
	*
	* @param string PEM key
	* @return string of hex encoded key
	*/
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
	/**
	* Transform a PEM Key to DER format
	* @param string PEM key
	* @return string DER Key
	*/
	function PemToDer($Pem) {
		$result=$this->removeHeadFoot($Pem);
		return base64_decode($result);
	}
	/**
	* Transform a Der Key to PEM format
	* FIXME : utiliser proprement phpseclib !!
	* @param string DER Key
	* @return string PEM key
	*/
	public function DerToKey($der) {
		include_once('File/ASN1.php');
		$ASN1   = new \File_ASN1();
		$result = $ASN1->decodeBER($der);
		$this->make_printable($result[0]);
	}
	/**
	* We generate a key for DSA without Header
	* https://github.com/FGrosse/PHPASN1
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
	/**
	*  Sign data with the public Key
	* with open_ssl functions
	*/
	public function sign($privateKeyPem,$data,$signature_alg=OPENSSL_ALGO_DSS1) {
		openssl_sign($data,
	}
	/**
	* Verifiy signed data
	* with open_ssl functions
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
}
?>
