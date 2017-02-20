<?php
namespace Crypto;
use \Zend\Crypt\Key\Derivation\Scrypt;
use \Zend\Crypt\Key\Derivation\Pbkdf2;
use \Zend\Math\Rand;

/**
* Implantation of :
* - scrypt
* - hkdf
* - pbkdf2
* - generate DSA Key
*/
class Crypto{
	/**
	* Scrypt function, select the module or Scrypt Class from Zend
	* don't forget the namespace !
	* @param string password
	* @param string salt a random string
	* @param integer N : the CPU cost; (pow of 2)
	* @param integer r : the memory cost;
	* @param integer p : the parallelization cost
	* @param integer size
	*/
	function scrypt($pass, $salt,$N,$r,$p,$size){
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
		if (!extension_loaded("scrypt")){
			return bin2hex(Scrypt::calc($pass, $salt,$N,$r,$p,$size));	//tyhe function return in binary
		}
		else{
			return scrypt($pass, $salt,$N,$r,$p,$size);		//return in already in hex
		}
	}
	/**
	* pbkdf2 implementation
	*
	* @param string hash
	* @param string pass
	* @param string salt
	* @param integer interations
	* @param integer length
	*/
	function pbkdf2($hash, $pass=null, $salt=null, $iterations, $length)
	{
		if ($salt == null){
			$salt = Rand::getBytes(strlen($pass), true);
		}
		$key  = Pbkdf2::calc($hash, $pass, $salt, $iterations, $length);
		return $key;
	}

	/**
	* HKDF Experimental HKDF implementation for CodeIgniter's encryption class
	* @author https://gist.github.com/narfbg
	* @source https://gist.github.com/narfbg/8793435
	* @link	https://tools.ietf.org/rfc/rfc5869.txt
	* @param	$key	Input key
	* @param	$digest	A SHA-2 hashing algorithm
	* @param	$salt	Optional salt
	* @param	$length	Output length (defaults to the selected digest size)
	* @param	$info	Optional context/application-specific info
	* @return	string A pseudo-random key
	*/
	static function hkdf($key, $digest = 'sha512', $salt = NULL, $length = NULL, $info = '')
	{
		// toujours pareil, on met de l'hexa en entrée et ne sorti
		$key=hex2bin($key);
		$salt=hex2bin($salt);

		if ( ! in_array($digest, array('sha224', 'sha256', 'sha384', 'sha512'), TRUE)){
			return FALSE;
		}

		$digest_length = substr($digest, 3) / 8;
		if (empty($length) OR ! is_int($length)){
			$length = $digest_length;
		}
		elseif ($length > (255 * $digest_length)){
			return FALSE;
		}

		if (!isset($salt)){
			$salt = str_repeat("\0", substr($digest, 3) / 8);
		}

		$prk = hash_hmac($digest, $key, $salt, TRUE);
		$key = '';
		for ($key_block = '', $block_index = 1; strlen($key) < $length; ++$block_index){
			$key_block = hash_hmac($digest, $key_block.$info.chr($block_index), $prk, TRUE);
			$key .= $key_block;
		}

		return bin2hex(substr($key, 0, $length));
	}



	/**
	* Generate a new DSA Key with open_ssl() PHP Functions
	* @param string SSLREP : destination for private_key.pem & public_key.pem
	* @param boolean  force recreation of the keys
	* @param boolean store private_key_content.txt  & public_key_content.txt keys
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
				foreach ($details['dsa'] as $key => $val){
					$details['dsa'][$key] = mb_strtoupper(bin2hex($val));
				}
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
	/**
	* Unshift an associative array
	*
	* @param array the input array by adress
	* @param mixed key added
	* @param mixed value added
	* @return integer number of array elements
	*/
	static function array_unshift_assoc(&$arr, $key, $val)
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

}
?>
