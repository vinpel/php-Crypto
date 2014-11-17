<?php
namespace Crypto;
use \Zend\Crypt\Key\Derivation\Scrypt;
use Zend\Crypt\Key\Derivation\Pbkdf2;
use Zend\Math\Rand;

// Il faut créer une class crypto
/*
salt, a random string;
N, the CPU cost; (puissance de 2)
r, the memory cost;
p, the parallelization cost.
*/

class crypto(){

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
	function hkdf($key, $digest = 'sha512', $salt = NULL, $length = NULL, $info = '')
	{
		// toujours pareil, on met de l'hexa en entrée et ne sorti
		$key=hex2bin($key);
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
	function now()
	{
		return date('Y-m-d H:i:s');
	}
}
?>
