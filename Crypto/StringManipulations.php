<?php namespace Crypto;
use \Zend\Crypt\Key\Derivation\Scrypt;
use \Zend\Crypt\Key\Derivation\Pbkdf2;
use \Zend\Math\Rand;


// Il faut créer une class crypto
/*
salt, a random string;
N, the CPU cost; (puissance de 2)
r, the memory cost;
p, the parallelization cost.
*/

class StringManipulations{

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

	/**
	* Hexa => decimal for an array
	* You need the bcmath extension
	* @param array to be converted
	* @return array result of the conversion
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
	/**
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

}
?>
