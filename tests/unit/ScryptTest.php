<?php

use Crypto\Crypto;
use \Codeception\Util\Debug;
/**
* Test vector for scrypt function
* https://tools.ietf.org/html/draft-josefsson-scrypt-kdf-00#section-11
*/
class ScryptTest extends \Codeception\TestCase\Test
{
  /**
  * @var \UnitTester
  */
  protected $tester;

  /**
  * @inheritdoc
  */
  public function testScryptVector1(){
    $result=Crypto::scrypt("","",16,1,1,64);
    $needed="77d6576238657b203b19ca42c18a0497".
    "f16b4844e3074ae8dfdffa3fede21442".
    "fcd0069ded0948f8326a753a0fc81f17".
    "e8d3e0fb2e0d3628cf35e20c38d18906";
    Debug::debug("\n".$result."\n".$needed);
    $this->assertTrue(strcmp($result,$needed)==0);
  }
  /**
  * @inheritdoc
  */
  public function testScryptVector2(){
    $result=Crypto::scrypt(bin2hex("password"),bin2hex("NaCl"),1024,8,16,64);
    $needed="fdbabe1c9d3472007856e7190d01e9fe".
    "7c6ad7cbc8237830e77376634b373162".
    "2eaf30d92e22a3886ff109279d9830da".
    "c727afb94a83ee6d8360cbdfa2cc0640";
    Debug::debug("\n".$result."\n".$needed);
    $this->assertTrue(strcmp($result,$needed)==0);
  }
  /**
  * @inheritdoc
  */
  public function testScryptVector3(){
    $result=Crypto::scrypt(bin2hex("pleaseletmein"),bin2hex("SodiumChloride"),16384,8,1,64);
    $needed="7023bdcb3afd7348461c06cd81fd38eb".
    "fda8fbba904f8e3ea9b543f6545da1f2".
    "d5432955613f0fcf62d49705242a9af9".
    "e61e85dc0d651e40dfcf017b45575887";
    Debug::debug("\n".$result."\n".$needed);
    $this->assertTrue(strcmp($result,$needed)==0);
  }
  /**
  * to heavy for normal tests
  */

  public function testScryptVector4(){
    if (extension_loaded("scrypt")){
      $result=Crypto::scrypt(bin2hex("pleaseletmein"),bin2hex("SodiumChloride"),1048576,8,1,64);
      $needed="2101cb9b6a511aaeaddbbe09cf70f881".
      "ec568d574a2ffd4dabe5ee9820adaa47".
      "8e56fd8f4ba5d09ffa1c6d927c40f4c3".
      "37304049e8a952fbcbf45c6fa77a41a4";
      Debug::debug("\n".$result."\n".$needed);
      $this->assertTrue(strcmp($result,$needed)==0);
    }
    else {
      Debug::debug("Skipped vector 4, need scrypt module");
    }
  }
}
