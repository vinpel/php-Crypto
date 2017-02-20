<?php
use Crypto\Crypto;
use \Codeception\Util\Debug;
/**
* Test the sign / verifySign functionality
*/
class SignatureTest extends \Codeception\TestCase\Test
{
  /**
  * @var \UnitTester
  */
  protected $tester;

  /**
  * @inheritdoc
  */
  public function testValidSignMessage(){
    $dsa=new Crypto();
    $SSLRep='./tests/test-keys/';
    $dsa->generateNewDSAKey($SSLRep);
    $privKey=file_get_contents($SSLRep . 'private_key.pem');
    $pubKey=file_get_contents($SSLRep . 'public_key.pem');
    $message='bidon';
    //Sign a message
    $signature=$dsa->sign($privKey,$message);
    // Check the signed message
    $this->assertTrue($dsa->verifySign($pubKey,$message,$signature));
  }
  /**
  * @inheritdoc
  */
  public function testInvalidSignMessage(){
    $dsa=new Crypto();
    $SSLRep='./keys/';
    $dsa->generateNewDSAKey($SSLRep);
    $privKey=file_get_contents($SSLRep . 'private_key.pem');
    $pubKey=file_get_contents($SSLRep . 'public_key.pem');
    $message='bidon';
    //Sign a message
    $signature=$dsa->sign($privKey,$message.'--');
    // Check the signed message
    $this->assertFalse($dsa->verifySign($pubKey,$message,$signature));
  }
}
