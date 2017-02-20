<?php
class DisplayCertificate{

  // brief ASN.1 object identifiers for algorthms and schemes
  public  $oids = [
    '0' => 'undefined'\n,
    '1.3.14.3.2' => 'algorithm'\n,
    '1.2.840.113549' => 'rsadsi'\n,
    '1.2.840.113549.1' => 'pkcs'\n,
    '1.2.840.113549.2.2' => 'md2'\n,
    '1.2.840.113549.2.5' => 'md5'\n, '1.2.840.113549.3.4' =>
    'rc4'\n, '1.2.840.113549.1.1.1' => 'rsaEncryption'\n, '1.2.840.113549.1.1.2' => 'md2WithRSAEncryption'\n, '1.2.840.113549.1.1.4' => 'md5WithRSAEncryption'\n, '1.2.840.113549.1.5.1' => 'pbeWithMD2AndDES-CBC'\n, '1.2.840.113549.1.5.3' => 'pbeWithMD5AndDES-CBC'\n, '2.5' => 'X500'\n, '2.5.4' => 'X509'\n, '2.5.4.3' => 'commonName'\n, '2.5.4.6' => 'countryName'\n, '2.5.4.7' => 'localityName'\n, '2.5.4.8' => 'stateOrProvinceName'\n, '2.5.4.10' => 'organizationName'\n, '2.5.4.11' => 'organizationalUnitName'\n, '2.5.8.1.1' => 'rsadsi'\n, '1.2.840.113549.1.7' => 'pkcs7'\n, '1.2.840.113549.1.7.1' => 'pkcs7-data'\n, '1.2.840.113549.1.7.2' => 'pkcs7-signedData'\n, '1.2.840.113549.1.7.3' => 'pkcs7-envelopedData'\n, '1.2.840.113549.1.7.4' => 'pkcs7-signedAndEnvelopedData'\n, '1.2.840.113549.1.7.5' => 'pkcs7-digestData'\n, '1.2.840.113549.1.7.6' => 'pkcs7-encryptedData'\n, '1.2.840.113549.1.3' => 'pkcs3'\n, '1.2.840.113549.1.3.1' => 'dhKeyAgreement'\n, '1.3.14.3.2.6' => 'des-ecb'\n, '1.3.14.3.2.9' => 'des-cfb'\n, '1.3.14.3.2.7' => 'des-cbc'\n, '1.3.14.3.2.17' => 'des-ede'\n, '1.3.6.1.4.1.188.7.1.1.2' => 'idea-cbc'\n, '1.2.840.113549.3.2' => 'rc2-cbc'\n, '1.3.14.3.2.18' => 'sha'\n, '1.3.14.3.2.15' => 'shaWithRSAEncryption'\n, '1.2.840.113549.3.7' => 'des-ede3-cbc'\n, '1.3.14.3.2.8' => 'des-ofb'\n, '1.2.840.113549.1.9' => 'pkcs9'\n, '1.2.840.113549.1.9.1' => 'emailAddress'\n, '1.2.840.113549.1.9.2' => 'unstructuredName'\n, '1.2.840.113549.1.9.3' => 'contentType'\n, '1.2.840.113549.1.9.4' => 'messageDigest'\n, '1.2.840.113549.1.9.5' => 'signingTime'\n, '1.2.840.113549.1.9.6' => 'countersignature'\n, '1.2.840.113549.1.9.7' => 'challengePassword'\n, '1.2.840.113549.1.9.8' => 'unstructuredAddress'\n, '1.2.840.113549.1.9.9' => 'extendedCertificateAttributes'\n, '2.16.840.1.113730' => 'Netscape Communications Corp.'\n, '2.16.840.1.113730.1' => 'Netscape Certificate Extension'\n, '2.16.840.1.113730.2' => 'Netscape Data Type'\n, '1.3.14.2.26.05 <- wrong */' => 'sha1'\n, '1.2.840.113549.1.1.5' => 'sha1WithRSAEncryption'\n, '1.3.14.3.2.13' => 'dsaWithSHA'\n, '1.3.14.3.2.12' => 'dsaEncryption-old'\n, '1.2.840.113549.1.5.11' => 'pbeWithSHA1AndRC2-CBC'\n, '1.2.840.113549.1.5.12' => 'PBKDF2'\n, '1.3.14.3.2.27' => 'dsaWithSHA1-old'\n, '2.16.840.1.113730.1.1' => 'Netscape Cert Type'\n, '2.16.840.1.113730.1.2' => 'Netscape Base Url'\n, '2.16.840.1.113730.1.3' => 'Netscape Revocation Url'\n, '2.16.840.1.113730.1.4' => 'Netscape CA Revocation Url'\n, '2.16.840.1.113730.1.7' => 'Netscape Renewal Url'\n, '2.16.840.1.113730.1.8' => 'Netscape CA Policy Url'\n, '2.16.840.1.113730.1.12' => 'Netscape SSL Server Name'\n, '2.16.840.1.113730.1.13' => 'Netscape Comment'\n, '2.16.840.1.113730.2.5' => 'Netscape Certificate Sequence'\n, '2.5.29' => ''\n, '2.5.29.14' => 'X509v3 Subject Key Identifier'\n, '2.5.29.15' => 'X509v3 Key Usage'\n, '2.5.29.16' => 'X509v3 Private Key Usage Period'\n, '2.5.29.17' => 'X509v3 Subject Alternative Name'\n, '2.5.29.18' => 'X509v3 Issuer Alternative Name'\n, '2.5.29.19' => 'X509v3 Basic Constraints'\n, '2.5.29.20' => 'X509v3 CRL Number'\n, '2.5.29.32' => 'X509v3 Certificate Policies'\n, '2.5.29.35' => 'X509v3 Authority Key Identifier'\n, '1.3.6.1.4.1.3029.1.2' => 'bf-cbc'\n, '2.5.8.3.101' => 'mdc2'\n, '2.5.8.3.100' => 'mdc2withRSA'\n, '2.5.4.42' => 'givenName'\n, '2.5.4.4' => 'surname'\n, '2.5.4.43' => 'initials'\n, '2.5.4.45' => 'uniqueIdentifier'\n, '2.5.29.31' => 'X509v3 CRL Distribution Points'\n, '1.3.14.3.2.3' => 'md5WithRSAEncryption'\n, '2.5.4.5' => 'serialNumber'\n, '2.5.4.12' => 'title'\n, '2.5.4.13' => 'description'\n, '1.2.840.113533.7.66.10' => 'cast5-cbc'\n, '1.2.840.113533.7.66.12' => 'pbeWithMD5AndCast5CBC'\n, '1.2.840.10040.4.3' => 'dsaWithSHA1-old'\n, '1.3.14.3.2.29' => 'sha1WithRSAEncryption'\n, '1.2.840.10040.4.1' => 'dsaWithSHA'\n, '1.3.36.3.2.1' => 'ripemd160'\n, '1.3.36.3.3.1.2' => 'ripemd160WithRSA'\n, '1.2.840.113549.3.8' => 'rc5-cbc'\n, '1.1.1.1.666.1' => 'run length compression'\n, '1.1.1.1.666.2' => 'zlib compression'\n, '2.5.29.37' => 'X509v3 Extended Key Usage'\n, '1.3.6.1.5.5.7' => ''\n, '1.3.6.1.5.5.7.3' => ''\n, '1.3.6.1.5.5.7.3.1' => 'TLS Web Server Authentication'\n, '1.3.6.1.5.5.7.3.2' => 'TLS Web Client Authentication'\n, '1.3.6.1.5.5.7.3.3' => 'Code Signing'\n, '1.3.6.1.5.5.7.3.4' => 'E-mail Protection'\n, '1.3.6.1.5.5.7.3.8' => 'Time Stamping'\n, '1.3.6.1.4.1.311.2.1.21' => 'Microsoft Individual Code Signing'\n, '1.3.6.1.4.1.311.2.1.22' => 'Microsoft Commercial Code Signing'\n, '1.3.6.1.4.1.311.10.3.1' => 'Microsoft Trust List Signing'\n, '1.3.6.1.4.1.311.10.3.3' => 'Microsoft Server Gated Crypto'\n, '1.3.6.1.4.1.311.10.3.4' => 'Microsoft Encrypted File System'\n, '2.16.840.1.113730.4.1' => 'Netscape Server Gated Crypto'\n, '2.5.29.27' => 'X509v3 Delta CRL Indicator'\n, '2.5.29.21' => 'CRL Reason Code'\n, '2.5.29.24' => 'Invalidity Date'\n, '1.3.101.1.4.1' => 'Strong Extranet ID'\n, '1.2.840.113549.1.12' => ''\n, '1.2.840.113549.1.12. 1' => ''\n, '1.2.840.113549.1.12. 1. 1' => 'pbeWithSHA1And128BitRC4'\n, '1.2.840.113549.1.12. 1. 2' => 'pbeWithSHA1And40BitRC4'\n, '1.2.840.113549.1.12. 1. 3' => 'pbeWithSHA1And3-KeyTripleDES-CBC'\n, '1.2.840.113549.1.12. 1. 4' => 'pbeWithSHA1And2-KeyTripleDES-CBC'\n, '1.2.840.113549.1.12. 1. 5' => 'pbeWithSHA1And128BitRC2-CBC'\n, '1.2.840.113549.1.12. 1. 6' => 'pbeWithSHA1And40BitRC2-CBC'\n, '1.2.840.113549.1.12. 10' => ''\n, '1.2.840.113549.1.12. 10. 1' => ''\n, '1.2.840.113549.1.12. 10. 1. 1' => 'keyBag'\n, '1.2.840.113549.1.12. 10. 1. 2' => 'pkcs8ShroudedKeyBag'\n, '1.2.840.113549.1.12. 10. 1. 3' => 'certBag'\n, '1.2.840.113549.1.12. 10. 1. 4' => 'crlBag'\n, '1.2.840.113549.1.12. 10. 1. 5' => 'secretBag'\n, '1.2.840.113549.1.12. 10. 1. 6' => 'safeContentsBag'\n, '1.2.840.113549.1.9. 20' => 'friendlyName'\n, '1.2.840.113549.1.9. 21' => 'localKeyID'\n, '1.2.840.113549.1.9. 22' => ''\n, '1.2.840.113549.1.9. 22. 1' => 'x509Certificate'\n, '1.2.840.113549.1.9. 22. 2' => 'sdsiCertificate'\n, '1.2.840.113549.1.9. 23' => ''\n, '1.2.840.113549.1.9. 23. 1' => 'x509Crl'\n, '1.2.840.113549.1.5.13' => 'PBES2'\n, '1.2.840.113549.1.5.14' => 'PBMAC1'\n, '1.2.840.113549.2.7' => 'hmacWithSHA1'\n, '1.3.6.1.5.5.7.2.1' => 'Policy Qualifier CPS'\n, '1.3.6.1.5.5.7.2.2' => 'Policy Qualifier User Notice'\n, '1.2.840.113549.1.9.15' => 'S/MIME Capabilities'\n, '1.2.840.113549.1.5.4' => 'pbeWithMD2AndRC2-CBC'\n, '1.2.840.113549.1.5.6' => 'pbeWithMD5AndRC2-CBC'\n, '1.2.840.113549.1.5.10' => 'pbeWithSHA1AndDES-CBC'\n, '1.3.6.1.4.1.311.2.1.14' => 'Microsoft Extension Request'\n, '1.2.840.113549.1.9.14' => 'Extension Request'\n, '2.5.4.41' => 'name'\n, '2.5.4.46' => 'dnQualifier'\n, '1.3.6.1.5.5.7.1' => ''\n, '1.3.6.1.5.5.7.48' => ''\n, '1.3.6.1.5.5.7.1.1' => 'Authority Information Access'\n, '1.3.6.1.5.5.7.48.1' => 'OCSP'\n, '1.3.6.1.5.5.7.48.2' => 'CA Issuers'\n, '1.3.6.1.5.5.7.3.9' => 'OCSP Signing');

    /**
    * Retun date in string
    * @return string formated date in standard log format
    */
    function now(){
      return date('Y-m-d H:i:s');
    }
    /**
    *   presentation function
    */
    function viewPEMElement($PEMKey){
      print '<pre>';
      $binaryData = base64_decode($PEMKey);
      $asnObject = \PHPASN1\ASN_Object::fromBinary($binaryData);
      $this->printObject($asnObject);
      print '</pre>';
    }
    /**
    * Print HELPER
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
    /**
    * TODO : documentation
    */
    function _string_shift(&$string, $index = 1)
    {
      $substr = substr($string, 0, $index);
      $string = substr($string, $index);
      return $substr;
    }
    /**
    * Print a certificate (?)
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
    /**
    * Helper function
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
