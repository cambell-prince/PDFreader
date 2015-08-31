<?php
namespace PdfReader;
/**
 * PDFdecrypt.class.php does the hard work of decrypting streams
 *
 * PHP version 5.1
 *
 * @category  File_Formats
 * @package   File_PDFreader
 * @author    Cambell Prince <cambell.prince@gmail.com>
 * @copyright 2014 John M. Stokes
 * @license   http://www.opensource.org/licenses/bsd-license.html BSD Style License
 * @link      http://heartofthefyre.us/PDFreader/index.php
 */

/**
 * I include one class per file, so the file description is the class's description.
 *
 * @category  File_Formats
 * @package   File_PDFreader
 * @author    Cambell Prince <cambell.prince@gmail.com>
 * @copyright 2014 John M. Stokes
 * @license   http://www.opensource.org/licenses/bsd-license.html BSD Style License
 * @link      http://heartofthefyre.us/PDFreader/index.php
 */
class PdfDecrypter
{
	private $_filterDictionary;
	private $_id;

	private $_key;
	
	public function __construct($filterDictionary, $id) {
		$this->_filterDictionary = $filterDictionary;
		$this->_id = $id;

		$this->getKey();
	}
	
	public function getKey() {
		if ($this->_key) {
			return $this->_key;
		}
		$buffer  = "\x28\xBF\x4E\x5E\x4E\x75\x8A\x41\x64\x00\x4E\x56\xFF\xFA\x01\x08";
		$buffer .= "\x2E\x2E\x00\xB6\xD0\x68\x3E\x80\x2F\x0C\xA9\xFE\x64\x53\x69\x7A";
		
		$buffer .= $this->_filterDictionary['O'];
		
		$p = pack('l', $this->_filterDictionary['P']);
		$buffer .= $p;
		
// 		var_dump('P ', bin2hex($p));
		
		$buffer .= $this->_id[0];
		
		var_dump('buffer ', bin2hex($buffer));
		
		$hash = md5($buffer, true);
		
		$this->_key = substr($hash, 0, 5);
		
		var_dump('key ', bin2hex($hash), ' ', bin2hex($this->_key));
		
        var_dump(\mcrypt_module_self_test(MCRYPT_ARCFOUR));
		
		return $this->_key;
	}
	
	public function decrypt($objectNumber, $generationNumber, $rawString) {
		$key = $this->getKey();
		
		$on = pack('l', $objectNumber);
		$on = substr($on, 0, 3);
		
		$gn = pack('l', $generationNumber);
		$gn = substr($gn, 0, 2);
		
		$key = $key . $on . $gn;
		
		$key = md5($key, true);
		$key = substr($key, 0, 10);
		
 		$decryptedString = @mcrypt_decrypt(MCRYPT_ARCFOUR, $key, $rawString, MCRYPT_MODE_STREAM, 0);
		return $decryptedString;
	}
	
}


?>
