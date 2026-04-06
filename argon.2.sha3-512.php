<?php 
error_reporting(E_ALL);

//		argon.2.sha3-512
//		argon2 sha3-512 comparison method
//		author 				: 	KO81 aka Christian Feilert
//		date last modified 	:	6/04-2026

define('argon2_sha3_512','VERSION: 2.3.3.a');
define('tagLength_ARRAY',[64,128,192,256]);
if(!defined('enc_ALGO'))define('enc_ALGO','id-aes256-GCM');
if(!defined('fast_ALGO'))define('fast_ALGO','xxh3');
if(!defined('boundary_sha3_512'))define('boundary_sha3_512','whirlpool');

class ARGON2_SHA3_512{
	private $txt_a='',$txt_b='';
	function __construct(string $str,string|NULL $known_secret=null,int $hardness=0,int $rotations=399999,int $tagLength=256){
		$this->str_a=strlen($str)?$str:'';
		$this->str_b=strval($known_secret==null?'':$known_secret);
		$this->replace='$argon2';
		$this->hardness=defined('override_hardness_ARGON2_SHA3_512')?override_hardness_ARGON2_SHA3_512:$hardness;
		$this->rotations=defined('override_rotations_ARGON2_SHA3_512')?override_rotations_ARGON2_SHA3_512:$rotations;
		$this->tagLength=defined('override_tagLength_ARGON2_SHA3_512')?override_tagLength_ARGON2_SHA3_512:$tagLength;
		$this->valid=$this->IsValid();
	}public function ThrowError(string $str){
		if(!strlen($str))$str='Unknown Error occured';
		throw new Exception('[ARGON2_SHA3_512] Exception : '.\n.\t.$str.'.'.\n);
	}private function IsValid(){
		$test_a=is_numeric($this->hardness);
		$test_b=is_numeric($this->rotations);
		$test_c=is_numeric($this->tagLength);
		if($test_a){$this->hardness=intval($this->hardness);
			$test_a=$this->hardness>-1&&$this->hardness<3;
		}if($test_b){$this->rotations=intval($this->rotations);
			$test_b=$this->rotations>1e4&&$this->rotations<1e6;
		}if($test_c){$this->tagLength=intval($this->tagLength);
			$test_c=in_array($this->tagLength,tagLength_ARRAY,true);
		}return $test_a&&$test_b&&$test_c;
	}private function ARGON2_hash(string $str){
		$txt=password_hash($str,PASSWORD_ARGON2ID);
		return '['.bin2hex(str_replace($this->replace,'',$txt)).']';
	}private function SHA3_512_hash(string $str){
		return hash_hmac('sha3-512',$str,strrev($str),false);
	}private function SHA3_512_lock_hash(string $str){
		$level=$this->hardness;
		$pre_hash=hash_hmac('sha3-512',strrev($str),substr($str,0,64),$level?true:false);
		if($level==0)return $pre_hash;
		elseif($level==1)return hash_pbkdf2(boundary_sha3_512,$pre_hash,$this->rotations,$this->tagLength,false);
		return hash('sha3-512',hash_pbkdf2(boundary_sha3_512,$pre_hash,$this->rotations,$this->tagLength,false));
	}private function openSSL(string $str,string $pass){
		$iv=mb_substr(hash(fast_ALGO,$str.$pass),0,16);
		return openssl_encrypt($str,enc_ALGO,$pass,OPENSSL_RAW_DATA,$iv);
	}function isValidHash(string $str){
		$isValid=$this->valid;
		if(!$isValid)return $this->ThrowError('Invalid dependencies given');
		$test_a=str_starts_with($str,'[')&&str_ends_with($str,']');
		if($test_a){$str=str_replace(['[',']'],'',$str);
			$test_b=preg_replace('/[^a-fA-F0-9]/u','',$str)==$str;
			if($test_b)$isValid=str_starts_with(hex2bin($str),'id');
		}return $isValid;
	}function createHash($bool=true){
		if(!$this->valid)return $this->ThrowError('Invalid dependencies given');
		$txt_a=$this->str_a;
		if(!strlen($txt_a))return $this->ThrowError('String [0] has no length');
		$level=$this->hardness;
		$lock_pass=$level?$this->SHA3_512_lock_hash($txt_a):$this->SHA3_512_hash($txt_a);
		if($level==0)$combind=$lock_pass;
		elseif($level==1)$combind=$this->SHA3_512_lock_hash($lock_pass.$this->SHA3_512_hash($txt_a));
		else{$seconadary=$this->SHA3_512_hash($txt_a);
			$combind=$this->openSSL($seconadary,$lock_pass);
		}return $bool?$this->ARGON2_hash($combind):$combind;
	}function compareHash(){
		$txt_a=$this->str_a;$txt_b=$this->str_b;
		if(!strlen($txt_a)||!strlen($txt_b)){
			return $this->ThrowError('String ['.(!strlen($txt_a)?0:1).'] has no length');
		}$isValidSecrect=$this->isValidHash($txt_b);
		if($isValidSecrect){
			$secret=strval($this->replace).hex2bin(str_replace(['[',']'],'',$txt_b));
			$compare=$this->createHash(false);
			return password_verify($compare,$secret);
		}return false;
	}
};
?>
