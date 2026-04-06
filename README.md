# ARGON2 + SHA3-512 + openSSL comparison tool

The reason why i build this, i needed a one-time hash 'comparison' method,
for several other projects i have.<br>
And this one does quite a good job at it.<br>
This one does also include openSSL encryption with raw data. 

Depending on the hardware you are running, the task takes longer or lesser time.
Every hash is different every time.

This makes backtracking of any kind multiple times harder, since ARGON2 is memory-hard to precompute.

with strict type checking and validation of given arguments.

```php
    class ARGON2_SHA3_512{
      private $txt_a='',$txt_b='';
      function __construct(string $str,string|NULL $known_secret=null,int $hardness=0,int $rotations=399999,int $tagLength=256){
        // ....
      }
    }
```

## The way this one works

### To create a new hash

```php
<?php
  $new_go=new ARGON2_SHA3_512('Hello World');
  $old_hash=$new_go->createHash();
?>
```

### To compare an existing hash

```php
<?php
  $compare_context=new ARGON2_SHA3_512('Hello World',$old_hash);
  $compare=$compare_context->compareHash();
  
  // $compare in this case will be true
?>
```
The outcome of this method will return true if they compare and validate,<br>
else false.

### 3 Levels of hardness
the 3rd argument lets you choose between the different levels of hardness.
every level has it own way to do the prework.
level 2 even includes <mark>OPENSSL_RAW_DATA</mark>.

```php
<?php
  $new_go=new ARGON2_SHA3_512('Hello World',null,2);
  $old_hash=$new_go->createHash();
?>
```
level 0
: only a simple 'hash_hmac' hash method
  ```php 
$level=$this->hardness;
$pre_hash=hash_hmac('sha3-512',strrev($str),substr($str,0,64),$level?true:false);
if($level==0)return $pre_hash;
  ```
level 1
: the same as level 0 plus 'hash_pbkdf2' hash
  ```php 
$level=$this->hardness;
$pre_hash=hash_hmac('sha3-512',strrev($str),substr($str,0,64),$level?true:false);
if($level==0)return $pre_hash;
elseif($level==1)return hash_pbkdf2(boundary_sha3_512,$pre_hash,$this->rotations,$this->tagLength,false);
  ```

level 2
: same as level 1 plus a final hash of sha3-512
  ```php 
$level=$this->hardness;
$pre_hash=hash_hmac('sha3-512',strrev($str),substr($str,0,64),$level?true:false);
if($level==0)return $pre_hash;
elseif($level==1)return hash_pbkdf2(boundary_sha3_512,$pre_hash,$this->rotations,$this->tagLength,false);
return hash('sha3-512',hash_pbkdf2(boundary_sha3_512,$pre_hash,$this->rotations,$this->tagLength,false));
  ```
## The ARGON2 part
  ```php
private function ARGON2_hash(string $str){
    $txt=password_hash($str,PASSWORD_ARGON2ID);
    return '['.bin2hex(str_replace($this->replace,'',$txt)).']';
}
  ```
## The comparison part
  ```php
function compareHash(){
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
  ```
## The validation part
  ```php
private function IsValid(){
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
}
  ```

### I even added several overides into the mix
  ```php
$this->hardness=defined('override_hardness_ARGON2_SHA3_512')?override_hardness_ARGON2_SHA3_512:$hardness;
$this->rotations=defined('override_rotations_ARGON2_SHA3_512')?override_rotations_ARGON2_SHA3_512:$rotations;
$this->tagLength=defined('override_tagLength_ARGON2_SHA3_512')?override_tagLength_ARGON2_SHA3_512:$tagLength;
  ```
### Error handling
  ```php
  public function ThrowError(string $str){
      if(!strlen($str))$str='Unknown Error occured';
      throw new Exception('[ARGON2_SHA3_512] Exception : '.\n.\t.$str.'.'.\n);
  }
  ```

