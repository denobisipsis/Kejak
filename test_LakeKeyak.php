<?
include "kejakv2.php";
/*
LakeKeyak can absorb up to 192 bytes of metadata per call to f 
or up to 168 of plaintext, with additionally 24 bytes of metadata

, up to 150 bytes of nonce
*/

class Sender
    {
    function __construct ($K, $N, $tagFlag, $decryptFlag, $forgetFlag)
    	{
	$this->T = new stringStream;   	
        $this->k = new Keyak("Lake");
        $status  = $this->k->StartEngine($K, $N,  $tagFlag, $this->T, $decryptFlag, $forgetFlag);
	}
    function sendAEADMsg($message, $metadata, $decryptFlag, $forgetFlag)
    	{
        $I = new stringStream($message);
        $A = new stringStream($metadata);
        $O = new stringStream;
        $status = $this->k->Wrap($I, $O, $A, $this->T, $decryptFlag, $forgetFlag);
        return [bin2hex($O->getvalue()), bin2hex($this->T->getvalue()), $status];
	}
    }
		      	
class Receiver
    {
    function __construct($K, $N, $tagFlag, $unwrapFlag, $forgetFlag)
    	{
        $this->k = new Keyak("Lake");
        $this->T = new stringStream; 
        $status  = $this->k->StartEngine($K, $N, $tagFlag, $this->T, $unwrapFlag, $forgetFlag);
	}
    function recvAEADMsg($cipher, $metadata, $unwrapFlag_W, $forgetFlag, $T="")
    	{
	$O = new stringStream;
        $I = new stringStream($cipher);
        $A = new stringStream($metadata);
	if ($T)
	$this->T = new stringStream($T); 
	else $this->T=new stringStream; 	    
        $status  = $this->k->Wrap($I, $O, $A, $this->T, $unwrapFlag_W, $forgetFlag);
        return [bin2hex($O->getvalue()), $status];
	}
    }	

$bool    = ["False"=>0,"false"=>0,"True"=>1];
$vectors = array_slice(explode('*** Keyak',file_get_contents("https://github.com/samvartaka/keyak-python/raw/master/TestVectors/LakeKeyak.txt")),1);

foreach ($vectors as $vector)
{
$K 	    = pack("H*",explode(']',explode('> K: [',$vector)[1])[0]);
$N 	    = pack("H*",explode(']',explode('> N: [',$vector)[1])[0]);
$T_valid    = explode(']',@explode('< T (tag): [',explode('Wrap',$vector)[0])[1])[0];
$engine     = explode(')',explode('StartEngine(K, N,',$vector)[1])[0];
$tagFlag    = $bool[explode(',',explode('tagFlag=',$engine)[1])[0]];
$unwrapFlag = $bool[explode(',',explode('unwrapFlag=',$engine)[1])[0]];
$forgetFlag = $bool[explode('forgetFlag=',$engine)[1]];

$sender     = new Sender($K, $N,  $tagFlag, $unwrapFlag, $forgetFlag);	

$wraps      = array_slice(explode('Wrap(I, O, A, T,',$vector),1);

foreach ($wraps as $wrap)
	{	
	$A 		= pack("H*",explode(']',explode('> A (metadata): [',$wrap)[1])[0]);
	$I 		= pack("H*",explode(']',explode('> I (plaintext): [',$wrap)[1])[0]);	
	$O_valid 	= explode(']',explode('< O (ciphertext): [',$wrap)[1])[0];
	$T_valid_wrap 	= explode(']',explode('< T (tag): [',$wrap)[1])[0];
	
	$wrap 		= explode(")",$wrap)[0];
		
	$unwrapFlag_W 	= $bool[explode(',',explode('unwrapFlag=',$wrap)[1])[0]];	
	$forgetFlag_W 	= $bool[explode('forgetFlag=',$wrap)[1]];
		
	echo "\nCiphering ".bin2hex($I)."\n";
		
	[$O,$T,$status] = $sender->sendAEADMsg($I, $A, $unwrapFlag_W, $forgetFlag_W);
	
	echo "Cipher   $O\nExpected $O_valid\nTag      $T\nExpected $T_valid_wrap\n\n";
	
	if ($O == $O_valid and $T == $T_valid_wrap) echo "Ok\n";
	else 		
		die("\n Bad Cipher");	
	}
}
