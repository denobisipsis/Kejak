<?
/*
Based on

 https://keccak.team/files/Keyakv2-doc2.2.pdf
 
 &
 
 https://github.com/samvartaka/keyak-python

*/

class stringStream
    	{
	/*
	In our specification we make use of byte streams. In actual implementations, they can
	take the form of pointers to some buffer, bytes arriving from, or sent to, 
	some communication channel, and so on. What is important is that a realization supports the set of
	functions defined here. We indicate byte streams by capital lethers such as X and denote
	operations using the convention X.DoSomething(), popular in object oriented programming. 
	Concretely, a byte stream is a string of bytes that supports the following functions,
	similarly to a queue:
	
	• z ? X.Pullbyte() removes the first byte of stream X and assigns it to z;
	• X.Pushbyte(z) appends byte z to the end of the stream X;
	• X.HasMore returns a Boolean value that indicates whether stream is empty (False)
	or not (True);
	• (X = Y) returns a Boolean value that is True iff streams X and Y have the same
	content;
	• X.Clear(): removes all bytes from stream X.
	At some places we speak of input byte streams and output byte streams. An input byte
	stream does not have to support Pushbyte(z) and an output byte stream does not have
	to support Pullbyte().
	*/
    	function __construct ($stream="")
    		{
		$fp        = fopen('php://memory','r+');
		$this->fp  = $fp;
		self::Clear();
		fwrite($this->fp, strval($stream));	    		
		rewind($this->fp);
		}
	function haymas()
		{
		$actual = ftell($this->fp);
		self::Pullbyte();				
		if(!feof($this->fp)) $r = True;
		else		     $r = False;
		fseek($this->fp,$actual,SEEK_SET);		
		return $r;
		}
	function Pullbyte()
		{return ord(fread($this->fp,1));}
	function Pushbyte($b)
	        {fwrite($this->fp, chr($b));}
	function Clear()
	        {ftruncate($this->fp,0);}
	function setvalue($s)
		{self::Clear();fwrite($this->fp, $s);}		
	function getvalue()
		{rewind($this->fp);return stream_get_contents($this->fp);}
	function rewind()
		{rewind($this->fp);}
    	}

class State 
	{
	function __construct($stateSize)
	    	{
	        $this->stateSize = $stateSize;	    	
	        $this->s = str_split(str_repeat(0,$stateSize));
		}	
	function reset()
	    	{$this->s = str_split(str_repeat(0,$this->stateSize));}
	}
	 
class EnginePhase
	{
	const preparado 	= 0;
	const espera 		= 1;
	const endOfCrypt 	= 2;
	const endOfMessage 	= 3;	
	}

class MotorPhase
	{
	const preparado		= 0;
	const atope 		= 1;
	const crash 		= 2;
	}
	
class keccap
    {
    function __construct ($bits,$rounds)
    	{
        $this->bits       = $bits;
	$this->init_round = 24-$rounds;
	}
	
    function rotLeft64($lane, $biShift) 
    	{ 	
	$byShift    = floor($biShift/8);		
	$lane       = substr($lane,-$byShift).substr($lane,0,-$byShift);
	$biShift   %= 8;

	$temp       = ord($lane[0]) << $biShift;
	$lane[0]    = chr($temp & 0xff);
	$carry      = $temp >> 8;	
		
	for ($i = 1; $i < 7; $i++) 
		{		
		$temp     = ord($lane[$i]) << $biShift;
		$lane[$i] = chr($temp & 0xff | $carry);
		$carry    = $temp >> 8;		
		}

	$temp     = ord($lane[7]) << $biShift;
	$lane[7]  = chr($temp & 0xff | $carry);
			
	$lane[0]  = chr(ord($lane[0]) | $temp >> 8);	
	return $lane;		
	}
		    			       
    function Theta(&$lanes)
    	{	
	for ($x=0;$x<5;$x++) 				
		$C[$x]=$lanes[$x] ^ $lanes[$x+5] ^ $lanes[$x+10] ^ $lanes[$x+15] ^ $lanes[$x+20];
			
	for ($x=0;$x<5;$x++) 
		{	
		$D=$C[($x+4)%5] ^ self::rotLeft64($C[($x+1)%5],1);
		for ($y=0;$y<25;$y+=5) 			
			$lanes[$x+$y]^= $D;			
		}   
	}
			
   function Ro_Pi(&$lanes)
	{
	$x=1;$y=0;
	$actual=$lanes[1]; 
	for ($t=0;$t<24;$t++) 
		{
		[$x,$y]=[$y,(2*$x+3*$y)%5];
		$pos=$x+5*$y;		
		[$actual,$lanes[$pos]]=[$lanes[$pos],self::rotLeft64($actual,(($t+1)*($t+2)/2)%64)];
		}
	}
	
    function Ji(&$lanes)
    	{
	for ($y=0;$y<25;$y+=5) 
		{			
		$temp = array_slice($lanes,$y,5);
		for ($x=0;$x<5;$x++) 			
			$lanes[$x+$y]=$temp[$x] ^ ((~ $temp[($x+1)%5])&$temp[($x+2)%5]);		
		}
	}
	
    function Iota(&$lanes,$round)
    	{
	$LFSRstate = [
	"1000000","0101100","0111101","0000111","1111100","1000010","1001111","1010101",
	"0111000","0011000","1010110","0110010","1111110","1111001","1011101","1100101",
	"0100101","0001001","0110100","0110011","1001111","0001101","1000010","0010111"];
		
	$RCC = [
	"\1\0\0\0\0\0\0\0",
	"\2\0\0\0\0\0\0\0",
	"\x8\0\0\0\0\0\0\0",
	"\x80\0\0\0\0\0\0\0",
	"\0\x80\0\0\0\0\0\0",
	"\0\0\0\x80\0\0\0\0",
	"\0\0\0\0\0\0\0\x80"];
	
	
	for ($j=0;$j<7;$j++) 
		if ($LFSRstate[$round][$j]) $lanes[0] ^= $RCC[$j];		
	}
				
    function keccak_p($state) 
    	{		
	for ($round=$this->init_round;$round<24;$round++) 
		{			
		self::Theta($state);		
		self::Ro_Pi($state);			
		self::Ji($state);		
		self::Iota($state,$round);	
		}
	return $state;	
	}
    }

class Pistones 
    {
/*
This layer keeps a b-bit state and applies the permutation f to it. It performs the
basic functions such as injecting data, possible simultaneous encryption or decryption, 
extracting tags and seJing the fragment offsets. It has a squeezing rate, the
classical sponge rate, and an absorbing rate, the state width minus the last part 
containing the fragment offsets. When being called to inject, it receives a reference to a
byte stream and it puts a fragment that is as long as the input block can hold or that
exhausts the input byte stream, and sets the corresponding fragment offsets to the
correct value
*/
    function __construct ($squeezing_byte_rate, $absorbing_byte_rate, $keccap_bits, $keccap_rounds)
    	{
	$this->keccap 			= new keccap($keccap_bits,$keccap_rounds);
	//  plaintext fragment limit
        $this->squeezing_byte_rate 	= $squeezing_byte_rate;
	//  metadata fragment limit
        $this->absorbing_byte_rate  	= $absorbing_byte_rate; 
	      
        if ($this->squeezing_byte_rate > $this->absorbing_byte_rate)			
		die("squeezing_byte_rate is larger than absorbing_byte_rate");
		
        if ($this->absorbing_byte_rate > ($keccap_bits-32)/8)		
		die("absorbing_byte_rate is larger than (keccap_bits-32)/8");
		
	$this->State 			= new State(floor(($keccap_bits+7)/8));
	/*
	This fragment offset has a double function. First, it codes the number of bytes in
	the next output block that are used as tag, and that will consequently not be used as
	key stream. Second, it delimits messages by having a non-zero value if it is part of
	an input block that is the last of a message or of a string that is injected collectively.
	In case no tag is requested at the end of message or string that is injected collectively,
	EOM takes the value 255. The value 248 and above have a special meaning and are
	reserved for future use
	
	End of Message
	*/
        $this->EndOfMessage 	= $this->absorbing_byte_rate;
	//  end of the plaintext fragment in the current input block
        $this->CryptEnd 	= $this->absorbing_byte_rate + 1;
	//  start of the metadata fragment in the current input block
        $this->InjectStart 	= $this->absorbing_byte_rate + 2;
	//  end of the metadata fragment in the current input block
        $this->InjectEnd 	= $this->absorbing_byte_rate + 3;
	}
	
    function Crypt($I, $O, $state_index, $decryptFlag)
    	{
	/*
	?=state_index specifies the index in the state from where
	the plaintext fragment must be injected. The fragment will end at index squeezing_byte_rate 
	or earlier if the input stream is exhausted. It codes the end of the plaintext fragment 
	in the offset Crypt End
	*/

	while ($I->haymas() and $state_index < $this->squeezing_byte_rate)
	    {
            $x = $I->Pullbyte();
            $O->Pushbyte($this->State->s[$state_index] ^ $x);
	    	    
            if($decryptFlag)	$this->State->s[$state_index]  = $x;
            else		$this->State->s[$state_index] ^= $x;
	    		
            $state_index++;	    
	    }
	    
        $this->State->s[$this->CryptEnd] ^= $state_index;
	}

    function Inyeccion($X, $cryptingFlag)
    	{
	/*
	injects metadata taken from the input
	stream X
	
	The metadata fragment will end at index absorbing_byte_rate or earlier
	if the input stream is exhausted. It codes the start of the metadata fragment in the offset
	Inject Start and its end in Inject End
	*/				 
        if($cryptingFlag) $state_index = $this->squeezing_byte_rate;
        else              $state_index = 0;	
   
	$this->State->s[$this->InjectStart] ^= $state_index;

        while ($X->haymas() and $state_index < $this->absorbing_byte_rate)	    
		$this->State->s[$state_index++]   ^= $X->Pullbyte();	    
	    	    
        $this->State->s[$this->InjectEnd]   ^= $state_index;
	}

    function Aparca($eomFlag, $nbytes)
    	{
	/*
	applies the underlying permutation f=Keccap to the
	state. Before it does that, it codes in the data element EOM 
	whether this is the last input
	block of a message (or of string injected collectively) as indicated 
	by eomFlag and, if so,
	the number l of bytes of the state after the application of f that are reserved as tag
	*/
        if($eomFlag)
	    {
            if ($nbytes == 0) 	$delimiter = 255;
            else         	$delimiter = $nbytes;
	    }
        else             	$delimiter = 0;
	
	$this->State->s[$this->EndOfMessage] ^= $delimiter;
		
	$z="";foreach ($this->State->s as $r) $z.=chr($r);	

        $this->State->s = implode($this->keccap->keccak_p(str_split($z,8)));
	$this->State->s = array_Values(unpack("C*",$this->State->s));
	}
	
    function GetTag($T, $length)
    	{
	/*
	writes the first l bytes of the state to output
	byte stream T, to be used as a tag or chaining value
	*/
        if ($length > $this->squeezing_byte_rate)
            die("Excesivo tamaño del Tag");
	    
        for ($i=0;$i<$length;$i++)
		$T->Pushbyte($this->State->s[$i]);
	}
}
	
class Motor 
{
/*
This layer controls ? = 1 Piston objects that operate in parallel. 
It serves as a dispatcher keeping its Piston objects busy, 
imposing that they are all treating the same
kind of request. 
It can also inject the same stream into all Piston objects collectively.
The Engine also ensures that the SUV and message sequence can be reconstructed
from the sponge input to each Piston object and that each output bit of its Piston
objects is used at most once

For each piston, Engine remembers in the Et how much
output was used as tag or chaining value, so as to pass this to Piston.crypt() 
and avoid reusing the bits as key stream. 
Engine also maintains a state machine via the PHASE
to govern the sequence of function calls supported and thereby to enforce consistency.

Phase attributes of input blocks

fresh 		They are empty.

crypted 	They have a plaintext fragment and more plaintext is coming.

endOfCrypt 	They have a plaintext fragment and no more plaintext is coming.

endOfMessage 	They have their fragments ready and the message has been fully injected.

*/
    
    function __construct($Pistones)
    	{
        $this->Parallelism	= sizeof($Pistones);
        $this->Pistones		= $Pistones;
        $this->Phase 		= EnginePhase::preparado;
        $this->Etag 		= str_split(str_repeat(0,$this->Parallelism));
	}
	
    function Crypt($I, $O, $decryptFlag)
    	{
	/*
	dispatches the input I to the ? Piston
	objects and collects the corresponding ? output in O. 
	Each Piston object takes a fragment
	from I, so the Pistons process in total up to ?Rs bytes. 
	The phase switches to crypted, or
	to endOfCrypt if the input stream is exhausted. 
	The decryptFlag is as for Piston.Crypt
	*/
        if($this->Phase != EnginePhase::preparado)
            die("Crypt requiere fase=preparado");	
	
	for ($i=0;$i<$this->Parallelism;$i++)    
        	$this->Pistones[$i]->Crypt($I, $O, $this->Etag[$i], $decryptFlag);
	
	if ($I->haymas())		
		$this->Phase = EnginePhase::espera;	
	else
		$this->Phase = EnginePhase::endOfCrypt;
	}
	
    function Inyeccion($A)
    	{
	/*
	dispatches the metadata A to the ? Piston objects.
	Each Piston object takes a fragment from A, so the Pistons process in total up to 
	?(Ra -	Rs) bytes (if Engine.C????() was called before) or ?Ra bytes (otherwise). 
	If both the input and the metadata streams are exhausted, 
	it switches the phase to endOfMessage and delays
	the application of f until the call to Engine.GetTags. 
	Otherwise, it calls Engine.Spark
	to perform f(keccap) on all ? Piston objects and switches the phase back to fresh.
	*/
        if ($this->Phase == EnginePhase::endOfMessage)
            die("Inyeccion requiere fase no igual a endOfMessage");
	    
	$cryptFlag = ($this->Phase == EnginePhase::espera or $this->Phase == EnginePhase::endOfCrypt);
		
	for ($i=0;$i<$this->Parallelism;$i++)  
        	$this->Pistones[$i]->Inyeccion($A, $cryptFlag);
			
        if($this->Phase == EnginePhase::espera or $A->haymas())
	     {
             self::Aparca(0, str_split(str_repeat(0,$this->Parallelism)));
             $this->Phase = EnginePhase::preparado;	    
	     }
        else $this->Phase = EnginePhase::endOfMessage;
	}
	
    function GetTags($T, $l)
    	{
        if ($this->Phase != EnginePhase::endOfMessage)
            die("GetTags requiere fase=endOfMessage");
	    
        self::Aparca(1, $l);	

        for ($i=0;$i<$this->Parallelism;$i++)	    
            $this->Pistones[$i]->GetTag($T,$l[$i]);   
	                       	    	    
        $this->Phase = EnginePhase::preparado;
	}
	
    function Fullinyeccion($X, $diversifyFlag)
    	{
	/*
	aims at injecting the same
	metadata X to all ? Piston objects. 
	It is used to inject the SUV and the chaining values.
	When diversifyFlag = True, as set when injecting the SUV, 
	it appends to X two bytes:
	
	-  degree of parallelism ?, for domain separation between instances 
		with a different number of Piston objects
	
	-  index of the Piston object, for domain separation between
		Piston objects and in particular to avoid identical key streams
	*/	
        if ($this->Phase != EnginePhase::preparado)
            die("Fullinyeccion requiere fase=preparado");
	
	for ($i=0;$i<$this->Parallelism;$i++)
		$Xt[$i] = new stringStream;
	
	while ($X->haymas())		
		for ($i=0;$i<$this->Parallelism;$i++)
			$Xt[$i]->Pushbyte($X->Pullbyte());
		
        if ($diversifyFlag)				
	        for ($i=0;$i<$this->Parallelism;$i++)
		    	{
	                $Xt[$i]->Pushbyte($this->Parallelism);
	                $Xt[$i]->Pushbyte($i);
			}		
	
        for ($i=0;$i<$this->Parallelism;$i++)
		$Xt[$i]->rewind();

	while($Xt[0]->haymas())
		{	
		for ($i=0;$i<$this->Parallelism;$i++)
			$this->Pistones[$i]->Inyeccion($Xt[$i], 0);

		if ($Xt[0]->haymas())		 
			self::Aparca(False, str_split(str_repeat(0,$this->Parallelism)));
		}	
			  	
        $this->Phase = EnginePhase::endOfMessage;
	}
	
    function Aparca($eomFlag, $l)
    	{
	for ($i=0;$i<$this->Parallelism;$i++)
        	$this->Pistones[$i]->Aparca($eomFlag, $l[$i]);

        $this->Etag = $l;
	}
}
	    
class Motorist 
{
/*
This layer implements the user interface. It supports the starting of a session
and subsequent wrapping of messages and unwrapping of cryptograms by driving
the Engine

Motorist injects the SUV into each duplex instance, 
appending a diversification string at the end to make their states different

A Motorist object is also parameterized by the alignment
unit W in bits, typically 32 or 64. This ensures that the fragment start offsets and the
length of tags, chaining values and fragments (except when a stream is exhausted) are
a multiple of W, allowing data to be manipulated in multi-byte chunks. The remaining
parameters determine the security strength: the capacity c and the tag length t. From
these, the Motorist object derives the following quantities:

• the squeezing byte rate Rs
, the largest multiple of W such that at least max(c, 32)
bits (for the inner part and for the fragment offsets) of the state are never used as
output;
• the absorbing byte rate Ra, the largest multiple of W that reserves at least 32 bits at
the end of the state for absorbing the fragment offsets;
• the chaining value length c
'
, the smallest multiple of W greater than or equal to the
capacity c.
*/
    function __construct ($keccap_bits, $keccap_rounds, $Parallelism, $Width, $Capacity, $Taglength)
    	{   
        $this->Parallelism	= $Parallelism;	
	/*
	largest multiple of W such that at least max(c, 32)
	bits (for the inner part and for the fragment offsets) 
	of the state are never used as output
	*/	
	$squeezing_byte_rate 	= ($keccap_bits - max($Capacity, 32))/8;
	/*
	largest multiple of W that reserves at least 32 bits at
	the end of the state for absorbing the fragment offsets
	*/
	$absorbing_byte_rate 	= floor(($keccap_bits/8-4)/$Width)*$Width;
	
	for ($k=0;$k<$Parallelism;$k++)
        	$Pistones[]= new Pistones($squeezing_byte_rate, $absorbing_byte_rate, 
								$keccap_bits,$keccap_rounds);	
						
        $this->Motor 		= new Motor($Pistones);
	/*
	smallest multiple of W greater than or equal to the
	capacity 
	*/
        $this->Chaining_length	= floor($Width*floor(($Capacity + $Width - 1)/$Width));
        $this->Taglength	= $Taglength;
        $this->Phase 		= MotorPhase::preparado;
	}
	
    function StartEngine($SUV, $tagFlag, $T, $decryptFlag, $forgetFlag)
    	{
        if ($this->Phase != MotorPhase::preparado)
            die("Startengine requiere fase=preparado");
	    
        $this->Motor->Fullinyeccion($SUV, 1);
		
        if ($forgetFlag)
            self::_MakeKnot();
	    
        $res = self::_HandleTag($tagFlag, $T, $decryptFlag);
	
        if ($res)
            $this->Phase = MotorPhase::atope;  
	     
        return $res;
	}
	
    function Wrap($I, $O, $A, $T, $decryptFlag, $forgetFlag)
    	{
	/*
	$I chunk 152
	A$ chunk 24   
	To wrap, the function must be called with decryptFlag = False, 
	I (resp. A) an input byte stream containing the plaintext 
	(resp. the metadata),  O (resp. T) an output byte
	 stream ready to get the ciphertext (resp. the tag) and forgetFlag
	*/
        if ($this->Phase != MotorPhase::atope)
            die("Wrap requiere fase=atope");     
				
	if(!$I->haymas() and !$A->haymas())	       
	       /*
	       ensure that the Engine object enters the endOfMessage phase
	       */
	       $this->Motor->Inyeccion($A);

	while ($I->haymas())
		{
		$this->Motor->Crypt($I, $O, $decryptFlag);		
		$this->Motor->Inyeccion($A);
		}
						
	while ($A->haymas())		
		$this->Motor->Inyeccion($A);	
				
	if ($this->Parallelism > 1 or $forgetFlag)
		self::_MakeKnot();
	    	    
        $res = self::_HandleTag(1, $T, $decryptFlag);
	
        if (!$res)
            $O->Clear();
	    	    
        return $res;
	}
	    
    function _MakeKnot()
    	{
	/*
	retrieves a c'-bit chaining values from each Piston object, 
	concatenates these to make a ? × c'-bit string
	and collectively injects it into all Piston objects. 
	For ? > 1, this makes the state of all
	Piston objects depend on each other. 
	A fortiori this is also the case for Pistons[0], from
	which the tag of a message is extracted.
	*/
	
	$Tchaining = new stringStream;
	
	for ($i=0;$i<$this->Parallelism;$i++) 
		$l[] = $this->Chaining_length/8;
	
        $this->Motor->GetTags($Tchaining, $l);
        $Tchaining->rewind();	
        $this->Motor->Fullinyeccion($Tchaining, 0);
	}

    function _HandleTag($tagFlag, $T, $decryptFlag)
    	{	
	$Tchaining = new stringStream;
	
        if (!$tagFlag)	     
            $this->Motor->GetTags($Tchaining,str_split(str_repeat(0,$this->Parallelism)));	    
        else
	    {
            $l    = str_split(str_repeat(0,$this->Parallelism));
            $l[0] = $this->Taglength/8;
            $this->Motor->GetTags($Tchaining, $l);

            if (!$decryptFlag)
                $T->setvalue($Tchaining->getvalue());
	    else
		{					
		if ($T->getvalue()!=$Tchaining->getvalue()) 
			{
			$this->phase = MotorPhase::crash;
			return False;
			}
		}
	    }
        return True;
	}
}
	
class Keyak
{
    function __construct ($mode)
    	{         
        switch ($mode)
		{
		case "River": 	return self::init( 800, 12, 1, 256, 128);
		case "Lake": 	return self::init(1600, 12, 1, 256, 128);
		case "Sea": 	return self::init(1600, 12, 2, 256, 128);
		case "Ocean": 	return self::init(1600, 12, 4, 256, 128);
		case "Lunar": 	return self::init(1600, 12, 8, 256, 128);
		}
	}
	
    function init($keccap_bits, $keccap_rounds, $Parallelism, $Capacity, $Tagsize)
    	{         
        $this->Width 	= $keccap_bits/25; //max($keccap_bits/25, 8); 1600->64
        $this->Capacity	= $Capacity;
        $this->motorist = new Motorist($keccap_bits, $keccap_rounds, $Parallelism, 
        							$this->Width, $Capacity, $Tagsize);
	}

    function StartEngine($K, $N, $tagFlag, $T, $decryptFlag, $forgetFlag)
    	{	    
        $lk  = ($this->Width/8)*floor(($this->Capacity+9+$this->Width-1)/$this->Width); //  24 192 bits
	// SUV = secret and unique value
        $SUV = new stringStream(self::_keypack($K, $lk).$N);
        return $this->motorist->StartEngine($SUV, $tagFlag, $T, $decryptFlag, $forgetFlag);
	}
	
    function Wrap($I, $O, $A, $T, $decryptFlag, $forgetFlag)
    	{
        return $this->motorist->Wrap($I, $O, $A, $T, $decryptFlag, $forgetFlag);
	}

    function _keypack($K, $l)
    	{
        if ((strlen($K) + 2) > $l)
            die("La clave debe ser < ".($l-2));

        $result = chr($l).$K."\x01";
	    
        return $result.str_repeat(chr(0),$l-strlen($result));
	}
}
