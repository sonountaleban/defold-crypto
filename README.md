# Crypto
This is the Crypto module for the [Defold game engine](http://www.defold.com) and it supports digests and hmac computations for SHA-256, 384 and 512. It is based on this [Lua binding](https://code.google.com/archive/p/sha2) and is source-code compatible with the Crypto library of Corona SDK.

## Installation
You can use Crypto in your own project by adding this project as a [Defold library dependency](http://www.defold.com/manuals/libraries/). Open your game.project file and in the dependencies field under project add:

https://github.com/sonountaleban/defold-crypto/archive/master.zip

## Usage
Here some examples:

```lua
local crypto = require("crypto.crypto")

assert(crypto.digest(crypto.sha256, "And so we say goodbye to our beloved pet, Nibbler, who's gone to a place where I, too, hope one day to go. The toilet.") ==
		"3c4ba860b4917a85b075f5e0c8cebe65bd1646d0d5ac3326a974ae965a44a5e1")
		
assert(crypto.hmac(crypto.sha256, "what do ya want for nothing?", "Jefe") ==
	"5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
	
assert(crypto.hmac(crypto.sha384, "This is a test!!!", "This is a key??") ==
	"2a0017d73a471f3f6a06000fb51d5df305da6a3e3b384671760aa45be85ffdc15cd6697b4aebafdc6e4b48f85e50d9c8")
	
assert(crypto.hmac(crypto.sha512, "This is a test!!!", "This is a key??") ==
	"01ecc8872d6809c78a98caac7b6d0a26a1373e3a00500cda497ad546d4a4655192f00c1909a1dc419befb3051b17b50c45e1d5f5ad54520c88eda327c1c12f51")
```

## Limitations
This module is available for all platforms that are currently supported by [Native Extensions](http://www.defold.com/manuals/extensions/). Also MD4, MD5, SHA-1 and SHA-224 are not yet implemented.
