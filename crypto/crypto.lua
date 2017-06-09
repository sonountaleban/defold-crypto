local crypto = {md4 = 0, md5 = 1, sha1 = 2, sha224 = 3, sha256 = 4, sha384 = 5, sha512 = 6, aes128ecb = 7, aes128cbc = 8}

local function bintohex(s)
	return (s:gsub('(.)', function(c)
 		return string.format('%02x', string.byte(c))
  	end))
end 

-- supported algorithms: sha256, sha384 and sha512
crypto.digest = function(algorithm, data, raw)
	local func
	
	if algorithm == crypto.sha256 then
		if raw == true then
			func = sha2.sha256
		else
			func = sha2.sha256hex
		end	
	elseif algorithm == crypto.sha384 then
		if raw == true then
			func = sha2.sha384
		else
			func = sha2.sha384hex
		end
	elseif algorithm == crypto.sha512 then
		if raw == true then
			func = sha2.sha512
		else
			func = sha2.sha512hex
		end
	else
		return nil
	end
	
	return func(data)
end

-- supported algorithms: sha256, sha384 and sha512
crypto.hmac = function(algorithm, data, key, raw)
	local hash
	local blocksize
	local opad
	local ipad
	local ret
	
	if algorithm == crypto.sha256 then
		hash = sha2.sha256
		blocksize = 64
	elseif algorithm == crypto.sha384 then
		hash = sha2.sha384
		blocksize = 128
	elseif algorithm == crypto.sha512 then
		hash = sha2.sha512
		blocksize = 128
	else
		return nil
	end
	
	if #key > blocksize then
        key = hash(key)
    end
    key = key .. string.rep('\0', blocksize - #key)
    
    opad = opad or sha2.exor(key, string.rep(string.char(0x5c), blocksize))
    ipad = ipad or sha2.exor(key, string.rep(string.char(0x36), blocksize))
    
    ret = hash(opad .. hash(ipad .. data))
    
    if raw == nil or not raw then
    	ret = bintohex(ret)
    end
    
    return ret
end

-- supported cyphers: aes128ecb and aes128cbc
crypto.encrypt = function(cipher, input, key, iv)
	local output = ""
	local b = 1
	
	if cipher == crypto.aes128ecb then
		if #input % 16 ~= 0 then
			input = input .. string.rep('\0', 16 - #input % 16)	
		end
		
		if #key < 16 then
			key = key .. string.rep('\0', 16 - #key)	
		elseif #key > 16 then
			key = string.sub(key, 1, 16)
		end
		
		for a = 1, #input / 16 do
			output = output .. aes128.aes128ecbencrypt(string.sub(input, b, b + 15), key)
			
			b = b + 16
		end
	elseif cipher == crypto.aes128cbc then
		if #input % 16 ~= 0 then
			input = input .. string.rep('\0', 16 - #input % 16)	
		end
		
		if #key < 16 then
			key = key .. string.rep('\0', 16 - #key)	
		elseif #key > 16 then
			key = string.sub(key, 1, 16)
		end
		
		if #iv < 16 then
			iv = iv .. string.rep('\0', 16 - #iv)	
		elseif #iv > 16 then
			iv = string.sub(iv, 1, 16)
		end
		
		output = aes128.aes128cbcencryptbuffer(input, key, iv)
	end
	
	return output
end

-- supported cyphers: aes128ecb and aes128cbc
crypto.decrypt = function(cipher, input, key, iv)
	local output = ""
	local b = 1
	
	if cipher == crypto.aes128ecb then
		if #key < 16 then
			key = key .. string.rep('\0', 16 - #key)	
		elseif #key > 16 then
			key = string.sub(key, 1, 16)
		end
		
		for a = 1, #input / 16 do
			output = output .. aes128.aes128ecbdecrypt(string.sub(input, b, b + 15), key)
			
			b = b + 16
		end
	elseif cipher == crypto.aes128cbc then
		if #key < 16 then
			key = key .. string.rep('\0', 16 - #key)	
		elseif #key > 16 then
			key = string.sub(key, 1, 16)
		end
		
		if #iv < 16 then
			iv = iv .. string.rep('\0', 16 - #iv)	
		elseif #iv > 16 then
			iv = string.sub(iv, 1, 16)
		end
		
		output = aes128.aes128cbcdecryptbuffer(input, key, iv)
	end
	
	return output
end

return crypto

