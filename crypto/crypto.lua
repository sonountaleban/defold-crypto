--[[
	HMAC implementation
	http://tools.ietf.org/html/rfc2104
	http://en.wikipedia.org/wiki/HMAC
--]]

local crypto = {md4 = 0, md5 = 1, sha1 = 2, sha224 = 3, sha256 = 4, sha384 = 5, sha512 = 6}

local function bintohex(s)
	return (s:gsub('(.)', function(c)
 		return string.format('%02x', string.byte(c))
  	end))
end 

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

return crypto

