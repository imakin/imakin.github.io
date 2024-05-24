//Izzulmakin 2021
function console_log(s){
    console.log(s);//debug
}

// crypto-save physical sensor analog to digital generated secure random initial vector
const pre_iv = "239iuadpks;x;pk29'a[pkoj";
//argon2-ed during encrypt and decrypt :::::::
const password_salt = "od;Þx86+x1b>,2/1."
const iv_salt = "E»Òi&*x99Qf59e"

/**
 * generate 128-bit key from password with any length
 * @param {*string} password 
 */
function passwordToKey(password) {
    var str = password;
    var bytes = []; // char codes

    for (var i = 0; i < str.length; ++i) {
        var code = str.charCodeAt(i);        
        bytes = bytes.concat([code]);
    }
    return bytes;

}

/** padd a text to have length of multiple of 16 bytes
 * @param length: length of text to be padded
 */
function whitespace16(length) {
    const padding_char = ' ';
    return padding_char.repeat(
        ((length-1)|15)+1-length // closest upper multiplier of 16
    );
}

/**
 * sample simple vulnerable pad
 * @param {Uint8Array} arr 
 * @returns 
 */
function xorpad(arr){
    for (let i=0;i<arr.length;i++){
        arr[i] = arr[i]^255;
    }
    return arr;
}

/**
 * pad & obscure data before encryption
 * @param {Uint8Array} arr
 * @returns {Uint8Array} new arr
 */
function padhalf(arr){ //pad & obscure one byte into 2 bytes
    let newarr = new Uint8Array(arr.length*2);
    window.crypto.getRandomValues(newarr);
    let i=0;
    for (i=0;i<arr.length;i++){
        let target = arr[i];
        let j = i*2;
        let msb = target>>4
        let lsb = target&0x0f;
        //make byte 0xAB into 2 bytes 0xRA 0xBR with R is random
        newarr[j] = ( newarr[j] & 0xf0 ) | msb;
        newarr[j+1] = ( newarr[j+1] & 0x0f) | (lsb<<4);
    }
    return newarr;
}
function unpadhalf(arr){
    let newarr = new Uint8Array(arr.length/2);
    let i = 0;
    for (i=0;i<newarr.length;i++){
        let j = i*2;
        let target = (arr[j]<<8) | arr[j+1];
        target = (target>>4) & 0x00ff;
        newarr[i] = target;
    }
    return newarr;
}
function test_unpadhalf(){
    let message = 'something here';
    let message_bytes = aesjs.utils.utf8.toBytes(message);
    let padded_a = padhalf(message_bytes);
    let padded_b = padhalf(message_bytes);
    console.log(message_bytes);
    console.log(padded_a);
    console.log(padded_b);
    console.log(unpadhalf(padded_a));
    console.log(unpadhalf(padded_b));
    console.assert(message==aesjs.utils.utf8.fromBytes(unpadhalf(padded_a)));
    console.assert(message==aesjs.utils.utf8.fromBytes(unpadhalf(padded_b)));
    console.assert(aesjs.utils.utf8.fromBytes(unpadhalf(padded_a))==aesjs.utils.utf8.fromBytes(unpadhalf(padded_b)));
    console.assert(padded_a!=padded_b);
    console.info('ok');
}

/**
 * Encrypt text string using password string with AES-CBC method, and argon2. with password size is used to argon2 the salt and iv
 * @param {*string} text 
 * @param {*string} password 
 * @return promise    resolve(hexstring of encrypted text)
 *        sample: encrypt("secret text", "passwd").then(function(encrypted_text){console.log(encrypted_text)})
 */
function encryptargon2(text, password) {
    var promisereturn = new Promise(function(resolve,reject){
        argon2.hash({ pass: password, salt: password_salt, time:password.length,mem:password.length*9,hashLen:16})
        .then(function(h) {
            console_log("step1 argon2 password");
            //~ console_log(h.hash, h.hashHex, h.encoded);
            argon2.hash({ pass: pre_iv, salt: iv_salt, time:password.length,mem:password.length*11,hashLen:16})
            .then(function(hiv) {
                console_log("step2 argon2 iv");
                //~ console_log(hiv.hash, hiv.hashHex, hiv.encoded);
                text = text+whitespace16(text.length); // pad to multiplier of 16 length
                var aesCbc = new aesjs.ModeOfOperation.cbc(h.hash,hiv.hash);
                var encryptedBytes = aesCbc.encrypt(
                    aesjs.utils.utf8.toBytes(text) // convert to bytes
                );
                var encryptedhexstring =    aesjs.utils.hex.fromBytes(encryptedBytes); //convert to hexstring
                console_log(encryptedhexstring);
                resolve(encryptedhexstring);
            })
        });
    });
    return promisereturn;
}

/**
 * Decrypt hexstringEncryptedData (hex string) using password
 * @param {*} hexstringEncryptedData: a hexstring of encrypted bytes
 * @param {*} password: password used
 *     sample: decrypt("ccdcaf625d66c658fc868e4fb9264a7b","pintars")
 */
function decryptargon2(hexstringEncryptedData, password) {
    
    var promisereturn = new Promise(function(resolve,reject){
        argon2.hash({ pass: password, salt: password_salt, time:password.length,mem:password.length*9,hashLen:16})
        .then(function(h) {
            console_log("step1 argon2 password");
            //~ console_log(h.hash, h.hashHex, h.encoded);
            argon2.hash({ pass: pre_iv, salt: iv_salt, time:password.length,mem:password.length*11,hashLen:16})
            .then(function(hiv) {
                console_log("step2 argon2 iv");
                //~ console_log(hiv.hash, hiv.hashHex, hiv.encoded);
                var aesCbc = new aesjs.ModeOfOperation.cbc(h.hash,hiv.hash);
                
                var encryptedBytes = aesjs.utils.hex.toBytes(hexstringEncryptedData);//hexstring to encrypted bytes
                var decryptedBytes = aesCbc.decrypt(encryptedBytes); //decrypt to bytes
                var decrypted_string = aesjs.utils.utf8.fromBytes(decryptedBytes).trim();//from Bytes to string, trim trailing spaces
                //~ console_log(decrypted_string);
                resolve(decrypted_string)
                
            })
        });
    });
    return promisereturn;
}

/**
 * Encrypt text string using password string with AES-CBC method, and blake2s
 * @param {*string} text 
 * @param {*string} password 
 * @param {*func} padfunction pad the Uint8Array to obscure data before encryption
 * @return promise    resolve(hexstring of encrypted text)
 *        sample: encrypt("secret text", "passwd").then(function(encrypted_text){console.log(encrypted_text)})
 */
function encryptblake2s(text, password, padfunction) {
    var promisereturn = new Promise(function(resolve,reject){
        localhashblake2s(password,password_salt,16,true).then(function(h){
            console_log("step1 blake2s password");
            localhashblake2s(pre_iv, iv_salt, 16,true).then(function(hiv){
                console_log("step2 blake2s iv");
                console_log(hiv, h);
                text = text+whitespace16(text.length); // pad to multiplier of 16 length
                var aesCbc = new aesjs.ModeOfOperation.cbc(h.digest(),hiv.digest());
                let bytes = aesjs.utils.utf8.toBytes(text); // convert to bytes
                if (padfunction){
                    bytes = padfunction(bytes);
                }
                var encryptedBytes = aesCbc.encrypt(
                    bytes
                );
                var encryptedhexstring =    aesjs.utils.hex.fromBytes(encryptedBytes); //convert to hexstring
                console_log(encryptedhexstring);
                resolve(encryptedhexstring);
            });
        });
    });
    return promisereturn;
}

/**
 * Decrypt hexstringEncryptedData (hex string) using password
 * @param {*} hexstringEncryptedData: a hexstring of encrypted bytes
 * @param {*} password: password used
 * @param {*func} unpadfunction unpad the Uint8Array to return from obscured data after decryption
 *     sample: decrypt("ccdcaf625d66c658fc868e4fb9264a7b","pintars")
 */
function decryptblake2s(hexstringEncryptedData, password, unpadfunction) {
    var promisereturn = new Promise(function(resolve,reject){
        localhashblake2s(password,password_salt,16, true).then(function(h){
            console_log("step1 blake2s password");
            localhashblake2s(pre_iv, iv_salt, 16, true).then(function(hiv){
                console_log("step2 blake2s iv");
                //~ console_log(hiv.hash, hiv.hashHex, hiv.encoded);
                var aesCbc = new aesjs.ModeOfOperation.cbc(h.digest(),hiv.digest());
                
                var encryptedBytes = aesjs.utils.hex.toBytes(hexstringEncryptedData);//hexstring to encrypted bytes
                var decryptedBytes = aesCbc.decrypt(encryptedBytes); //decrypt to bytes
                if (unpadfunction){
                    decryptedBytes = unpadfunction(decryptedBytes);
                }
                var decrypted_string = aesjs.utils.utf8.fromBytes(decryptedBytes).trim();//from Bytes to string, trim trailing spaces
                //~ console_log(decrypted_string);
                resolve(decrypted_string)
            });
        });
    });
    return promisereturn;
}

function utf8(s) {
    var i, d = unescape(encodeURIComponent(s)), b = new Uint8Array(d.length);
    for (i = 0; i < d.length; i++) b[i] = d.charCodeAt(i);
    return b;
}
/**
 * using blake2s hashing 
 * password, salt
 *
 */ 
function localhashblake2s(input, key, hashlength, return_raw) {
    if (!hashlength) {
        hashlength = 32;
    }
    const length = hashlength;
    var promisereturn = new Promise(function(resolve,reject){
            var h = new BLAKE2s(length,utf8(key));
            h.update(utf8(input));
            if (return_raw) {
                    resolve(h);
            } else {
                resolve(h.hexDigest());
            }
    });
    return promisereturn;
}

/**hash pin locally
 * @param: pin (String)
 * @param argon2salt (String)
 * 
 *    nsalt = adds up all pin's digit pin[0]+pin[1]+pin[2]+...
 *    uint8hash = argon2(password=pin, salt=argon2salt, t=nsalt, memory=nsalt*100, tagLength=124
 *    alphabetifiedhash = "".join([chr(c) for c in uint8hash if (c>=97 and c<=122)])
 * 
 * @return promise(function(hasilhexstring){})
 *    usage: localhash("kmklmx","jsdjnaasdjajasjiosjiodsaj").then(function(hasilhexstring){ console.log(hasilhexstring) })
**/function localhashargon2(pin, argon2salt,hashlength, return_raw) {
    var promisereturn = new Promise(function(resolve,reject){
            if (!hashlength) {
                hashlength = 32;
            }
            const length = hashlength;
            nsalt = 0;
            for (i=0;i<pin.length;i++) {
                    let c = parseInt(pin[i]);
                    nsalt = nsalt + c;
            }
            console.log("nsaltnya",nsalt);
            argon2.hash({
                    pass:pin,
                    salt:argon2salt,
                    time:nsalt,
                    mem:256, //in KiB
                    hashLen:length,
                    type:argon2.ArgonType.Argon2i
            }).then(function(h){
                    console.log(h)
                    if (return_raw) {
                        resolve(h);
                    } else {
                        perhasilan = h.hashHex;
                        resolve(perhasilan);
                    }
            });
    });
    return promisereturn;
}
