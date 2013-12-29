var util  = require('util'),
    spawn = require('child_process').spawn;

//openssl smime -decrypt -in ./data/smime.p7m -inform der -recip ./certs/hub.amida-demo.com.pem -inkey ./certs/hub.amida-demo.com.privateKey.pem -out ./data/smime_clear.txt

//openssl smime -encrypt -in ./data/clear.txt -inkey ./certs/hub.amida-demo.com.privateKey.pem -out ./data/smime_notclear.txt ./certs/transport-testing.org.pem

//openssl smime -sign -in ./data/clear.txt -text -out ./data/clear_signed_opaque.txt -nodetach  -signer ./certs/hub.amida-demo.com.pem  -inkey ./certs/hub.amida-demo.com.privateKey.pem -certfile ./certs/hub.amida-demo.com.pem
//openssl smime -sign -in ./data/clear.txt -text -out ./data/clear_signed.txt -signer ./certs/hub.amida-demo.com.pem  -inkey ./certs/hub.amida-demo.com.privateKey.pem -certfile ./certs/hub.amida-demo.com.pem

exports.encrypt = function encrypt(buff, inkey, outkey, callback){
    var params = ['smime', '-encrypt', '-inkey', inkey, outkey];
    smime(buff, params, callback);
}

exports.decrypt = function decrypt(buff, inkey, callback){
    var params = ['smime', '-decrypt', '-inform', 'der','-inkey' , inkey];
    smime(buff, params, callback);
}

exports.sign = function sign(buff, cert, inkey, callback){
    var params = ['smime', '-sign', '-text', '-signer', cert, '-inkey' , inkey, '-certfile', cert];
    smime(buff, params, callback);
}

function smime(buff, params, callback) {
    var ssl = spawn('openssl', params),
        result = new Buffer(0),
        resultSize = 0;

        r="";

    ssl.stdout.on('data', function (data) {
        // Save up the result (or perhaps just call the callback repeatedly
        // with it as it comes, whatever)
        if (data.length + resultSize > result.length+10000000) {
            // Too much data, our SOME_APPROPRIATE_SIZE above wasn't big enough
            console.log("too much data");
        }
        else {
            // Append to our buffer
            resultSize += data.length;
            var result2=Buffer.concat([result, data]);
            result=result2;

            r=r+data.toString();
        }
    });

    ssl.stderr.on('data', function (data) {
        // Handle error output
    });

    ssl.on('exit', function (code) {
        // Done, trigger your callback (perhaps check `code` here)
        callback(result, r, resultSize);
    });

    // Write the buffer
    ssl.stdin.write(buff);
    ssl.stdin.end();
}