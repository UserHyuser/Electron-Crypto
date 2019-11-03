// This file is required by the index.html file and will
// be executed in the renderer process for that window.
// All of the Node.js APIs are available in this process.
const bigInt = require('big-integer');
const crypto = require('crypto');
/*Class of functions for export them to main.js*/
class cryptFunctions {
    constructor () {}
    // возвращает строки чтобы адекватно отправлялось по сокетам
    static DiffiHellman(P,Q, size){
        let p,q;
        if (SolovayStrassenTest(BigInt(P),128) && SolovayStrassenTest(BigInt(Q),128)){
            p = BigInt(P); q = BigInt(Q);
        } else {
            let numbers = getPrimeNumbers(size);
            console.log(numbers)
            // Find g
            q = BigInt(numbers.q); p = BigInt(numbers.p);
        }
        let g = 5n;
        while( fastDegreeModule(g,q,p) === 1n){
            g = BigInt(bigInt.randBetween(1, (p-1n).toString()))
        }

        // first client
        let Xa = (bigInt.randBetween((p/2n).toString(), (p-1n).toString())).toString();
        let Ya = fastDegreeModule(g,Xa, p);

        // second
        let Xb = (bigInt.randBetween((p/2n).toString(), (p-1n).toString())).toString();
        let Yb = fastDegreeModule(g,Xb, p);

        // Connection
        let Zab = fastDegreeModule(Yb,Xa, p);
        let Zba = fastDegreeModule(Ya,Xb, p);

        // console.table({q, p, g, Xa, Ya, Xb, Yb, Zab, Zba})
        return {q: q.toString(), p: p.toString(), g: g.toString(), Xa, Ya: Ya.toString(), Xb, Yb: Yb.toString(), Zab: Zab.toString(), Zba: Zba.toString()}
    }

    static AlGamal(message, size, P, G, C1, C2, D1, D2) {
        let p = BigInt(P) || BigInt(randomPrime(size).toString()); // Открытые
        let g = BigInt(G) || 3n;
        while (NOD(g, p-1n) !== 1n){
            g++;
        }
        // 2 числа Ci
        let c1 = BigInt(C1) || BigInt(bigInt.randBetween(1, (p-1n).toString()));
        let c2 = BigInt(C2) || BigInt(bigInt.randBetween(1, (p-1n).toString()));
        console.log(p);
        //Вычисляем Di
        let d1 = BigInt(D1) || fastDegreeModule(g, c1, p);
        let d2 = BigInt(D2) || fastDegreeModule(g, c2, p);

        // Шифрование
        let cipher = asUTF8Codes(message).split(" ");

        for (let i = 0; i < cipher.length; i++){
            cipher[i] = (BigInt(cipher[i]) * fastDegreeModule(d2, c1, p)) % p;
        }
        cipher = cipher.join(' ');

        let decipher = cipher.split(' ');

        for (let i = 0; i < decipher.length; i++){
            decipher[i] = (BigInt(decipher[i]) * fastDegreeModule(d1, p - 1n - c2, p)) % p;
            decipher[i] = unicodeToChar(parseInt(decipher[i]));
        }
        decipher = decipher.join('');
        // cipher = (message * fastDegreeModule(d2, c1, p)) % p; // Нечетные - первый абонент // d1 и cipher посылаются Бобу

        return {p,g,c1,c2,d1,d2,cipher,decipher};
    }

    static AlGamalGenerate(size, P, G, C1, C2, D1, D2) {
        let p = BigInt(P || BigInt(randomPrime(size).toString())); // Открытые
        let g = BigInt(G || 3n);
        while (NOD(g, p-1n) !== 1n){
            g++;
        }
        // 2 числа Ci
        let c1 = BigInt(C1 || BigInt(bigInt.randBetween(1, (p-1n).toString())));
        let c2 = BigInt(C2 || BigInt(bigInt.randBetween(1, (p-1n).toString())));
        console.log(p);
        //Вычисляем Di
        let d1 = BigInt(D1 || fastDegreeModule(g, c1, p));
        let d2 = BigInt(D2 || fastDegreeModule(g, c2, p));

        return {p,g,c1,c2,d1,d2};
    }

}
module.exports = cryptFunctions;

/*A - base, P - power, M - module
* returns (A ** P) mod M for any numbers*/
function fastDegreeModule(A,P,M) {
    let a = BigInt(A); let p = BigInt(P); let m = BigInt(M);
    let result = 1n;
    let arrayOfDegrees = countFactorOf2Degree(p).split(" ");
    //console.log(arrayOfDegrees);
    let helpVar = (a * a) % m;
    let helpDegree = 2n;
    for (let i = arrayOfDegrees.length; i > 0; i--) {

        // Возведение в степень по модулю
        if (arrayOfDegrees[i - 1] !== "" && arrayOfDegrees[i - 1] !== '1' && arrayOfDegrees[i - 1] !== '0') {
            while (helpDegree.toString() !== arrayOfDegrees[i - 1]) {
                helpVar = ((helpVar * helpVar)) % m;
                helpDegree = helpDegree * 2n;
            }
            // console.log(helpVar + " " + helpDegree)
            result = (result * helpVar) % m

        } else result = (result * degreeModule(a, BigInt(arrayOfDegrees[i - 1]), m)) % m;
    }
    // return parseInt(result);
    return result;
}

/*Same result but it's not optimal
* Also it can't evaluate a REAL big numbers*/
const degreeModule = (a, p, m) => {
    return (a ** p) % m;
};

/*RSA encryption
* Message, open key (e, n)*/
function RSAEncrypt(message, e, n){
    let c = asUTF8Codes(message).split(" ");
    n = BigInt(n);
    e = BigInt(e);
    for (let i = 1; i < c.length; i++){ // Запутывание последовательности
        c[i] = (BigInt(c[i]) + BigInt(c[i - 1])) % n;
    }
    for (let i = 0; i < c.length; i++){
        c[i] = fastDegreeModule(c[i],e,n);
    }
    return c.join(' ');
}

/*RSA encryption
* Message, hidden key e, open key n*/
function RSADecrypt(message, d, n){
    n = BigInt(n);
    d = BigInt(d);

    let c = message.split(' ');
    let result = [];
    for (let i = 0; i < c.length; i++){
        if (i === 0){
            c[i] = fastDegreeModule(c[i],d,n);
            result[i] = c[i];
        } else{
            c[i] = (fastDegreeModule(c[i],d,n));
            result[i] = (c[i] - c[i-1]) % BigInt(n) // Распутывание последовательности
        }
    }
    for (let i = 0; i < c.length; i++){
        // console.log(result[i])
        result[i] = unicodeToChar(parseInt(result[i]));
    }
    return result.join('');
}

/*String to array of UTF8 codes*/
function asUTF8Codes(str) {
    let output = "";
    for (let i = 0; i < str.length; i++) {
        output += str.charCodeAt(i) + " ";
    }
    return output.trim();
}

/*Number to UTF char*/
function unicodeToChar(text) {
    return String.fromCharCode(parseInt(text))
}

/*Factorize number to sum of degrees of 2
* returns a string like "2 4 8" for 14 */
function countFactorOf2Degree(num) {
    let tmp = 1n;
    if (num === 0n) {
        return 0n
    } else if (num === 1n) {
        return "1"
    }
    while (tmp <= num) {
        tmp *= 2n;
    }
    tmp /= 2n;
    num = num - tmp;
    return tmp.toString() + " " + countFactorOf2Degree(num)
}

/*Find d = a^(-1) mod m
* uses an Extended Euclid's algorithm */
function getInverseElem(a,m) {
    m = BigInt(m); a = BigInt(a);
    a = (a % m + m) % m
    if (!a || m < 2n) {
        return NaN // invalid input
    }
    const s = [];
    let b = m;
    while(b) {                  // Алгоритм Евклида с записью промежуточных значений
        [a, b] = [b, a % b];
        s.push({a, b})
    }
    if (a !== 1n) {
        return NaN // Обратного элемента нет
    }
    // Нахождение обратного элемента по "ручному алгоритму"
    let x = 1n;
    let y = 0n;
    for(let i = s.length - 2; i >= 0; --i) {
        [x, y] = [y,  x - y * ~~(s[i].a / s[i].b)]
    }
    let t = ((y % m) + m) % m;
    if (t > 0n){
        return t
    } else {
        return t + m;
    }
}

/*GCD - Euclid's algorithm to find Greatest common divisor */
function NOD(a, b) {
    if (!b) {
        return a;
    }
    return NOD(b, a % b);
}

/*Generate P, Q, N, E, D for RSA algorithm*/
function bigNumbersGenerate(keysize, P, Q) {
    let e = BigInt(65537);
    let p = BigInt(P) || 0;
    let q = BigInt(Q) || 0;
    let eilerFunc;

    if (!isNaN(parseInt(keysize))){
        p = BigInt(randomPrime(keysize / 2));
        q = BigInt(randomPrime(keysize / 2));
        eilerFunc = (p-1n)*(q-1n);
        if(NOD(e,eilerFunc) !== 1n){
            do {
                e = bigInt.randBetween(5n, eilerFunc - 1n)
            } while (bigInt.gcd(e, eilerFunc).notEquals(1)); // Пока НОД е, и "числа Эйлера" !== 1 или || p.minus(q).abs().shiftRight(keysize / 2 - 100).isZero()
        }
    } else {
        eilerFunc = (p-1n)*(q-1n)
    }
    // console.log({ d: getInverseElem(e,totient), totient, e})
    return {
        p,
        q,
        e,
        n: p*q,
        d: getInverseElem(e,eilerFunc),
    };
}

/*Generate a prime number
* size in bits*/
function randomPrime(bits) {
    const min = bigInt.one.shiftLeft(bits - 1);
    const max = bigInt.one.shiftLeft(bits).prev();

    while (true) {
        let p = bigInt.randBetween(min, max);
        // console.log(p);
        if (p.isProbablePrime(32)) {
            return p.toString();
        }
    }
}

/*Generate 2 prime numbers P and Q
* Q consist of deg digits
* P = Q*2 + 1*/
function getPrimeNumbers(deg) { // указывается степень
    const min = BigInt(10n ** (BigInt(deg)-2n));
    const max = BigInt(10n ** (BigInt(deg)));
    let q,p;
    while (true) {
        q = (bigInt.randBetween(min, max)).toString();
        if (SolovayStrassenTest(q.toString(),32)) {
            p = (bigInt(2n*BigInt(q) + 1n)).toString();
            if (SolovayStrassenTest(p.toString(),32)){ // Почему-то нужно передавать как строку BigInt не работает
                return {p, q}
            }
        }
    }
}

/*Generate 2 prime numbers P and Q
* Q size in bits; P = Q*2 + 1
* This function uses a secure generation of bytes with 'crypto' object*/
function getPrimeNumbersBits(bits) { // У p-1 будет большой простой делитель

    // console.time('gen')
    let q,p;
    while (true) {
        q = BigInt('0x' + crypto.randomBytes(~~(bits/8)).toString('hex'));
        if (SolovayStrassenTest(q,10)) {
            // console.timeLog('gen');
            p = ((2n*q + 1n));
            if (SolovayStrassenTest(p,10)){
                return {p, q}
            }
        }
    }
}

/*Find a Jacobian*/
function calculateJacobian(a, n) {
    if (!a)
        return 0;// (0/n) = 0
    let  ans = 1;
    if (a < 0n)
    {
        a = -a; // (a/n) = (-a/n)*(-1/n)
        if (n % 4n === 3n)
            ans = -ans; // (-1/n) = -1 if n = 3 (mod 4)
    }

    if (a === 1n)
        return ans;// (1/n) = 1

    while (a)
    {
        if (a < 0n)
        {
            a = -a;// (a/n) = (-a/n)*(-1/n)
            if (n % 4n === 3n)
                ans = -ans;// (-1/n) = -1 if n = 3 (mod 4)
        }
        while (a % 2n === 0n)
        {
            a = a / 2n;
            if (n % 8n === 3n || n % 8n === 5n)
                ans = -ans;

        }
        [a,n] = [n,a]; // swap
        if (a % 4n === 3n && n % 4n === 3n)
            ans = -ans;
        a = a % n;
        if (a > n / 2n)
            a = a - n;
    }
    if (n === 1n)
        return ans;
    return 0;
}

/*Test on primarity of a number P
* returns bool*/
function SolovayStrassenTest(p, iterations) {
    p = BigInt(p);
    if (p < 2n)
        return false;
    if (p !== 2n && p % 2n === 0n)
        return false;

    for (let i = 0; i < iterations; i++)
    {
        // Generate a random number a
        let a = BigInt(bigInt.randBetween(1, 999999999)) % ((p - 1n) + 1n); // TODO: Do ok generation of prime numbers
        let jacobian = (p + BigInt(calculateJacobian(a, p))) % p;
        let mod = fastDegreeModule(a, (p - 1n) / 2n, p);

        if (!jacobian || mod !== jacobian)
            return false;
    }
    return true;
}

/*An Diffie-Hellman algorithm
* Can get (P and Q) OR size of them in number of digits*/
function DiffiHellman(P,Q, size){
    let p,q;
    if (SolovayStrassenTest(BigInt(P),32) && SolovayStrassenTest(BigInt(Q),32)){
        p = BigInt(P); q = BigInt(Q);
    } else {
        let numbers = getPrimeNumbers(size);
        console.log(numbers);
        // Find g
        q = BigInt(numbers.q); p = BigInt(numbers.p);
    }
    let g = 5n;
    while(fastDegreeModule(g,q,p) === 1n){
        g = BigInt(bigInt.randBetween(1, (p-1n).toString()))
    }

    // first client
    let Xa = (bigInt.randBetween((p/2n).toString(), (p-1n).toString())).toString();
    let Ya = fastDegreeModule(g,Xa, p);

    // second
    let Xb = (bigInt.randBetween((p/2n).toString(), (p-1n).toString())).toString();
    let Yb = fastDegreeModule(g,Xb, p);

    // Connection
    let Zab = fastDegreeModule(Yb,Xa, p);
    let Zba = fastDegreeModule(Ya,Xb, p);

    // console.table({q, p, g, Xa, Ya, Xb, Yb, Zab, Zba})
    return {q, p, g, Xa, Ya, Xb, Yb, Zab, Zba}
}

/*An Al Gamal algorithm in 3 functions
* Encrypt and Decrypt functions return strings */
function AlGamalEncrypt(message, P, K, D2) {
    let p = BigInt(P);
    // 2 числа Ci
    let k = BigInt(K);
    //Вычисляем Di
    let d2 = BigInt(D2);

    // Шифрование
    let cipher = asUTF8Codes(message).split(" ");

    for (let i = 0; i < cipher.length; i++){
        cipher[i] = (BigInt(cipher[i]) * fastDegreeModule(d2, k, p)) % p; // Вычисляем е = m * (Db ^ k) mod p
    }
    cipher = cipher.join(' ');

    return cipher;
}

function AlGamalDecrypt(message, P, C2, R) {
    let p = BigInt(P);
    // 2 числа Ci
    let c2 = BigInt(C2);
    //Вычисляем Di
    let r = BigInt(R);

    // Шифрование
    let decipher = message.split(' ');

    for (let i = 0; i < decipher.length; i++){
        decipher[i] = (BigInt(decipher[i]) * fastDegreeModule(r, p - 1n - c2, p)) % p;
        decipher[i] = unicodeToChar(parseInt(decipher[i]));
    }
    decipher = decipher.join('');

    return decipher;
}

function AlGamalGenerate(size, P) { // При P слишком малом может не хватить мощности алфавита для символов Unicode
    let p;
    if (!size){
        p = BigInt(P || BigInt(randomPrime(size).toString())); // Открытые
    } else {
        p = BigInt(randomPrime(size).toString()); // Открытые
    }
    let g = BigInt(bigInt.randBetween(1, (p-1n)).toString());
    while (NOD(g, p-1n) !== 1n){
        g = BigInt(bigInt.randBetween(1, (p-1n)).toString());
    }
    // 2 числа Ci
    // Абонент А выбирает случайное число k и вычисляет из него r, e
    let k = BigInt(bigInt.randBetween(1, (p-1n).toString()));
    let r = fastDegreeModule(g, k, p);
    let c2 = BigInt(bigInt.randBetween(1, (p-1n).toString()));
    //Вычисляем Di
    let d2 = fastDegreeModule(g, c2, p);
    return {p,g,c2,d2,k,r};
}

/*Full Shamir encryption and decryption algorithm
* returns an all steps of encoding and decoding,*/
function ShamirEncode(message, P, CA, DA, CB, DB) { // size - порядок // p = (q*2) + 1
    let p = BigInt(P); // Открытое большое число
    let Ca = BigInt(CA); // абонент A
    while (NOD(Ca, p-1n) !== 1n){
        Ca = BigInt(bigInt.randBetween(1,p-1n).toString());
    }
    let Da = BigInt(DA || BigInt((bigInt(Ca).modInv(p-1n)).toString()));

    let Cb = BigInt(CB); // абонент B
    while (NOD(Cb, p-1n) !== 1n){
        Cb = BigInt(bigInt.randBetween(1,p-1n).toString());
    }
    let Db = BigInt(DB || BigInt((bigInt(Cb).modInv(p-1n)).toString()));
    // A формирует x1
    let x1 = asUTF8Codes(message).split(" ");
    for (let i = 0; i < x1.length; i++){
        x1[i] = fastDegreeModule(x1[i], Ca, p);
    }
    // x1 отправляется к абоненту B
    let x2 = [];
    for (let i = 0; i < x1.length; i++){
        x2[i] = fastDegreeModule(x1[i], Cb, p);
    }
    // x2 отправляется к абоненту A
    let x3 = [];
    for (let i = 0; i < x2.length; i++){
        x3[i] = fastDegreeModule(x2[i], Da, p);
    }
    // x3 отправляется к абоненту B и он получает исходное сообщение
    let x4 = [];
    for (let i = 0; i < x3.length; i++){
        x4[i] = fastDegreeModule(x3[i], Db, p);
        x4[i] = unicodeToChar(parseInt(x4[i]));
    }
    x4 = x4.join('');
    return {p, Ca, Cb, Da, Db, x1, x2, x3, x4}
}

/*Generate P, Ca, Cb, Da, Db for Shamir's alrorithm
* size of P is 'size' bits*/
function ShamirGenerate(size) { // size - порядок // p = (q*2) + 1

    let numbers  = getPrimeNumbersBits(size);
    let p = BigInt(numbers.p); // Открытое большое число
    let Ca = 2n; // абонент A
    while (NOD(Ca, p-1n) !== 1n){
        Ca = BigInt(bigInt.randBetween(1,p-1n).toString());
    }
    let Da = BigInt((bigInt(Ca).modInv(p-1n)).toString());

    let Cb = 2n; // абонент B
    while (NOD(Cb, p-1n) !== 1n){
        Cb = BigInt(bigInt.randBetween(1,p-1n).toString());
    }
    let Db = BigInt((bigInt(Cb).modInv(p-1n)).toString());
    return {p, Ca, Cb, Da, Db}
}

function MD5Encode(str) {	// Calculate the md5 hash of a string
    //
    // +   original by: Webtoolkit.info (http://www.webtoolkit.info/)
    // + namespaced by: Michael White (http://crestidg.com)

    var RotateLeft = function(lValue, iShiftBits) {
        return (lValue<<iShiftBits) | (lValue>>>(32-iShiftBits));
    };

    var AddUnsigned = function(lX,lY) {
        var lX4,lY4,lX8,lY8,lResult;
        lX8 = (lX & 0x80000000);
        lY8 = (lY & 0x80000000);
        lX4 = (lX & 0x40000000);
        lY4 = (lY & 0x40000000);
        lResult = (lX & 0x3FFFFFFF)+(lY & 0x3FFFFFFF);
        if (lX4 & lY4) {
            return (lResult ^ 0x80000000 ^ lX8 ^ lY8);
        }
        if (lX4 | lY4) {
            if (lResult & 0x40000000) {
                return (lResult ^ 0xC0000000 ^ lX8 ^ lY8);
            } else {
                return (lResult ^ 0x40000000 ^ lX8 ^ lY8);
            }
        } else {
            return (lResult ^ lX8 ^ lY8);
        }
    };

    var F = function(x,y,z) { return (x & y) | ((~x) & z); };
    var G = function(x,y,z) { return (x & z) | (y & (~z)); };
    var H = function(x,y,z) { return (x ^ y ^ z); };
    var I = function(x,y,z) { return (y ^ (x | (~z))); };

    var FF = function(a,b,c,d,x,s,ac) {
        a = AddUnsigned(a, AddUnsigned(AddUnsigned(F(b, c, d), x), ac));
        return AddUnsigned(RotateLeft(a, s), b);
    };

    var GG = function(a,b,c,d,x,s,ac) {
        a = AddUnsigned(a, AddUnsigned(AddUnsigned(G(b, c, d), x), ac));
        return AddUnsigned(RotateLeft(a, s), b);
    };

    var HH = function(a,b,c,d,x,s,ac) {
        a = AddUnsigned(a, AddUnsigned(AddUnsigned(H(b, c, d), x), ac));
        return AddUnsigned(RotateLeft(a, s), b);
    };

    var II = function(a,b,c,d,x,s,ac) {
        a = AddUnsigned(a, AddUnsigned(AddUnsigned(I(b, c, d), x), ac));
        return AddUnsigned(RotateLeft(a, s), b);
    };

    var ConvertToWordArray = function(str) {
        var lWordCount;
        var lMessageLength = str.length;
        var lNumberOfWords_temp1=lMessageLength + 8;
        var lNumberOfWords_temp2=(lNumberOfWords_temp1-(lNumberOfWords_temp1 % 64))/64;
        var lNumberOfWords = (lNumberOfWords_temp2+1)*16;
        var lWordArray=Array(lNumberOfWords-1);
        var lBytePosition = 0;
        var lByteCount = 0;
        while ( lByteCount < lMessageLength ) {
            lWordCount = (lByteCount-(lByteCount % 4))/4;
            lBytePosition = (lByteCount % 4)*8;
            lWordArray[lWordCount] = (lWordArray[lWordCount] | (str.charCodeAt(lByteCount)<<lBytePosition));
            lByteCount++;
        }
        lWordCount = (lByteCount-(lByteCount % 4))/4;
        lBytePosition = (lByteCount % 4)*8;
        lWordArray[lWordCount] = lWordArray[lWordCount] | (0x80<<lBytePosition);
        lWordArray[lNumberOfWords-2] = lMessageLength<<3;
        lWordArray[lNumberOfWords-1] = lMessageLength>>>29;
        return lWordArray;
    };

    var WordToHex = function(lValue) {
        var WordToHexValue="",WordToHexValue_temp="",lByte,lCount;
        for (lCount = 0;lCount<=3;lCount++) {
            lByte = (lValue>>>(lCount*8)) & 255;
            WordToHexValue_temp = "0" + lByte.toString(16);
            WordToHexValue = WordToHexValue + WordToHexValue_temp.substr(WordToHexValue_temp.length-2,2);
        }
        return WordToHexValue;
    };

    var x=Array();
    var k,AA,BB,CC,DD,a,b,c,d;
    var S11=7, S12=12, S13=17, S14=22;
    var S21=5, S22=9 , S23=14, S24=20;
    var S31=4, S32=11, S33=16, S34=23;
    var S41=6, S42=10, S43=15, S44=21;

    str = utf8_encode(str);
    x = ConvertToWordArray(str);
    a = 0x67452301; b = 0xEFCDAB89; c = 0x98BADCFE; d = 0x10325476;

    for (k=0;k<x.length;k+=16) {
        AA=a; BB=b; CC=c; DD=d;
        a=FF(a,b,c,d,x[k+0], S11,0xD76AA478);
        d=FF(d,a,b,c,x[k+1], S12,0xE8C7B756);
        c=FF(c,d,a,b,x[k+2], S13,0x242070DB);
        b=FF(b,c,d,a,x[k+3], S14,0xC1BDCEEE);
        a=FF(a,b,c,d,x[k+4], S11,0xF57C0FAF);
        d=FF(d,a,b,c,x[k+5], S12,0x4787C62A);
        c=FF(c,d,a,b,x[k+6], S13,0xA8304613);
        b=FF(b,c,d,a,x[k+7], S14,0xFD469501);
        a=FF(a,b,c,d,x[k+8], S11,0x698098D8);
        d=FF(d,a,b,c,x[k+9], S12,0x8B44F7AF);
        c=FF(c,d,a,b,x[k+10],S13,0xFFFF5BB1);
        b=FF(b,c,d,a,x[k+11],S14,0x895CD7BE);
        a=FF(a,b,c,d,x[k+12],S11,0x6B901122);
        d=FF(d,a,b,c,x[k+13],S12,0xFD987193);
        c=FF(c,d,a,b,x[k+14],S13,0xA679438E);
        b=FF(b,c,d,a,x[k+15],S14,0x49B40821);
        a=GG(a,b,c,d,x[k+1], S21,0xF61E2562);
        d=GG(d,a,b,c,x[k+6], S22,0xC040B340);
        c=GG(c,d,a,b,x[k+11],S23,0x265E5A51);
        b=GG(b,c,d,a,x[k+0], S24,0xE9B6C7AA);
        a=GG(a,b,c,d,x[k+5], S21,0xD62F105D);
        d=GG(d,a,b,c,x[k+10],S22,0x2441453);
        c=GG(c,d,a,b,x[k+15],S23,0xD8A1E681);
        b=GG(b,c,d,a,x[k+4], S24,0xE7D3FBC8);
        a=GG(a,b,c,d,x[k+9], S21,0x21E1CDE6);
        d=GG(d,a,b,c,x[k+14],S22,0xC33707D6);
        c=GG(c,d,a,b,x[k+3], S23,0xF4D50D87);
        b=GG(b,c,d,a,x[k+8], S24,0x455A14ED);
        a=GG(a,b,c,d,x[k+13],S21,0xA9E3E905);
        d=GG(d,a,b,c,x[k+2], S22,0xFCEFA3F8);
        c=GG(c,d,a,b,x[k+7], S23,0x676F02D9);
        b=GG(b,c,d,a,x[k+12],S24,0x8D2A4C8A);
        a=HH(a,b,c,d,x[k+5], S31,0xFFFA3942);
        d=HH(d,a,b,c,x[k+8], S32,0x8771F681);
        c=HH(c,d,a,b,x[k+11],S33,0x6D9D6122);
        b=HH(b,c,d,a,x[k+14],S34,0xFDE5380C);
        a=HH(a,b,c,d,x[k+1], S31,0xA4BEEA44);
        d=HH(d,a,b,c,x[k+4], S32,0x4BDECFA9);
        c=HH(c,d,a,b,x[k+7], S33,0xF6BB4B60);
        b=HH(b,c,d,a,x[k+10],S34,0xBEBFBC70);
        a=HH(a,b,c,d,x[k+13],S31,0x289B7EC6);
        d=HH(d,a,b,c,x[k+0], S32,0xEAA127FA);
        c=HH(c,d,a,b,x[k+3], S33,0xD4EF3085);
        b=HH(b,c,d,a,x[k+6], S34,0x4881D05);
        a=HH(a,b,c,d,x[k+9], S31,0xD9D4D039);
        d=HH(d,a,b,c,x[k+12],S32,0xE6DB99E5);
        c=HH(c,d,a,b,x[k+15],S33,0x1FA27CF8);
        b=HH(b,c,d,a,x[k+2], S34,0xC4AC5665);
        a=II(a,b,c,d,x[k+0], S41,0xF4292244);
        d=II(d,a,b,c,x[k+7], S42,0x432AFF97);
        c=II(c,d,a,b,x[k+14],S43,0xAB9423A7);
        b=II(b,c,d,a,x[k+5], S44,0xFC93A039);
        a=II(a,b,c,d,x[k+12],S41,0x655B59C3);
        d=II(d,a,b,c,x[k+3], S42,0x8F0CCC92);
        c=II(c,d,a,b,x[k+10],S43,0xFFEFF47D);
        b=II(b,c,d,a,x[k+1], S44,0x85845DD1);
        a=II(a,b,c,d,x[k+8], S41,0x6FA87E4F);
        d=II(d,a,b,c,x[k+15],S42,0xFE2CE6E0);
        c=II(c,d,a,b,x[k+6], S43,0xA3014314);
        b=II(b,c,d,a,x[k+13],S44,0x4E0811A1);
        a=II(a,b,c,d,x[k+4], S41,0xF7537E82);
        d=II(d,a,b,c,x[k+11],S42,0xBD3AF235);
        c=II(c,d,a,b,x[k+2], S43,0x2AD7D2BB);
        b=II(b,c,d,a,x[k+9], S44,0xEB86D391);
        a=AddUnsigned(a,AA);
        b=AddUnsigned(b,BB);
        c=AddUnsigned(c,CC);
        d=AddUnsigned(d,DD);
    }
    function utf8_encode ( str_data ) {	// Encodes an ISO-8859-1 string to UTF-8
        //
        // +   original by: Webtoolkit.info (http://www.webtoolkit.info/)

        str_data = str_data.replace(/\r\n/g,"\n");
        var utftext = "";

        for (var n = 0; n < str_data.length; n++) {
            var c = str_data.charCodeAt(n);
            if (c < 128) {
                utftext += String.fromCharCode(c);
            } else if((c > 127) && (c < 2048)) {
                utftext += String.fromCharCode((c >> 6) | 192);
                utftext += String.fromCharCode((c & 63) | 128);
            } else {
                utftext += String.fromCharCode((c >> 12) | 224);
                utftext += String.fromCharCode(((c >> 6) & 63) | 128);
                utftext += String.fromCharCode((c & 63) | 128);
            }
        }

        return utftext;
    }

    var temp = WordToHex(a)+WordToHex(b)+WordToHex(c)+WordToHex(d);

    return temp.toLowerCase();
}
