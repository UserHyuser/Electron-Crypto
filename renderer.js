// This file is required by the index.html file and will
// be executed in the renderer process for that window.
// All of the Node.js APIs are available in this process.
const bigInt = require('big-integer');

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

const degreeModule = (a, p, m) => {
    return (a ** p) % m;
};

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

function asUTF8Codes(str) {
    let output = "";
    for (let i = 0; i < str.length; i++) {
        output += str.charCodeAt(i) + " ";
    }
    return output.trim();
}

function unicodeToChar(text) {
    return String.fromCharCode(parseInt(text))
}

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

function getInverseElem(a,m) {
    a = (a % m + m) % m
    if (!a || m < 2n) {
        return NaN // invalid input
    }

    const s = []
    let b = m
    while(b) {                  // Алгоритм Евклида с записью промежуточных значений
        [a, b] = [b, a % b]
        s.push({a, b})
    }
    if (a !== 1n) {
        return NaN // Обратного элемента нет
    }
    // Нахождение обратного элемента по "ручному алгоритму"
    let x = 1n
    let y = 0n
    for(let i = s.length - 2; i >= 0; --i) {
        [x, y] = [y,  x - y * Math.floor(s[i].a / s[i].b)]
    }
    let t = (y % m + m) % m;
    if (t > 0n){
        return t
    } else {
        return t + m;
    }
}

function NODex(a, b) {
    if (!b) {
        return a;
    }

    return NOD(b, a % b);
}

function NOD(a, b) {
    if (!b) {
        return a;
    }

    return NOD(b, a % b);
}

function genKeys (P, Q){
    let p = BigInt(P) || 113n;
    let q = BigInt(Q) || 281n;
    /*if(isPrime(p) === -1 || isPrime(q) === -1){
        return false
    }*/
    let n = BigInt(p*q);
    let eilerNumber = BigInt((p-1n)*(q-1n));

    // Gen e
    let e = BigInt(65537);
    // while (NOD(e,eilerNumber) !== 1n){
    //     e++;
    // }
    d = BigInt(bigInt(e).modInv(eilerNumber));
    return {p:p, q:q, e:e, n:n, eilerNumber:eilerNumber, d:d};
}

const isPrime = (num) => {
    for(let i = 2, s = Math.sqrt(num); i <= s; i++)
        if(num % i === 0) return false;
    return num > 1;
}

function bigNumbersGenerate(keysize, P, Q) {

    const e = bigInt(65537);
    let p = bigInt(P) || 0;
    let q = bigInt(Q) || 0;
    let totient;

    if (!isNaN(parseInt(keysize))){
        do {
            p = randomPrime(keysize / 2);
            q = randomPrime(keysize / 2);
            totient = bigInt.lcm(               //Наименьшее общее кратное
                p.prev(), // -1
                q.prev()
            );
        } while (bigInt.gcd(e, totient).notEquals(1)); // Пока НОД е, и "числа Эйлера" !== 1 или || p.minus(q).abs().shiftRight(keysize / 2 - 100).isZero()
    } else {
        totient = bigInt.lcm(
            p.prev(),
            q.prev()
        );
    }

    return {
        p,
        q,
        e,
        n: p.multiply(q),
        d: e.modInv(totient),
    };
}

function randomPrime(bits) {
    const min = bigInt.one.shiftLeft(bits - 1); // При использовании больших почему-то начинает появляться ошибка...
    const max = bigInt.one.shiftLeft(bits).prev();

    while (true) {
        let p = bigInt.randBetween(min, max);
        if (p.isProbablePrime(32)) {
            return p;
        }
    }
}

