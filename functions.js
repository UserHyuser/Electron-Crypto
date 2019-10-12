// This file is required by the index.html file and will
// be executed in the renderer process for that window.
// All of the Node.js APIs are available in this process.
const bigInt = require('big-integer');
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
            console.log(p);
            q = randomPrime(keysize / 2);
            console.log(q);
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
    const min = bigInt.one.shiftLeft(bits - 1);
    const max = bigInt.one.shiftLeft(bits).prev();

    while (true) {
        let p = bigInt.randBetween(min, max);
        // console.log(p);
        if (p.isProbablePrime(32)) {
            return p;
        }
    }
}

function getPrimeNumbers(deg) { // указывается степень
    const min = BigInt(10n ** (BigInt(deg)-2n));
    const max = BigInt(10n ** (BigInt(deg)));
    let q,p;
    while (true) {
        q = (bigInt.randBetween(min, max)).toString();
        if (SolovayStrassenTest(q.toString(),128)) {
            p = (bigInt(2n*BigInt(q) + 1n)).toString();
            if (SolovayStrassenTest(p.toString(),128)){ // Почему-то нужно передавать как строку BigInt не работает
                return {p, q}
            }
        }
    }
}

// Якобиан
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
// Тест на простоту Соловея - Штрассена (псевдопростое или точно составное)

/**
 * @return {boolean}
 */
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

function DiffiHellman(P,Q, size){
    let p,q;
    if (SolovayStrassenTest(BigInt(P),128) && SolovayStrassenTest(BigInt(Q),128)){
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

/*function AlGamal(message, size, P, G, C1, C2, D1, D2) {
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
}*/

function AlGamalEncode(message, P, G, C1, D2) {
    let p = BigInt(P); // Открытые
    let g = BigInt(G || 3n);
    while (NOD(g, p-1n) !== 1n){
        g++;
    }
    // 2 числа Ci
    let c1 = BigInt(C1);
    //Вычисляем Di
    let d2 = BigInt(D2);

    // Шифрование
    let cipher = asUTF8Codes(message).split(" ");

    for (let i = 0; i < cipher.length; i++){
        cipher[i] = (BigInt(cipher[i]) * fastDegreeModule(d2, c1, p)) % p;
    }
    cipher = cipher.join(' ');

    return cipher;
}

function AlGamalDecode(message, P, G, C2, D1) {
    let p = BigInt(P); // Открытые
    let g = BigInt(G || 3n);
    while (NOD(g, p-1n) !== 1n){
        g++;
    }
    // 2 числа Ci
    let c2 = BigInt(C2);
    //Вычисляем Di
    let d1 = BigInt(D1);

    // Шифрование
    let decipher = message.split(' ');

    for (let i = 0; i < decipher.length; i++){
        decipher[i] = (BigInt(decipher[i]) * fastDegreeModule(d1, p - 1n - c2, p)) % p;
        decipher[i] = unicodeToChar(parseInt(decipher[i]));
    }
    decipher = decipher.join('');

    return decipher;
}

function AlGamalGenerate(size, P) {
    if (!size){
        let p = BigInt(P || BigInt(randomPrime(size).toString())); // Открытые
        let g = 3n;
        while (NOD(g, p-1n) !== 1n){
            g++;
        }
        // 2 числа Ci
        let c1 = BigInt(bigInt.randBetween(1, (p-1n).toString()));
        let c2 = BigInt(bigInt.randBetween(1, (p-1n).toString()));
        //Вычисляем Di
        let d1 = fastDegreeModule(g, c1, p);
        let d2 = fastDegreeModule(g, c2, p);
        return {p,g,c1,c2,d1,d2};
    } else {
        let p = BigInt(randomPrime(size).toString()); // Открытые
        let g = 3n;
        while (NOD(g, p-1n) !== 1n){
            g++;
        }
        // 2 числа Ci
        let c1 = BigInt(bigInt.randBetween(1, (p-1n).toString()));
        let c2 = BigInt(bigInt.randBetween(1, (p-1n).toString()));
        //Вычисляем Di
        let d1 = fastDegreeModule(g, c1, p);
        let d2 = fastDegreeModule(g, c2, p);
        return {p,g,c1,c2,d1,d2};
    }



}



