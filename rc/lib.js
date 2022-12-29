
(function (global, factory) {
    typeof exports === 'object' && typeof module !== 'undefined' ? factory(exports) :
        typeof define === 'function' && define.amd ? define(['exports'], factory) :
            (factory((global.l9x = {})));
}(this, function (exports) {
    'use strict';

    function clearLog() {
        document.getElementById("log").innerHTML = ""
    }

    function log(...args) {
        var e = document.createElement("li")
        e.innerText = args.map(JSON.stringify).join(", ")
        document.getElementById("log").append(e)
    }

    async function hashKeyJks(k) {
        //var t = JSON.stringify({e: k.e, kty: k.kty, n: k.n})
        var t = JSON.stringify({crv: k.crv, kty: k.kty, x: k.x, y: k.y})
        var a = new TextEncoder().encode(t)
        var h = await window.crypto.subtle.digest({name: "SHA-256"}, a)
        return btoa([...new Uint8Array(h)].map(k => String.fromCodePoint(k)).join(""))
            .replaceAll("/", "_")
            .replaceAll("+", "-")
            .replaceAll("=", "")
    }

    async function hashKey(key) {
        var k = await crypto.subtle.exportKey("jwk", key)
        //var t=JSON.stringify({e:k.e, kty:k.kty, n:k.n})
        var t = JSON.stringify({crv: k.crv, kty: k.kty, x: k.x, y: k.y})
        var a = new TextEncoder().encode(t)
        var h = await window.crypto.subtle.digest({name: "SHA-256"}, a)
        return btoa([...new Uint8Array(h)].map(k => String.fromCodePoint(k)).join(""))
            .replaceAll("/", "_")
            .replaceAll("+", "-")
            .replaceAll("=", "")
    }

    function u8toa(a) {
        return btoa(String.fromCharCode(...a))
    }

    function atou8(a) {
        return new Uint8Array([...atob(a)].map(k => k.charCodeAt(0)))
    }

    function secGenerateKey() {
        return crypto.subtle.generateKey( // TODO global
            //{name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([0x01, 0x00, 0x01]), hash: {name: "SHA-256"}},
            {name: "ECDSA", namedCurve: "P-256"},
            true, //whether the key is extractable (i.e. can be used in exportKey)
            ["sign", "verify"] //can be any combination of "sign" and "verify"
        )
    }

    async function secSign(privateKey, msg) {
        return window.crypto.subtle.sign(
            // {name: "RSA-PSS", saltLength: 128}, //
            {name: "ECDSA", hash: {name: "SHA-256"}},
            privateKey, //from generateKey or importKey above
            atou8(msg) //ArrayBuffer of data you want to sign
        ).then(s => u8toa(new Uint8Array(s)))
    }

    async function secVerifySign(publicKey, msg, sig) {
        return crypto.subtle.verify(
            // {name: "RSA-PSS", saltLength: 128}, //
            {name: "ECDSA", hash: {name: "SHA-256"}},
            publicKey, //from generateKey or importKey above
            atou8(sig), //ArrayBuffer of the signature
            atou8(msg)//ArrayBuffer of the data
        )
    }

    function secImportPublicKey(jwk) {
        return crypto.subtle.importKey("jwk", jwk,
            //{name: "RSA-PSS", hash: {name: "SHA-256"}},
            {name: "ECDSA", hash: {name: "SHA-256"}},
            false, //whether the key is extractable (i.e. can be used in exportKey)
            ["verify"])
    }



    class Acceptor {

        constructor(method="frame") {
            this.method=method
        }

        async genKey() {
            this.key= await secGenerateKey()
            return this;
        }

        async getFp() {
            return l9x.hashKey(this.key.publicKey)
        }

        log(...x) {
            log(...x)
        }

        open() {
            switch(this.method) {
                case "window": {
                    this.w = window.open("https://l9x.de/rc/S.html");
                    break;
                }
                case "frame": {
                    var ifr = document.createElement("iframe")
                    this.w = ifr
                    ifr.src = "https://l9x.de/rc/S.html"
                    ifr.height = "50%"
                    ifr.width = "100%"
                    ifr.style.display="none"
                    document.body.append(ifr)
                    break;
                }
            }
        }

        w= void 0
        accept(onConnect, onAccepting) {
            const that=this;
            async function f(e) {
                if(e.source==that.w||true) {
                    that.log(e.data);
                    ({
                        identify: async () => {
                            window.removeEventListener("message", f)
                            var sig = await secSign(that.key.privateKey, e.data.ch)
                            var pk = await crypto.subtle.exportKey("jwk", that.key.publicKey)
                            //console.log({t: "id", sig: sig, pk: pk})
                            var ch=new MessageChannel()
                            ch.port1.onmessage=e=>{
                                var p = e.ports[0]
                                that.log("Accepting",e.data)
                                p.postMessage({t:'connected'})
                                p.onmessage=e=>onConnect(p,e)
                            }
                            e.source.postMessage({t: "id", sig: sig, pk: pk}, "*",[ch.port2]);
                            if(onAccepting) {
                                onAccepting(ch.port1)
                            }
                        }
                    })[e.data.t]()
                }
            }
            window.addEventListener("message", f)
            this.open()
        }

        rcall(port, msg) {
            return new Promise((res,rej)=>{
                var ch=new MessageChannel()
                ch.port1.onmessage=e=>e.data.length==1 ? res(e.data[0]) : rej(e.data)
                port.postMessage(msg, [ch.port2])
            })
        }

        link=(hdl,tkn='prompt("rc-token")')=>'javascript:(e=>{var t,a=window,o="message",r=(e,...t)=>e.postMessage(...t);f=(s=>{if(s.source==t&&"connected"==s.data.t){var n=s.ports[0];n["on"+o]=(t=>{(async()=>[await e(t.data)])().catch(e=>[e.message,e.stack]).then(e=>r(t.ports[0],e))}),r(n,{t:"ready",loc:document.location.href}),a.removeEventListener(o,f)}}),a.addEventListener(o,f),t=a.open("https://l9x.de/rc/C.html#"+'+tkn+')})('+hdl+')';


    }

    exports.clearLog=clearLog;
    exports.log=log;
    exports.hashKeyJks=hashKeyJks;
    exports.hashKey=hashKey;
    exports.u8toa=u8toa;
    exports.atou8=atou8;
    exports.secGenerateKey=secGenerateKey;
    exports.secSign=secSign;
    exports.secVerifySign=secVerifySign;
    exports.secImportPublicKey=secImportPublicKey;
    exports.Acceptor=Acceptor;

}));
