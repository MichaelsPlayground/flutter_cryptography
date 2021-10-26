import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter/material.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({Key? key}) : super(key: key);

  // This widget is the root of your application.
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Flutter Demo',
      theme: ThemeData(
        // This is the theme of your application.
        //
        // Try running your application with "flutter run". You'll see the
        // application has a blue toolbar. Then, without quitting the app, try
        // changing the primarySwatch below to Colors.green and then invoke
        // "hot reload" (press "r" in the console where you ran "flutter run",
        // or simply save your changes to "hot reload" in a Flutter IDE).
        // Notice that the counter didn't reset back to zero; the application
        // is not restarted.
        primarySwatch: Colors.blue,
      ),
      home: const MyHomePage(title: 'Flutter Demo Home Page'),
    );
  }
}

class MyHomePage extends StatefulWidget {
  const MyHomePage({Key? key, required this.title}) : super(key: key);

  // This widget is the home page of your application. It is stateful, meaning
  // that it has a State object (defined below) that contains fields that affect
  // how it looks.

  // This class is the configuration for the state. It holds the values (in this
  // case the title) provided by the parent (in this case the App widget) and
  // used by the build method of the State. Fields in a Widget subclass are
  // always marked "final".

  final String title;

  @override
  State<MyHomePage> createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  int _counter = 0;

  void _incrementCounter() {
    setState(() {
      // This call to setState tells the Flutter framework that something has
      // changed in this State, which causes it to rerun the build method below
      // so that the display can reflect the updated values. If we changed
      // _counter without calling setState(), then the build method would not be
      // called again, and so nothing would appear to happen.
      _counter++;
    });
  }

  Uint8List createUint8ListFromString(String s) {
    var ret = new Uint8List(s.length);
    for (var i = 0; i < s.length; i++) {
      ret[i] = s.codeUnitAt(i);
    }
    return ret;
  }

  Future<void> _runChacha() async {
    final plaintext = 'The quick brown fox jumps over the lazy dog';
    var plaintextUint8 = createUint8ListFromString(plaintext);
    var plaintextUtf8 = utf8.encode(plaintext);

    final algorithm = Chacha20.poly1305Aead();

    // Generate a random 256-bit secret key
    final secretKey = await algorithm.newSecretKey();

    // import a key
    //final secretKeyImp = await algorithm.newSecretKeyFromBytes(key);

    // generate a nonce
    final nonce = algorithm.newNonce();

    // encrypt
    print('\n* * * encrypt * * *');
    final secretBox = await algorithm.encrypt(
      //plaintextUint8,
      plaintextUtf8,
      secretKey: secretKey,
      //secretKey: secretKeyImp,
      nonce: nonce,
    );
    var ciphertext = secretBox.cipherText;
    var mac = secretBox.mac.bytes;
    var secretKeyBase64 = base64.encode(await secretKey.extractBytes());
    var nonceBase64 = base64.encode(nonce);
    var ciphertextBase64 = base64.encode(ciphertext);
    var macBase64 = base64.encode(mac);
    print('secretkey  : ' + secretKeyBase64);
    print('nonce      : ' + nonceBase64);
    print('ciphertext : ' + ciphertextBase64);
    print('mac        : ' + macBase64);

    print('\n* * * decrypt * * *');
    final algorithmDecrypt = Chacha20.poly1305Aead();
    final secretKeyImp = await algorithm.newSecretKeyFromBytes(base64.decode(secretKeyBase64));
    var macDecryption = new Mac(base64.decode(macBase64));
    var secretBoxDecryption = await SecretBox(
    base64.decode(ciphertextBase64),
    nonce: base64.decode(nonceBase64),
    mac: macDecryption);
    final decryption = await algorithmDecrypt.decrypt(
    secretBoxDecryption,
    secretKey: secretKeyImp
    );
    var decryptedtextString = new String.fromCharCodes(decryption);
    print('decryptedtext: ' + decryptedtextString);
  }

  Future<void> _runAesGcm256() async {
    print('\nAES GCM 256');
    final algorithm = AesGcm.with256bits();

    // Generate a random 256-bit secret key
    final secretKey = await algorithm.newSecretKey();

    // Generate a random 96-bit nonce.
    final nonce = algorithm.newNonce();

    // Encrypt
    final clearText = [1, 2, 3];
    final secretBox = await algorithm.encrypt(
      clearText,
      secretKey: secretKey,
      nonce: nonce,
    );
    print('Ciphertext: ${secretBox.cipherText}');
    print('MAC: ${secretBox.mac}');
  }

  Future<void> _x25519KeyExchange() async {
    // Let's generate two X25519 keypairs.
    final localKeyPair = await X25519().newKeyPair();
    final remoteKeyPair = await X25519().newKeyPair();
    final remotePublicKey = await remoteKeyPair.extractPublicKey();

    // We can now calculate a shared 256-bit secret
    final secretKey = await X25519().sharedSecretKey(keyPair: localKeyPair, remotePublicKey: remotePublicKey);

    final secretBytes = await secretKey.extractBytes();
    final secretBytesBase64 = base64Encode(secretBytes);
    print('X25519 key exchange');
    print('X25519 local Shared secret : $secretBytesBase64');

    // now remote
    final localPublicKey = await localKeyPair.extractPublicKey();
    final remoteSecretKey = await X25519().sharedSecretKey(keyPair: remoteKeyPair, remotePublicKey: localPublicKey);
    final remoteSecretBytes = await remoteSecretKey.extractBytes();
    final remoteSecretBytesBase64 = base64Encode(remoteSecretBytes);
    print('X25519 remote Shared secret: $remoteSecretBytesBase64');
  }

  Future<void> _x25519KeyExchangeCpc() async {

    // uses the fixed keys from Cross Platform Cryptography
    // works !
    // fixed keys
    String aPrivateKeyBase64 = "yJIzp7IueQOu8l202fwI21/aNXUxXBcg3jJoLFJATlU=";
    String bPublicKeyBase64 =  "jVSuHjVH47PMbMaAxL5ziBS9/Z0HQK6TJLw9X3Jw6yg=";

    // received public key
    String aPublicKeyBase64 =  "b+Z6ajj7wI6pKAK5N28Hzp0Lyhv2PvHofwGY3WSm7W0=";
    // own private key
    String bPrivateKeyBase64 = "yNmXR5tfBXA/uZjanND+IYgGXlrFnrdUiUXesI4fOlM=";

    // generate the local keyPair
    final algorithm = X25519();
    final aPrivateKey = base64Decode(aPrivateKeyBase64);
    final localKeyPair = await algorithm.newKeyPairFromSeed(aPrivateKey);

    final bPrivateKey = base64Decode(bPrivateKeyBase64);
    final remoteKeyPair = await algorithm.newKeyPairFromSeed(bPrivateKey);
    final remotePublicKey = await remoteKeyPair.extractPublicKey();

    // We can now calculate a shared 256-bit secret
    final secretKey = await X25519().sharedSecretKey(keyPair: localKeyPair, remotePublicKey: remotePublicKey);

    final secretBytes = await secretKey.extractBytes();
    final secretBytesBase64 = base64Encode(secretBytes);
    print('X25519 key exchange CPC');
    print('X25519 local Shared secret CPC : $secretBytesBase64');

    // now remote
    final localPublicKey = await localKeyPair.extractPublicKey();
    final remoteSecretKey = await X25519().sharedSecretKey(keyPair: remoteKeyPair, remotePublicKey: localPublicKey);
    final remoteSecretBytes = await remoteSecretKey.extractBytes();
    final remoteSecretBytesBase64 = base64Encode(remoteSecretBytes);
    print('X25519 remote Shared secret CPC: $remoteSecretBytesBase64');
  }

  Future<void> _runEd25519Signature() async {
    // The message that we will sign
    final message = <int>[1,2,3];

    // Generate a random ED25519 keypair
    final keyPairEd25519 = await Ed25519().newKeyPair();

    // Sign
    final signature = await Ed25519().sign(
      message,
      keyPair: keyPairEd25519,
    );

    print('ED25519 signature');
    print('ED25519 privateKey: ' + base64Encode(await keyPairEd25519.extractPrivateKeyBytes()));
    SimplePublicKey pubKey = await keyPairEd25519.extractPublicKey();
    print('ED25519 publicKey:  ' + base64Encode(pubKey.bytes));
    print('ED25519 signature:  ' + base64Encode(signature.bytes));
    print('Signature: ${signature.bytes}');
    print('Public key: ${signature.publicKey.toString()}');

    // Verify signature
    final isSignatureCorrect = await Ed25519().verify(
      message,
      signature: signature,
    );

    print('ED25519 Is the signature correct: $isSignatureCorrect');
  }

  Future<void> _runAes256CtrHmac() async {
    final algorithm = AesCtr.with256bits(macAlgorithm: Hmac.sha256());
    // Generate a random 256-bit secret key
    final secretKey = await algorithm.newSecretKey();
    // Generate a random 96-bit nonce.
    final nonce = algorithm.newNonce();
    // Our message
    final message = utf8.encode('encrypted message');
    // Encrypt
    //final clearText = [1, 2, 3];
    final secretBox = await algorithm.encrypt(
      message,
      secretKey: secretKey,
      nonce: nonce,
    );
    print('AES-256 CTR with HMAC SHA-256');
    print('AES-256 CTR Nonce: ${base64Encode(secretBox.nonce)}');
    print('AES-256 CTR Ciphertext: ${base64Encode(secretBox.cipherText)}');
    print('AES-256 CTR MAC: ${base64Encode(secretBox.mac.bytes)}');

    // decrypt
    final secretBoxDecrypt = await algorithm.decrypt(secretBox, secretKey: secretKey);
    print('AES-256 CTR decrypt: ' + new String.fromCharCodes(secretBoxDecrypt));

    SecretBox secretBoxConcat = SecretBox(secretBox.cipherText, nonce: secretBox.nonce, mac: secretBox.mac);
    final secretBoxDecryptNonceCiphertextMac = await algorithm.decrypt(secretBoxConcat, secretKey: secretKey);
    print('AES-256 CTR decrypt: ' + new String.fromCharCodes(secretBoxDecryptNonceCiphertextMac));
  }

  @override
  Widget build(BuildContext context) {
    // This method is rerun every time setState is called, for instance as done
    // by the _incrementCounter method above.
    //
    // The Flutter framework has been optimized to make rerunning build methods
    // fast, so that you can just rebuild anything that needs updating rather
    // than having to individually change instances of widgets.
    return Scaffold(
      appBar: AppBar(
        // Here we take the value from the MyHomePage object that was created by
        // the App.build method, and use it to set our appbar title.
        title: Text(widget.title),
      ),
      body: Center(
        // Center is a layout widget. It takes a single child and positions it
        // in the middle of the parent.
        child: Column(
          // Column is also a layout widget. It takes a list of children and
          // arranges them vertically. By default, it sizes itself to fit its
          // children horizontally, and tries to be as tall as its parent.
          //
          // Invoke "debug painting" (press "p" in the console, choose the
          // "Toggle Debug Paint" action from the Flutter Inspector in Android
          // Studio, or the "Toggle Debug Paint" command in Visual Studio Code)
          // to see the wireframe for each widget.
          //
          // Column has various properties to control how it sizes itself and
          // how it positions its children. Here we use mainAxisAlignment to
          // center the children vertically; the main axis here is the vertical
          // axis because Columns are vertical (the cross axis would be
          // horizontal).
          mainAxisAlignment: MainAxisAlignment.center,
          children: <Widget>[
            const Text(
              'You have pushed the button this many times:',
            ),
            Text(
              '$_counter',
              style: Theme.of(context).textTheme.headline4,
            ),
            Text('ChaCha20Poly1305 fixed key & nonce'),
          ],
        ),
      ),
      floatingActionButton: FloatingActionButton(
        tooltip: 'Increment',

        onPressed: () {
          _incrementCounter;
          _runChacha();
          _runAesGcm256();
          _x25519KeyExchange();
          _x25519KeyExchangeCpc();
          _runEd25519Signature();
          _runAes256CtrHmac();
        },
        child: const Icon(Icons.add),
      ), // This trailing comma makes auto-formatting nicer for build methods.
    );
  }
}
