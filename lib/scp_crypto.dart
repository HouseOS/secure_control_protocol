import 'dart:convert';
import 'dart:math';

import 'package:collection/collection.dart';
import 'package:cryptography/cryptography.dart' as cryptography;
import 'package:web3dart/crypto.dart';

class ScpCrypto {

  static final Random _random = Random.secure();

  static final String defaultPassword = '01234567890123456789012345678901';

  Future<String> decodeThenDecrypt(
      String key, String base64nonce, String base64mac, String base64Text, int payloadLength) async {
        print('Nonce: $base64nonce');
        print('base64mac: $base64mac');
        print('base64Text: $base64Text');
    List<int> decodedKey = utf8.encode(key);
    List<int> decodedNonce = base64.decode(base64nonce);
    List<int> decodedText = List<int>();
    print('Decoded base64Text: ${base64.decode(base64Text)}');
    print('Decoded base64mac: ${base64.decode(base64mac)}');
    decodedText.addAll(base64.decode(base64Text));
    print('Text length: ${decodedText.length}');
    print('Text length: $payloadLength');
    decodedText.addAll(base64.decode(base64mac));
    while(decodedText.length <= payloadLength){
      decodedText.add(0);
    }
    print('Decoded combined: $decodedText');
    return await decryptMessage(decodedKey, decodedNonce, decodedText);
  }

  Future<String> decryptMessage(
      List<int> key, List<int> nonce, List<int> encryptedText) async {
    // Encode Key
    cryptography.SecretKey secretKey = cryptography.SecretKey(key);
    //Encode nonce
    cryptography.Nonce encodedNonce = cryptography.Nonce(nonce);
    //Encode encrypted text
    List<int> cipherText = encryptedText;
    // Decrypt
    final clearText = await cryptography.chacha20Poly1305Aead
        .decrypt(
      cipherText,
      secretKey: secretKey,
      nonce: encodedNonce,
    )
        .catchError((err) {
      print(err);
    });
    // Return text
    return utf8.decode(clearText);
  }

  Future<ScpJson> encryptThenEncode(
      String key, String message) async {
    EncryptedPayload encryptedPayload =
        await encryptMessage(key, message);
    return ScpJson(
      key: base64Encode(utf8.encode(key)),
      encryptedPayload: encryptedPayload,
    );
  }

  Future<EncryptedPayload> encryptMessage(
      String key, String plainText) async {
    // Encode Key
    cryptography.SecretKey secretKey = cryptography.SecretKey(utf8.encode(key));
    //Encode encrypted text
    List<int> clearText = utf8.encode(plainText);
    // Encrypt
    cryptography.Nonce nonce = cryptography.Nonce.randomBytes(12);
    final encryptedText = await cryptography.chacha20Poly1305Aead.encrypt(
      clearText,
      secretKey: secretKey,
      nonce: nonce,
    );

    String base64Data =
        base64Encode(cryptography.chacha20Poly1305Aead.getDataInCipherText(encryptedText));
    String base64Mac = base64Encode(
        cryptography.chacha20Poly1305Aead.getMacInCipherText(encryptedText).bytes);

    return EncryptedPayload(
      base64Data: base64Data,
      dataLength:
          cryptography.chacha20Poly1305Aead.getDataInCipherText(encryptedText).length,
      base64Mac: base64Mac,
      base64DataWithMac: base64Encode(encryptedText),
      base64Nonce: base64Encode(nonce.bytes),
    );
  }

  bool verifyHMAC(String content, String hmac, String password) {
    //for now only with default password later the password stored for the device has to be extracted.
    cryptography.SecretKey secretKey;
    if(password == null){
      secretKey = cryptography.SecretKey(utf8.encode(defaultPassword));
    } else {
      secretKey = cryptography.SecretKey(utf8.encode(password));
    }
     
    var input = utf8.encode(content);
    final sink = cryptography.Hmac(cryptography.sha512).newSink(secretKey: secretKey);
    sink.add(input);
    sink.close();
    var mac = sink.mac;
    return ListEquality().equals(hexToBytes(hmac), mac.bytes);
  }
   
  String generatePassword() {
      var values = List<int>.generate(32, (i) => _random.nextInt(256));
      return base64Url.encode(values).substring(0,32);
  }
}

class EncryptedPayload {
  String base64DataWithMac;
  String base64Data;
  int dataLength;
  String base64Mac;
  String base64Nonce;

  EncryptedPayload(
      {this.base64Data, this.dataLength, this.base64Mac, this.base64DataWithMac, this.base64Nonce});

      
}

class ScpJson {
  String key;
  EncryptedPayload encryptedPayload;

  ScpJson({this.key, this.encryptedPayload});

  Map<String, dynamic> toJson() => {
        'key': key,
        'payload': encryptedPayload.base64Data,
        'payloadLength': encryptedPayload.dataLength,
        'mac': encryptedPayload.base64Mac,
      };
}
